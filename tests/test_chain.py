from dataclasses import replace

import pytest

from forkchain.block import Block, BlockHeader, mine_header
from forkchain.errors import ValidationError
from forkchain.merkle import merkle_root
from forkchain.miner import build_template, mine_block, solve
from forkchain.params import COIN, REGTEST
from forkchain.pow import bits_to_target
from forkchain.script.vm import verify_input
from forkchain.tx import OutPoint, Transaction, TxIn, TxOut, make_coinbase
from forkchain.validation import check_tx_inputs
from forkchain.wallet import Wallet

from .conftest import ChainHarness


def fund(h: ChainHarness, w: Wallet, blocks: int = 2) -> None:
    h.mine_many(blocks, w.script_pubkey)


def test_genesis_state(harness: ChainHarness) -> None:
    assert harness.chain.height == 0
    assert harness.chain.contains(harness.chain.genesis.hash)
    assert len(harness.chain.utxos) == 1


def test_mining_pays_reward(harness: ChainHarness, alice: Wallet) -> None:
    fund(harness, alice, 3)
    coins = harness.chain.utxos.coins_for_script(alice.script_pubkey)
    assert sum(c.output.value for _, c in coins) == 3 * 50 * COIN
    assert harness.chain.block_at(3).txs[0].coinbase_height() == 3


def test_spend_and_fee(harness: ChainHarness, alice: Wallet, bob: Wallet) -> None:
    fund(harness, alice)
    coins = harness.chain.utxos.coins_for_script(alice.script_pubkey)
    tx = alice.build_payment(coins, [TxOut(10 * COIN, bob.script_pubkey)], fee=1000)
    fee = check_tx_inputs(tx, harness.chain.utxos, harness.chain.height + 1, REGTEST)
    assert fee == 1000
    block = harness.mine(alice.script_pubkey, [tx], fees=fee)
    assert block.txs[0].total_out() == 50 * COIN + 1000
    assert (
        sum(c.output.value for _, c in harness.chain.utxos.coins_for_script(bob.script_pubkey))
        == 10 * COIN
    )


def test_double_spend_inside_block_rejected(
    harness: ChainHarness, alice: Wallet, bob: Wallet
) -> None:
    fund(harness, alice)
    coins = harness.chain.utxos.coins_for_script(alice.script_pubkey)[:1]
    tx1 = alice.build_payment(coins, [TxOut(COIN, bob.script_pubkey)], fee=0)
    tx2 = alice.build_payment(coins, [TxOut(2 * COIN, bob.script_pubkey)], fee=0)
    block = mine_block(harness.chain, alice.script_pubkey, [tx1, tx2])
    with pytest.raises(ValidationError, match="missingorspent"):
        harness.chain.add_block(block).check()
    assert harness.chain.height == 2


def test_double_spend_across_blocks_rejected(
    harness: ChainHarness, alice: Wallet, bob: Wallet
) -> None:
    fund(harness, alice)
    coins = harness.chain.utxos.coins_for_script(alice.script_pubkey)[:1]
    tx1 = alice.build_payment(coins, [TxOut(COIN, bob.script_pubkey)], fee=0)
    harness.mine(alice.script_pubkey, [tx1])
    tx2 = alice.build_payment(coins, [TxOut(2 * COIN, bob.script_pubkey)], fee=0)
    harness.clock.tick(1000)
    with pytest.raises(ValidationError, match="missingorspent"):
        harness.chain.add_block(mine_block(harness.chain, alice.script_pubkey, [tx2])).check()


def test_forged_signature_rejected(harness: ChainHarness, alice: Wallet, bob: Wallet) -> None:
    fund(harness, alice)
    coins = harness.chain.utxos.coins_for_script(alice.script_pubkey)[:1]
    tx = alice.build_payment(coins, [TxOut(COIN, bob.script_pubkey)], fee=0)
    # Bob re-signs Alice's coin with his own key: pubkey hash does not match the output.
    stolen = bob.build_payment(coins, [TxOut(COIN, bob.script_pubkey)], fee=0)
    assert not verify_input(stolen, 0, coins[0][1].output)
    # Changing an output after signing invalidates the signature.
    tampered = replace(tx, outputs=(TxOut(COIN // 2, bob.script_pubkey), *tx.outputs[1:]))
    assert not verify_input(tampered, 0, coins[0][1].output)
    with pytest.raises(ValidationError, match="bad-txns-script"):
        check_tx_inputs(tampered, harness.chain.utxos, 3, REGTEST)


def test_malformed_script_sig_rejected(harness: ChainHarness, alice: Wallet) -> None:
    fund(harness, alice)
    op, coin = harness.chain.utxos.coins_for_script(alice.script_pubkey)[0]
    for script_sig in (b"", b"\x05ab", b"\x01a\x01b\x01c", b"\x02ab\x03xyz"):
        tx = Transaction((TxIn(op, script_sig),), (TxOut(1, b""),))
        assert not verify_input(tx, 0, coin.output)


def test_overspend_and_coinbase_amount(harness: ChainHarness, alice: Wallet, bob: Wallet) -> None:
    fund(harness, alice, 1)
    harness.mine(bob.script_pubkey)
    coins = harness.chain.utxos.coins_for_script(alice.script_pubkey)
    tx = alice.build_payment(coins, [TxOut(COIN, bob.script_pubkey)], fee=0)
    over = replace(tx, outputs=(TxOut(51 * COIN, bob.script_pubkey),))
    with pytest.raises(ValidationError, match="in-belowout"):
        check_tx_inputs(over, harness.chain.utxos, 3, REGTEST)
    greedy = mine_block(harness.chain, alice.script_pubkey, fees=1)
    with pytest.raises(ValidationError, match="bad-cb-amount"):
        harness.chain.add_block(greedy).check()


def test_coinbase_maturity() -> None:
    h = ChainHarness(REGTEST.with_overrides(coinbase_maturity=3))
    w = Wallet.__new__(Wallet)
    from forkchain.keys import PrivateKey

    w.key = PrivateKey.from_seed("m")
    h.mine(w.script_pubkey)
    coins = h.chain.utxos.coins_for_script(w.script_pubkey)
    tx = w.build_payment(coins, [TxOut(COIN, b"x")], fee=0)
    with pytest.raises(ValidationError, match="premature"):
        check_tx_inputs(tx, h.chain.utxos, 2, h.params)
    assert check_tx_inputs(tx, h.chain.utxos, 4, h.params) == 0


def test_locktime(harness: ChainHarness, alice: Wallet) -> None:
    fund(harness, alice)
    coins = harness.chain.utxos.coins_for_script(alice.script_pubkey)
    tx = alice.build_payment(coins, [TxOut(COIN, b"x")], fee=0, locktime=10)
    with pytest.raises(ValidationError, match="nonfinal"):
        check_tx_inputs(tx, harness.chain.utxos, 3, REGTEST)
    assert check_tx_inputs(tx, harness.chain.utxos, 10, REGTEST) == 0


def test_coinbase_rules(harness: ChainHarness, alice: Wallet) -> None:
    cb = make_coinbase(5, (TxOut(1, b""),))  # wrong height
    template = build_template(harness.chain, alice.script_pubkey)
    header = replace(template.header, merkle_root=merkle_root([cb.txid]))
    harness.clock.tick(1000)
    with pytest.raises(ValidationError, match="bad-cb-height"):
        harness.chain.add_block(solve(Block(header, (cb,)))).check()
    with pytest.raises(ValidationError, match="bad-txns-coinbase"):
        check_tx_inputs(cb, harness.chain.utxos, 1, REGTEST)


def test_header_context_rules(harness: ChainHarness, alice: Wallet) -> None:
    harness.mine_many(3, alice.script_pubkey)
    template = build_template(harness.chain, alice.script_pubkey)
    wrong_bits = Block(replace(template.header, bits=0x2000FFFF), template.txs)
    with pytest.raises(ValidationError, match="bad-diffbits"):
        harness.chain.add_block(solve(wrong_bits)).check()
    old = Block(replace(template.header, timestamp=REGTEST.genesis_timestamp_ms), template.txs)
    with pytest.raises(ValidationError, match="time-too-old"):
        harness.chain.add_block(solve(old)).check()
    future = harness.clock.now + REGTEST.max_future_drift_ms + 1
    new = Block(replace(template.header, timestamp=future), template.txs)
    with pytest.raises(ValidationError, match="time-too-new"):
        harness.chain.add_block(solve(new)).check()


def test_block_off_tip_becomes_side_branch(harness: ChainHarness, alice: Wallet) -> None:
    tip = harness.mine(alice.script_pubkey)
    harness.clock.tick(1)
    stale = mine_block(harness.chain, alice.script_pubkey, parent=harness.chain.genesis)
    assert harness.chain.add_block(stale).status == "side"
    assert harness.chain.tip.hash == tip.hash  # equal work: first seen wins


def test_duplicate_block_is_idempotent(harness: ChainHarness, alice: Wallet) -> None:
    block = harness.mine(alice.script_pubkey)
    result = harness.chain.add_block(block).check()
    assert result.status == "duplicate"
    assert result.index is not None
    assert result.index.height == 1


def test_halving() -> None:
    p = REGTEST
    assert p.block_reward(0) == 50 * COIN
    assert p.block_reward(p.halving_interval - 1) == 50 * COIN
    assert p.block_reward(p.halving_interval) == 25 * COIN
    assert p.block_reward(p.halving_interval * 3) == 50 * COIN // 8
    assert p.block_reward(p.halving_interval * 64) == 0


def test_halving_applies_on_chain(alice: Wallet) -> None:
    h = ChainHarness(REGTEST.with_overrides(halving_interval=3))
    blocks = h.mine_many(4, alice.script_pubkey)
    assert [b.txs[0].total_out() for b in blocks] == [50 * COIN, 50 * COIN, 25 * COIN, 25 * COIN]


def test_difficulty_rises_when_blocks_are_fast(alice: Wallet) -> None:
    params = REGTEST.with_overrides(pow_limit_bits=0x2100FFFF, genesis_bits=0x2000FFFF)
    h = ChainHarness(params)
    for _ in range(params.retarget_interval - 1):
        h.mine(alice.script_pubkey, step_ms=params.target_block_time_ms // 4)
    before = h.chain.tip.header.bits
    h.mine(alice.script_pubkey, step_ms=params.target_block_time_ms // 4)
    after = h.chain.tip.header.bits
    assert bits_to_target(after) < bits_to_target(before)
    assert bits_to_target(after) == pytest.approx(bits_to_target(before) / 4, rel=0.01)


def test_difficulty_falls_when_blocks_are_slow(alice: Wallet) -> None:
    params = REGTEST.with_overrides(pow_limit_bits=0x2100FFFF, genesis_bits=0x2000FFFF)
    h = ChainHarness(params)
    for _ in range(params.retarget_interval):
        h.mine(alice.script_pubkey, step_ms=params.target_block_time_ms * 2)
    assert bits_to_target(h.chain.tip.header.bits) == pytest.approx(
        bits_to_target(0x2000FFFF) * 2, rel=0.01
    )


def test_header_mining_respects_bits() -> None:
    header = BlockHeader(bytes(32), bytes(32), 0, 0x2000FFFF)
    solved = mine_header(header)
    assert solved is not None
    assert solved.check_pow()


def test_spend_unknown_input(harness: ChainHarness) -> None:
    tx = Transaction((TxIn(OutPoint(b"\x09" * 32, 0)),), (TxOut(1, b""),))
    from forkchain.validation import MissingInputsError

    with pytest.raises(MissingInputsError):
        check_tx_inputs(tx, harness.chain.utxos, 1, REGTEST)
