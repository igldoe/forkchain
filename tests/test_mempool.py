from __future__ import annotations

import pytest

from forkchain.errors import ValidationError
from forkchain.mempool import Mempool, MempoolPolicy
from forkchain.params import COIN
from forkchain.tx import OutPoint, Transaction, TxIn, TxOut
from forkchain.utxo import Coin
from forkchain.validation import MissingInputsError
from forkchain.wallet import Wallet

from .conftest import ChainHarness


@pytest.fixture
def funded(harness: ChainHarness, alice: Wallet) -> ChainHarness:
    harness.mine_many(6, alice.script_pubkey)
    return harness


def coins(h: ChainHarness, w: Wallet) -> list[tuple[OutPoint, Coin]]:
    return h.chain.utxos.coins_for_script(w.script_pubkey)


def pay(w: Wallet, coin: tuple[OutPoint, Coin], to: Wallet, amount: int, fee: int) -> Transaction:
    return w.build_payment([coin], [TxOut(amount, to.script_pubkey)], fee=fee)


def own_output(tx: Transaction, w: Wallet, index: int) -> tuple[OutPoint, Coin]:
    out = tx.outputs[index]
    assert out.script_pubkey == w.script_pubkey
    return OutPoint(tx.txid, index), Coin(out, 0, False)


def test_accept_and_query(funded: ChainHarness, alice: Wallet, bob: Wallet) -> None:
    pool = Mempool(funded.chain)
    tx = pay(alice, coins(funded, alice)[0], bob, COIN, 1000)
    result = pool.accept(tx)
    assert result.fee == 1000
    assert tx.txid in pool
    assert pool.get(tx.txid) == tx
    assert pool.total_bytes == tx.size
    with pytest.raises(ValidationError, match="already-in-mempool"):
        pool.accept(tx)


def test_rejects_low_fee_coinbase_and_unknown(
    funded: ChainHarness, alice: Wallet, bob: Wallet
) -> None:
    pool = Mempool(funded.chain)
    with pytest.raises(ValidationError, match="min-relay-fee"):
        pool.accept(pay(alice, coins(funded, alice)[0], bob, COIN, 1))
    with pytest.raises(ValidationError, match="coinbase"):
        pool.accept(funded.chain.block_at(1).txs[0])
    with pytest.raises(MissingInputsError):
        pool.accept(Transaction((TxIn(OutPoint(b"\x05" * 32, 0)),), (TxOut(1, b""),)))


def test_double_spend_without_bump_is_rejected(
    funded: ChainHarness, alice: Wallet, bob: Wallet
) -> None:
    pool = Mempool(funded.chain)
    coin = coins(funded, alice)[0]
    pool.accept(pay(alice, coin, bob, COIN, 1000))
    with pytest.raises(ValidationError, match="insufficient-fee"):
        pool.accept(pay(alice, coin, alice, COIN, 1000))
    assert len(pool) == 1


def test_rbf_replaces_with_descendants(funded: ChainHarness, alice: Wallet, bob: Wallet) -> None:
    pool = Mempool(funded.chain)
    coin = coins(funded, alice)[0]
    parent = pay(alice, coin, bob, COIN, 1000)
    pool.accept(parent)
    child = pay(alice, own_output(parent, alice, 1), bob, COIN, 1000)
    pool.accept(child)
    assert pool.entries[child.txid].parents == {parent.txid}

    replacement = pay(alice, coin, alice, COIN, 5000)
    result = pool.accept(replacement)
    assert set(result.replaced) == {parent.txid, child.txid}
    assert list(pool.entries) == [replacement.txid]
    assert not pool.spends.get(OutPoint(parent.txid, 1))


def test_rbf_needs_higher_feerate(funded: ChainHarness, alice: Wallet, bob: Wallet) -> None:
    pool = Mempool(funded.chain, MempoolPolicy(incremental_feerate=0))
    coin = coins(funded, alice)[0]
    small = pay(alice, coin, bob, COIN, 2000)
    pool.accept(small)
    # Same absolute fee + more bytes => lower fee rate, even though it covers relay cost.
    bigger = alice.build_payment(
        [coin], [TxOut(COIN, bob.script_pubkey), TxOut(COIN, bob.script_pubkey)], fee=2000
    )
    with pytest.raises(ValidationError, match="insufficient-feerate"):
        pool.accept(bigger)


def test_replacement_cannot_spend_what_it_replaces(
    funded: ChainHarness, alice: Wallet, bob: Wallet
) -> None:
    pool = Mempool(funded.chain)
    a, b = coins(funded, alice)[:2]
    parent = pay(alice, a, bob, COIN, 1000)
    pool.accept(parent)
    # Spends both parent's input and parent's own output: impossible once parent is gone.
    sneaky = alice.build_payment(
        [a, own_output(parent, alice, 1)], [TxOut(60 * COIN, bob.script_pubkey)], 9000
    )
    assert len(sneaky.inputs) == 2
    with pytest.raises(MissingInputsError):
        pool.accept(sneaky)
    assert b  # second coin untouched


def test_eviction_by_feerate(funded: ChainHarness, alice: Wallet, bob: Wallet) -> None:
    sample = pay(alice, coins(funded, alice)[0], bob, COIN, 1000)
    pool = Mempool(funded.chain, MempoolPolicy(max_bytes=sample.size * 2 + 10))
    c = coins(funded, alice)
    cheap = pay(alice, c[0], bob, COIN, 500)
    mid = pay(alice, c[1], bob, COIN, 1000)
    pool.accept(cheap)
    pool.accept(mid)
    rich = pay(alice, c[2], bob, COIN, 3000)
    result = pool.accept(rich)
    assert result.evicted == (cheap.txid,)
    assert set(pool.entries) == {mid.txid, rich.txid}
    with pytest.raises(ValidationError, match="mempool-full"):
        pool.accept(pay(alice, c[3], bob, COIN, 400))


def test_eviction_never_evicts_own_parent(funded: ChainHarness, alice: Wallet, bob: Wallet) -> None:
    c = coins(funded, alice)
    parent = pay(alice, c[0], bob, COIN, 300)
    other = pay(alice, c[1], bob, COIN, 2000)
    child = pay(alice, own_output(parent, alice, 1), bob, COIN, 5000)
    pool = Mempool(funded.chain, MempoolPolicy(max_bytes=parent.size + other.size + child.size - 1))
    pool.accept(parent)
    pool.accept(other)
    result = pool.accept(child)
    assert result.evicted == (other.txid,)
    assert set(pool.entries) == {parent.txid, child.txid}


def test_oversized_for_pool(funded: ChainHarness, alice: Wallet, bob: Wallet) -> None:
    pool = Mempool(funded.chain, MempoolPolicy(max_bytes=50))
    with pytest.raises(ValidationError, match="larger than mempool"):
        pool.accept(pay(alice, coins(funded, alice)[0], bob, COIN, 1000))


def test_select_orders_by_feerate_and_parents_first(
    funded: ChainHarness, alice: Wallet, bob: Wallet
) -> None:
    pool = Mempool(funded.chain)
    c = coins(funded, alice)
    low = pay(alice, c[0], bob, COIN, 500)
    high = pay(alice, c[1], bob, COIN, 8000)
    child_of_low = pay(alice, own_output(low, alice, 1), bob, COIN, 20000)
    for tx in (low, high, child_of_low):
        pool.accept(tx)
    txs, fees = pool.select(10**6)
    order = [t.txid for t in txs]
    assert order.index(low.txid) < order.index(child_of_low.txid)
    assert order[0] == high.txid
    assert fees == 28500
    limited, _ = pool.select(high.size)
    assert [t.txid for t in limited] == [high.txid]


def test_block_connected_removes_confirmed_and_conflicts(
    funded: ChainHarness, alice: Wallet, bob: Wallet
) -> None:
    pool = Mempool(funded.chain)
    c = coins(funded, alice)
    in_pool = pay(alice, c[0], bob, COIN, 1000)
    child = pay(alice, own_output(in_pool, alice, 1), bob, COIN, 1000)
    unrelated = pay(alice, c[1], bob, COIN, 1000)
    for tx in (in_pool, child, unrelated):
        pool.accept(tx)
    # A conflicting spend of c[0] gets mined instead (e.g. by a different node).
    conflicting = pay(alice, c[0], alice, 2 * COIN, 1000)
    block = funded.mine(alice.script_pubkey, [conflicting], fees=1000)
    conflicted = pool.block_connected(block)
    assert conflicted == {in_pool.txid, child.txid}
    assert set(pool.entries) == {unrelated.txid}

    block2 = funded.mine(alice.script_pubkey, [unrelated], fees=1000)
    assert pool.block_connected(block2) == set()
    assert len(pool) == 0


def test_confirmed_parent_unlinks_child(funded: ChainHarness, alice: Wallet, bob: Wallet) -> None:
    pool = Mempool(funded.chain)
    parent = pay(alice, coins(funded, alice)[0], bob, COIN, 1000)
    child = pay(alice, own_output(parent, alice, 1), bob, COIN, 1000)
    pool.accept(parent)
    pool.accept(child)
    pool.block_connected(funded.mine(alice.script_pubkey, [parent], fees=1000))
    assert pool.entries[child.txid].parents == set()


def test_resync_keeps_valid_and_drops_invalid(
    funded: ChainHarness, alice: Wallet, bob: Wallet
) -> None:
    pool = Mempool(funded.chain)
    c = coins(funded, alice)
    good = pay(alice, c[0], bob, COIN, 1000)
    pool.accept(good)
    returned_ok = pay(alice, c[1], bob, COIN, 1000)
    returned_bad = Transaction((TxIn(OutPoint(b"\x07" * 32, 0)),), (TxOut(1, b""),))
    readded, dropped = pool.resync([funded.chain.block_at(1).txs[0], returned_ok, returned_bad])
    assert readded == [returned_ok.txid, good.txid]
    assert dropped == [returned_bad.txid]


def test_entry_json(funded: ChainHarness, alice: Wallet, bob: Wallet) -> None:
    pool = Mempool(funded.chain)
    tx = pay(alice, coins(funded, alice)[0], bob, COIN, 1000)
    pool.accept(tx)
    doc = pool.sorted_entries()[0].to_json()
    assert doc["txid"] == tx.txid.hex()
    assert doc["fee"] == 1000
