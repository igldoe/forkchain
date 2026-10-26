"""Fork choice, reorgs, orphan handling and the mempool's reaction to them."""

from __future__ import annotations

from dataclasses import replace

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from forkchain.block import Block
from forkchain.chain import BlockIndex, Chain
from forkchain.errors import MissingDataError, ValidationError
from forkchain.mempool import Mempool
from forkchain.miner import mine_block
from forkchain.params import COIN, REGTEST, ConsensusParams
from forkchain.pow import block_work
from forkchain.tx import Transaction, TxOut
from forkchain.wallet import Wallet

from .conftest import FakeClock, wallet

DAY_MS = 86_400_000


def new_chain(params: ConsensusParams = REGTEST) -> Chain:
    # Clock far ahead so that hand-picked timestamps are never "too far in the future".
    return Chain(params, clock=FakeClock(params.genesis_timestamp_ms + 30 * DAY_MS))


def extend(
    chain: Chain,
    parent: BlockIndex,
    n: int,
    script: bytes,
    *,
    tag: bytes,
    step_ms: int = 1000,
    txs: dict[int, list[Transaction]] | None = None,
) -> list[Block]:
    """Mine ``n`` blocks on ``parent`` (not necessarily the tip) and feed them to the chain."""
    blocks = []
    for i in range(n):
        block_txs = (txs or {}).get(i, [])
        block = mine_block(
            chain,
            script,
            block_txs,
            parent=parent,
            timestamp=parent.header.timestamp + step_ms,
            extra=tag,
        )
        chain.add_block(block)
        parent = chain.index[block.hash]
        blocks.append(block)
    return blocks


def utxo_snapshot(chain: Chain) -> dict[object, object]:
    return dict(chain.utxos)


def replay(chain: Chain) -> Chain:
    """A fresh chain fed only the active blocks, in order."""
    fresh = new_chain(chain.params)
    for height in range(1, chain.height + 1):
        fresh.add_block(chain.block_at(height)).check()
    return fresh


def test_heavier_branch_wins_and_utxos_match_replay() -> None:
    chain = new_chain()
    miner = wallet("m").script_pubkey
    a = extend(chain, chain.genesis, 3, miner, tag=b"A")
    assert chain.tip.hash == a[-1].hash
    b = extend(chain, chain.genesis, 4, miner, tag=b"B")
    assert chain.tip.hash == b[-1].hash
    assert chain.height == 4
    assert not chain.contains(a[0].hash)
    assert utxo_snapshot(chain) == utxo_snapshot(replay(chain))


def test_equal_work_keeps_first_seen() -> None:
    chain = new_chain()
    miner = wallet("m").script_pubkey
    a = extend(chain, chain.genesis, 2, miner, tag=b"A")
    result = chain.add_block(
        mine_block(
            chain,
            miner,
            parent=chain.genesis,
            timestamp=chain.genesis.header.timestamp + 5,
            extra=b"B",
        )
    )
    assert result.status == "side"
    extend(chain, chain.index[result.index.hash], 1, miner, tag=b"B")  # type: ignore[union-attr]
    assert chain.tip.hash == a[-1].hash


def test_reorg_update_reports_depth_and_blocks() -> None:
    chain = new_chain()
    miner = wallet("m").script_pubkey
    a = extend(chain, chain.genesis, 3, miner, tag=b"A")
    b = extend(chain, chain.genesis, 3, miner, tag=b"B")
    final = mine_block(
        chain,
        miner,
        parent=chain.index[b[-1].hash],
        timestamp=b[-1].header.timestamp + 1000,
        extra=b"B",
    )
    result = chain.add_block(final)
    assert result.status == "active"
    assert result.update.reorg_depth == 3
    assert [blk.hash for blk in result.update.disconnected] == [x.hash for x in reversed(a)]
    assert [blk.hash for blk in result.update.connected] == [*(x.hash for x in b), final.hash]


def test_most_work_beats_longest_chain() -> None:
    params = REGTEST.with_overrides(retarget_interval=4, target_block_time_ms=1000)
    chain = new_chain(params)
    miner = wallet("m").script_pubkey
    # Easy branch: on-schedule blocks, difficulty stays at the pow limit (work ~1 each).
    easy = extend(chain, chain.genesis, 10, miner, tag=b"easy", step_ms=1000)
    assert chain.tip.hash == easy[-1].hash
    # Hard branch: blocks 4x too fast, so from height 4 on each block is worth ~4x the work.
    hard = extend(chain, chain.genesis, 6, miner, tag=b"hard", step_ms=250)
    assert chain.index[hard[-1].hash].height < chain.index[easy[-1].hash].height
    assert chain.index[hard[-1].hash].chainwork > chain.index[easy[-1].hash].chainwork
    assert chain.tip.hash == hard[-1].hash


def test_reorg_returns_transactions_to_mempool() -> None:
    chain = new_chain()
    alice, bob = wallet("alice"), wallet("bob")
    base = extend(chain, chain.genesis, 2, alice.script_pubkey, tag=b"base")
    pool = Mempool(chain, clock=chain.clock)
    coin = chain.utxos.coins_for_script(alice.script_pubkey)[0]
    pay = alice.build_payment([coin], [TxOut(COIN, bob.script_pubkey)], fee=1000)
    pool.accept(pay)
    fork_point = chain.index[base[-1].hash]
    a = extend(chain, fork_point, 1, alice.script_pubkey, tag=b"A", txs={0: [pay]})
    pool.block_connected(a[0])
    assert pay.txid not in pool

    blocks_b = extend(chain, fork_point, 1, alice.script_pubkey, tag=b"B")
    last = mine_block(
        chain,
        alice.script_pubkey,
        parent=chain.index[blocks_b[-1].hash],
        timestamp=blocks_b[-1].header.timestamp + 1000,
        extra=b"B",
    )
    result = chain.add_block(last)
    assert result.update.reorg_depth == 1
    sync = pool.chain_updated(result.update)
    assert sync.reverted == (pay.txid,)
    assert sync.readded == (pay.txid,)
    assert pay.txid in pool


def test_double_spend_via_reorg_drops_victim_tx() -> None:
    """The classic 51% double spend: the merchant's payment is replaced by a conflicting one."""
    chain = new_chain()
    attacker, merchant = wallet("attacker"), wallet("merchant")
    base = extend(chain, chain.genesis, 2, attacker.script_pubkey, tag=b"base")
    fork_point = chain.index[base[-1].hash]
    coin = chain.utxos.coins_for_script(attacker.script_pubkey)[0]
    to_merchant = attacker.build_payment(
        [coin], [TxOut(10 * COIN, merchant.script_pubkey)], fee=1000
    )
    to_self = attacker.build_payment([coin], [TxOut(10 * COIN, attacker.script_pubkey)], fee=2000)

    pool = Mempool(chain, clock=chain.clock)
    honest = extend(
        chain, fork_point, 2, merchant.script_pubkey, tag=b"honest", txs={0: [to_merchant]}
    )
    assert chain.contains(honest[0].hash)
    assert chain.utxos.coins_for_script(merchant.script_pubkey)

    # Attacker's private chain spends the same coin to themselves and is one block longer.
    private = extend(chain, fork_point, 2, attacker.script_pubkey, tag=b"evil", txs={0: [to_self]})
    tip_before = chain.tip.hash
    final = mine_block(
        chain,
        attacker.script_pubkey,
        parent=chain.index[private[-1].hash],
        timestamp=private[-1].header.timestamp + 1000,
        extra=b"evil",
    )
    result = chain.add_block(final)
    assert tip_before == honest[-1].hash
    assert result.update.reorg_depth == 2
    sync = pool.chain_updated(result.update)
    assert to_merchant.txid in sync.reverted
    assert to_merchant.txid in sync.dropped  # its input is now spent by to_self
    assert to_merchant.txid not in pool
    merchant_coins = [c for _, c in chain.utxos.coins_for_script(merchant.script_pubkey)]
    assert all(c.output.value != 10 * COIN for c in merchant_coins)


def test_invalid_block_on_heavier_branch_falls_back() -> None:
    chain = new_chain()
    miner = wallet("m")
    a = extend(chain, chain.genesis, 2, miner.script_pubkey, tag=b"A")
    snapshot = utxo_snapshot(chain)

    b1 = extend(chain, chain.genesis, 1, miner.script_pubkey, tag=b"B")[0]
    # b2 overpays its coinbase: statelessly fine, contextually invalid.
    b1_idx = chain.index[b1.hash]
    b2 = mine_block(
        chain,
        miner.script_pubkey,
        parent=b1_idx,
        fees=1,
        timestamp=b1.header.timestamp + 1000,
        extra=b"B",
    )
    # Tie with A: a side branch is not fully validated until it would become active.
    assert chain.add_block(b2).status == "side"
    b3 = mine_block(
        chain,
        miner.script_pubkey,
        parent=chain.index[b2.hash],
        timestamp=b2.header.timestamp + 1000,
        extra=b"B",
    )
    result = chain.add_block(b3)
    assert result.status == "invalid"
    assert result.error is not None
    assert chain.tip.hash == a[-1].hash
    assert utxo_snapshot(chain) == snapshot
    assert chain.index[b3.hash].invalid


def test_invalid_branch_reverts_to_previous_chain() -> None:
    chain = new_chain()
    miner = wallet("m")
    a = extend(chain, chain.genesis, 2, miner.script_pubkey, tag=b"A")
    snapshot = utxo_snapshot(chain)
    # Feed a 3-block branch whose middle block is bad, deepest block first (as orphans),
    # so the whole branch shows up at once and a real reorg is attempted.
    b1 = mine_block(
        chain,
        miner.script_pubkey,
        parent=chain.genesis,
        timestamp=chain.genesis.header.timestamp + 1000,
        extra=b"B",
    )
    # Build b2 (invalid: overpaid coinbase) and b3 on a scratch chain, faking b2's index
    # entry there so b3 can be templated on top of it.
    shadow = new_chain()
    shadow.add_block(b1).check()
    b2 = mine_block(
        shadow, miner.script_pubkey, fees=1, timestamp=b1.header.timestamp + 1000, extra=b"B"
    )
    work = shadow.tip.chainwork + block_work(b2.header.bits)
    b2_idx = BlockIndex(b2.header, 2, work, shadow.tip)
    b3 = mine_block(
        shadow, miner.script_pubkey, parent=b2_idx, timestamp=b2.header.timestamp + 1000, extra=b"B"
    )

    assert chain.add_block(b3).status == "orphan"
    assert chain.add_block(b2).status == "orphan"
    result = chain.add_block(b1)
    # A2, A1 were disconnected, B1 connected, B2 failed, then B1 out and A1, A2 back in.
    assert len(result.update.disconnected) == 3
    assert result.update.reorg_depth == 0
    assert chain.tip.hash == a[-1].hash
    assert utxo_snapshot(chain) == snapshot
    assert chain.index[b2.hash].invalid
    assert chain.index[b3.hash].invalid
    assert not chain.index[b1.hash].invalid
    assert chain.add_block(b3).status == "duplicate"


def test_orphans_connect_when_parent_arrives() -> None:
    source = new_chain()
    miner = wallet("m").script_pubkey
    blocks = extend(source, source.genesis, 5, miner, tag=b"x")
    chain = new_chain()
    for block in reversed(blocks[1:]):
        assert chain.add_block(block).status == "orphan"
    assert len(chain.orphans) == 4
    result = chain.add_block(blocks[0])
    assert chain.tip.hash == blocks[-1].hash
    assert len(result.update.connected) == 5
    assert not chain.orphans


def test_headers_first_download() -> None:
    source = new_chain()
    miner = wallet("m").script_pubkey
    blocks = extend(source, source.genesis, 6, miner, tag=b"x")
    chain = new_chain()
    headers = source.headers_after(chain.locator())
    assert [h.hash for h in headers] == [b.hash for b in blocks]
    for header in headers:
        chain.add_header(header)
    assert chain.best_header.hash == blocks[-1].hash
    assert chain.blocks_to_download(3) == [b.hash for b in blocks[:3]]
    # Bodies arrive out of order: later ones wait until the gap is filled.
    chain.add_block(blocks[2])
    chain.add_block(blocks[1])
    assert chain.height == 0
    chain.add_block(blocks[0])
    assert chain.height == 3
    for block in blocks[3:]:
        chain.add_block(block)
    assert chain.tip.hash == blocks[-1].hash
    assert chain.blocks_to_download(10) == []


def test_locator_and_headers_after_on_fork() -> None:
    chain = new_chain()
    miner = wallet("m").script_pubkey
    blocks = extend(chain, chain.genesis, 30, miner, tag=b"x")
    loc = chain.locator()
    assert loc[0] == blocks[-1].hash
    assert loc[-1] == chain.genesis.hash
    assert len(loc) < 30
    # A peer that knows up to block 20 gets 21..30.
    peer_locator = [blocks[19].hash, chain.genesis.hash]
    assert [h.hash for h in chain.headers_after(peer_locator)] == [b.hash for b in blocks[20:]]
    assert len(chain.headers_after([b"\x00" * 32], limit=5)) == 5


def test_bad_headers_rejected() -> None:
    source = new_chain()
    blocks = extend(source, source.genesis, 2, wallet("m").script_pubkey, tag=b"x")
    chain = new_chain()
    with pytest.raises(MissingDataError):
        chain.add_header(blocks[1].header)
    with pytest.raises(ValidationError, match="high-hash"):
        chain.add_header(replace(blocks[0].header, bits=0x03000001))


# -- property: any interleaving of forks ends in a state equal to a clean replay ----------


@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(st.tuples(st.integers(0, 3), st.integers(1, 3)), min_size=1, max_size=8))
def test_random_forks_converge_to_replayable_state(ops: list[tuple[int, int]]) -> None:
    """Each op: pick a fork point ``back`` blocks below the tip and mine ``n`` blocks there."""
    chain = new_chain()
    alice: Wallet = wallet("alice")
    for step, (back, n) in enumerate(ops):
        parent = chain.tip.ancestor(max(0, chain.height - back))
        extend(chain, parent, n, alice.script_pubkey, tag=bytes([step]))
        best = max(
            (i for i in chain.iter_index() if i.complete and not i.invalid),
            key=lambda i: i.chainwork,
        )
        assert chain.tip.chainwork == best.chainwork
    assert utxo_snapshot(chain) == utxo_snapshot(replay(chain))
    assert chain.utxos.total_value() == sum(
        REGTEST.block_reward(h) for h in range(1, chain.height + 1)
    )
