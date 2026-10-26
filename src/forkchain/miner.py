"""Block templates and a blocking miner (the async, hashrate-limited one lives in the node)."""

from __future__ import annotations

from collections.abc import Sequence

from forkchain.block import Block, BlockHeader, mine_header
from forkchain.chain import BlockIndex, Chain
from forkchain.merkle import merkle_root
from forkchain.tx import Transaction, TxOut, make_coinbase


def build_template(
    chain: Chain,
    script_pubkey: bytes,
    txs: Sequence[Transaction] = (),
    *,
    fees: int = 0,
    timestamp: int | None = None,
    parent: BlockIndex | None = None,
    extra: bytes = b"",
) -> Block:
    """Assemble an unsolved block on top of ``parent`` (default: the tip).

    ``fees`` must be the total fee of ``txs``; the caller (mempool) already knows it.
    """
    parent = parent or chain.tip
    height = parent.height + 1
    reward = chain.params.block_reward(height) + fees
    coinbase = make_coinbase(height, (TxOut(reward, script_pubkey),), extra=extra)
    all_txs = (coinbase, *txs)
    mtp = chain.median_time_past(parent)
    ts = max(timestamp if timestamp is not None else chain.clock(), mtp + 1)
    header = BlockHeader(
        prev_hash=parent.hash,
        merkle_root=merkle_root([tx.txid for tx in all_txs]),
        timestamp=ts,
        bits=chain.next_bits(parent),
    )
    return Block(header, all_txs)


def solve(block: Block) -> Block:
    header = mine_header(block.header)
    if header is None:  # pragma: no cover - 2**64 nonces at test difficulty never run out
        raise RuntimeError("nonce space exhausted")
    return Block(header, block.txs)


def mine_block(
    chain: Chain,
    script_pubkey: bytes,
    txs: Sequence[Transaction] = (),
    *,
    fees: int = 0,
    timestamp: int | None = None,
    parent: BlockIndex | None = None,
    extra: bytes = b"",
) -> Block:
    template = build_template(
        chain, script_pubkey, txs, fees=fees, timestamp=timestamp, parent=parent, extra=extra
    )
    return solve(template)
