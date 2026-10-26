"""Block headers, blocks, stateless validation and the PoW search loop."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from functools import cached_property

from forkchain.crypto import ZERO_HASH, sha256d
from forkchain.encoding import DecodeError, Reader, Writer
from forkchain.errors import ValidationError
from forkchain.merkle import merkle_root
from forkchain.params import ConsensusParams
from forkchain.pow import bits_to_target, hash_meets_target
from forkchain.tx import Transaction, TxOut, make_coinbase

HEADER_SIZE = 88
MAX_BLOCK_TXS = 20_000


@dataclass(frozen=True)
class BlockHeader:
    prev_hash: bytes
    merkle_root: bytes
    timestamp: int  # milliseconds since the Unix epoch
    bits: int
    nonce: int = 0
    version: int = 1

    def serialize(self) -> bytes:
        # The nonce is deliberately last: the miner can hash the 80-byte prefix once and
        # only feed the nonce for every attempt (see ``mine_header``).
        return self._prefix() + self.nonce.to_bytes(8, "little")

    def _prefix(self) -> bytes:
        return (
            Writer()
            .u32(self.version)
            .raw(self.prev_hash)
            .raw(self.merkle_root)
            .u64(self.timestamp)
            .u32(self.bits)
            .getvalue()
        )

    @classmethod
    def read_from(cls, r: Reader) -> BlockHeader:
        version = r.u32()
        prev_hash = r.raw(32)
        root = r.raw(32)
        timestamp = r.u64()
        bits = r.u32()
        nonce = r.u64()
        return cls(prev_hash, root, timestamp, bits, nonce, version)

    @classmethod
    def deserialize(cls, data: bytes) -> BlockHeader:
        r = Reader(data)
        header = cls.read_from(r)
        r.expect_end()
        return header

    @cached_property
    def hash(self) -> bytes:
        return sha256d(self.serialize())

    def check_pow(self) -> bool:
        try:
            return hash_meets_target(self.hash, self.bits)
        except ValueError:
            return False


@dataclass(frozen=True)
class Block:
    header: BlockHeader
    txs: tuple[Transaction, ...]

    @property
    def hash(self) -> bytes:
        return self.header.hash

    @property
    def prev_hash(self) -> bytes:
        return self.header.prev_hash

    def serialize(self) -> bytes:
        w = Writer().raw(self.header.serialize()).varint(len(self.txs))
        for tx in self.txs:
            w.raw(tx.serialize())
        return w.getvalue()

    @classmethod
    def deserialize(cls, data: bytes) -> Block:
        r = Reader(data)
        header = BlockHeader.read_from(r)
        n = r.varint()
        if n > MAX_BLOCK_TXS:
            raise DecodeError("too many transactions")
        try:
            txs = tuple(Transaction.read_from(r) for _ in range(n))
        except ValueError as exc:
            raise DecodeError(str(exc)) from exc
        r.expect_end()
        return cls(header, txs)

    @cached_property
    def size(self) -> int:
        return len(self.serialize())

    def compute_merkle_root(self) -> bytes:
        return merkle_root([tx.txid for tx in self.txs])


def check_block(block: Block, params: ConsensusParams) -> None:
    """Context-free validity checks (anything that does not need the chain or UTXO set)."""
    if not block.header.check_pow():
        raise ValidationError("high-hash", "proof of work does not meet target")
    try:
        if bits_to_target(block.header.bits) > bits_to_target(params.pow_limit_bits):
            raise ValidationError("bad-bits", "target above pow limit")
    except ValueError as exc:
        raise ValidationError("bad-bits", str(exc)) from exc
    if not block.txs:
        raise ValidationError("bad-blk-empty", "block has no transactions")
    if block.size > params.max_block_size:
        raise ValidationError("bad-blk-size", f"{block.size} > {params.max_block_size}")
    if not block.txs[0].is_coinbase:
        raise ValidationError("bad-cb-missing", "first transaction is not coinbase")
    if any(tx.is_coinbase for tx in block.txs[1:]):
        raise ValidationError("bad-cb-multiple", "more than one coinbase")
    txids = [tx.txid for tx in block.txs]
    if len(set(txids)) != len(txids):
        raise ValidationError("bad-txns-duplicate", "duplicate transaction")
    if block.compute_merkle_root() != block.header.merkle_root:
        raise ValidationError("bad-merkle", "merkle root mismatch")
    for tx in block.txs:
        check_tx_basic(tx, params)


def check_tx_basic(tx: Transaction, params: ConsensusParams) -> None:
    """Structural transaction checks that need no context."""
    if not tx.inputs:
        raise ValidationError("bad-txns-vin-empty")
    if not tx.outputs:
        raise ValidationError("bad-txns-vout-empty")
    if tx.size > params.max_tx_size:
        raise ValidationError("bad-txns-oversize")
    total = 0
    for out in tx.outputs:
        if out.value < 0:
            raise ValidationError("bad-txns-vout-negative")
        total += out.value
        if total > 21_000_000 * 100_000_000:
            raise ValidationError("bad-txns-txouttotal-toolarge")
    prevouts = [i.prevout for i in tx.inputs]
    if len(set(prevouts)) != len(prevouts):
        raise ValidationError("bad-txns-inputs-duplicate")
    if not tx.is_coinbase and any(p.is_null for p in prevouts):
        raise ValidationError("bad-txns-prevout-null")


def mine_header(header: BlockHeader, start: int = 0, count: int = 1 << 64) -> BlockHeader | None:
    """Search ``count`` nonces from ``start``; return the solved header or ``None``.

    The 80-byte prefix is absorbed into a SHA-256 state once and copied for every nonce,
    which roughly doubles throughput compared to hashing the full header each time.
    """
    target = bits_to_target(header.bits)
    base = hashlib.sha256(header._prefix())
    sha = hashlib.sha256
    end = min(start + count, 1 << 64)
    for nonce in range(start, end):
        h = base.copy()
        h.update(nonce.to_bytes(8, "little"))
        if int.from_bytes(sha(h.digest()).digest(), "big") <= target:
            return replace(header, nonce=nonce)
    return None


GENESIS_MESSAGE = b"forkchain genesis: educational, not for real funds"


def make_genesis(params: ConsensusParams) -> Block:
    """The genesis block is fixed by the params and is never PoW-checked."""
    coinbase = make_coinbase(0, (TxOut(0, b""),), extra=GENESIS_MESSAGE)
    header = BlockHeader(
        prev_hash=ZERO_HASH,
        merkle_root=merkle_root([coinbase.txid]),
        timestamp=params.genesis_timestamp_ms,
        bits=params.genesis_bits,
    )
    return Block(header, (coinbase,))
