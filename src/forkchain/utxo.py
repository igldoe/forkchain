"""The unspent transaction output set and block undo data."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Protocol

from forkchain.block import Block
from forkchain.tx import OutPoint, Transaction, TxOut


@dataclass(frozen=True)
class Coin:
    output: TxOut
    height: int
    is_coinbase: bool


class UtxoView(Protocol):
    def get(self, outpoint: OutPoint) -> Coin | None: ...


@dataclass
class BlockUndo:
    """Coins a block consumed, in spend order, so the block can be disconnected later."""

    spent: list[tuple[OutPoint, Coin]] = field(default_factory=list)


class UtxoSet:
    def __init__(self) -> None:
        self._coins: dict[OutPoint, Coin] = {}
        self._by_script: defaultdict[bytes, set[OutPoint]] = defaultdict(set)

    def get(self, outpoint: OutPoint) -> Coin | None:
        return self._coins.get(outpoint)

    def __contains__(self, outpoint: object) -> bool:
        return outpoint in self._coins

    def __len__(self) -> int:
        return len(self._coins)

    def __iter__(self) -> Iterator[tuple[OutPoint, Coin]]:
        return iter(self._coins.items())

    def add(self, outpoint: OutPoint, coin: Coin) -> None:
        if outpoint in self._coins:
            raise KeyError(f"coin {outpoint} already exists")
        self._coins[outpoint] = coin
        self._by_script[coin.output.script_pubkey].add(outpoint)

    def spend(self, outpoint: OutPoint) -> Coin:
        coin = self._coins.pop(outpoint)
        bucket = self._by_script[coin.output.script_pubkey]
        bucket.discard(outpoint)
        if not bucket:
            del self._by_script[coin.output.script_pubkey]
        return coin

    def coins_for_script(self, script_pubkey: bytes) -> list[tuple[OutPoint, Coin]]:
        return sorted((op, self._coins[op]) for op in self._by_script.get(script_pubkey, ()))

    def total_value(self) -> int:
        return sum(c.output.value for c in self._coins.values())

    def apply_tx(self, tx: Transaction, height: int, undo: BlockUndo | None = None) -> None:
        if not tx.is_coinbase:
            for txin in tx.inputs:
                coin = self.spend(txin.prevout)
                if undo is not None:
                    undo.spent.append((txin.prevout, coin))
        for index, out in enumerate(tx.outputs):
            self.add(OutPoint(tx.txid, index), Coin(out, height, tx.is_coinbase))

    def apply_block(self, block: Block, height: int) -> BlockUndo:
        undo = BlockUndo()
        for tx in block.txs:
            self.apply_tx(tx, height, undo)
        return undo

    def undo_block(self, block: Block, undo: BlockUndo) -> None:
        """Exactly reverse ``apply_block``, one transaction at a time, last one first.

        Each transaction's outputs are removed *before* its inputs are restored. Doing all
        removals first would break on a block where a later tx spends an earlier tx's
        output: that output is already gone from the set.
        """
        spent = list(undo.spent)
        for tx in reversed(block.txs):
            for index in range(len(tx.outputs)):
                self.spend(OutPoint(tx.txid, index))
            if tx.is_coinbase:
                continue
            for _ in tx.inputs:
                outpoint, coin = spent.pop()
                self.add(outpoint, coin)
        if spent:
            raise ValueError("undo data does not match block")


class OverlayView:
    """Copy-on-write layer over a base view: lets us validate a sequence of transactions
    (a block, or a mempool chain) without mutating the real UTXO set."""

    def __init__(self, base: UtxoView) -> None:
        self._base = base
        self._added: dict[OutPoint, Coin] = {}
        self._spent: set[OutPoint] = set()

    def get(self, outpoint: OutPoint) -> Coin | None:
        if outpoint in self._spent:
            return None
        coin = self._added.get(outpoint)
        return coin if coin is not None else self._base.get(outpoint)

    def apply_tx(self, tx: Transaction, height: int) -> None:
        if not tx.is_coinbase:
            for txin in tx.inputs:
                self._spent.add(txin.prevout)
        for index, out in enumerate(tx.outputs):
            self._added[OutPoint(tx.txid, index)] = Coin(out, height, tx.is_coinbase)
