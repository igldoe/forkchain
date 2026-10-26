"""Transaction memory pool.

Policy (not consensus) rules, loosely following Bitcoin Core:

* transactions are prioritised by fee rate (fee per byte);
* an input may be spent by at most one pool transaction (double-spend protection);
* a conflicting transaction may *replace* the existing ones (full RBF) if it pays more in
  absolute fees, covers its own relay cost, and has a strictly higher fee rate;
* when the pool exceeds its byte budget, the lowest fee-rate transactions are evicted
  together with their in-pool descendants;
* unconfirmed chains are allowed: a transaction may spend outputs of pool transactions.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from forkchain.block import Block, check_tx_basic
from forkchain.chain import Chain, Clock, wall_clock_ms
from forkchain.errors import MissingDataError, ValidationError
from forkchain.tx import OutPoint, Transaction
from forkchain.utxo import Coin
from forkchain.validation import check_tx_inputs


@dataclass(frozen=True)
class MempoolPolicy:
    max_bytes: int = 2_000_000
    min_feerate: float = 1.0  # base units per byte
    incremental_feerate: float = 1.0  # extra fee rate a replacement must pay for its bytes


@dataclass
class MempoolEntry:
    tx: Transaction
    fee: int
    time_ms: int
    parents: set[bytes] = field(default_factory=set)  # in-pool txids this tx spends from

    @property
    def size(self) -> int:
        return self.tx.size

    @property
    def feerate(self) -> float:
        return self.fee / self.size

    def to_json(self) -> dict[str, object]:
        return {
            "txid": self.tx.txid.hex(),
            "fee": self.fee,
            "size": self.size,
            "feerate": round(self.feerate, 3),
            "time": self.time_ms,
            "parents": sorted(p.hex() for p in self.parents),
        }


@dataclass(frozen=True)
class AcceptResult:
    txid: bytes
    fee: int
    replaced: tuple[bytes, ...] = ()
    evicted: tuple[bytes, ...] = ()


class _PoolView:
    """UTXO view = chain tip + outputs of pool transactions - outputs they already spend.

    ``exclude`` hides transactions that are about to be replaced, so the newcomer is
    validated as if they were already gone.
    """

    def __init__(self, pool: Mempool, exclude: set[bytes]) -> None:
        self._pool = pool
        self._exclude = exclude

    def get(self, outpoint: OutPoint) -> Coin | None:
        spender = self._pool.spends.get(outpoint)
        if spender is not None and spender not in self._exclude:
            return None
        entry = self._pool.entries.get(outpoint.txid)
        if entry is not None and outpoint.txid not in self._exclude:
            if outpoint.index >= len(entry.tx.outputs):
                return None
            return Coin(entry.tx.outputs[outpoint.index], self._pool.chain.height + 1, False)
        return self._pool.chain.utxos.get(outpoint)


class Mempool:
    def __init__(
        self,
        chain: Chain,
        policy: MempoolPolicy | None = None,
        *,
        clock: Clock = wall_clock_ms,
    ) -> None:
        self.chain = chain
        self.policy = policy or MempoolPolicy()
        self._clock = clock
        self.entries: dict[bytes, MempoolEntry] = {}
        self.spends: dict[OutPoint, bytes] = {}
        self.total_bytes = 0

    def __contains__(self, txid: object) -> bool:
        return txid in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def get(self, txid: bytes) -> Transaction | None:
        entry = self.entries.get(txid)
        return entry.tx if entry else None

    # -- graph helpers ---------------------------------------------------------------------

    def children(self, txid: bytes) -> set[bytes]:
        entry = self.entries[txid]
        return {
            self.spends[op]
            for i in range(len(entry.tx.outputs))
            if (op := OutPoint(txid, i)) in self.spends
        }

    def descendants(self, txid: bytes) -> set[bytes]:
        seen: set[bytes] = set()
        stack = [txid]
        while stack:
            for child in self.children(stack.pop()):
                if child not in seen:
                    seen.add(child)
                    stack.append(child)
        return seen

    def ancestors(self, tx: Transaction) -> set[bytes]:
        seen: set[bytes] = set()
        stack = [i.prevout.txid for i in tx.inputs if i.prevout.txid in self.entries]
        while stack:
            txid = stack.pop()
            if txid not in seen:
                seen.add(txid)
                stack.extend(self.entries[txid].parents)
        return seen

    def _with_descendants(self, txids: Iterable[bytes]) -> set[bytes]:
        result: set[bytes] = set()
        for txid in txids:
            if txid in self.entries:
                result.add(txid)
                result |= self.descendants(txid)
        return result

    # -- mutation --------------------------------------------------------------------------

    def _insert(self, entry: MempoolEntry) -> None:
        txid = entry.tx.txid
        self.entries[txid] = entry
        for txin in entry.tx.inputs:
            self.spends[txin.prevout] = txid
        self.total_bytes += entry.size

    def _remove_one(self, txid: bytes) -> None:
        entry = self.entries.pop(txid)
        for txin in entry.tx.inputs:
            if self.spends.get(txin.prevout) == txid:
                del self.spends[txin.prevout]
        self.total_bytes -= entry.size

    def remove(self, txid: bytes, *, with_descendants: bool = True) -> set[bytes]:
        doomed = self._with_descendants([txid]) if with_descendants else {txid}
        for t in doomed:
            self._remove_one(t)
        return doomed

    def accept(self, tx: Transaction) -> AcceptResult:
        """Validate ``tx`` against the tip + pool and insert it.

        Raises ``ValidationError`` (with ``ban`` telling whether the sender misbehaved) or
        ``MissingInputsError`` when an input is unknown.
        """
        txid = tx.txid
        if txid in self.entries:
            raise ValidationError("txn-already-in-mempool", ban=False)
        if tx.is_coinbase:
            raise ValidationError("coinbase", "coinbase transactions are only valid in blocks")
        check_tx_basic(tx, self.chain.params)

        conflicts = {self.spends[i.prevout] for i in tx.inputs if i.prevout in self.spends}
        replaced = self._with_descendants(conflicts)

        verifier = {"verifier": self.chain.verifier} if self.chain.verifier else {}
        fee = check_tx_inputs(
            tx, _PoolView(self, replaced), self.chain.height + 1, self.chain.params, **verifier
        )
        feerate = fee / tx.size
        if feerate < self.policy.min_feerate:
            raise ValidationError(
                "min-relay-fee-not-met", f"{feerate:.2f} < {self.policy.min_feerate}", ban=False
            )
        if conflicts:
            self._check_replacement(tx, fee, conflicts, replaced)

        evicted = self._make_room(tx.size, feerate, replaced, protected=self.ancestors(tx))
        for t in replaced:
            self._remove_one(t)
        parents = {i.prevout.txid for i in tx.inputs if i.prevout.txid in self.entries}
        self._insert(MempoolEntry(tx, fee, self._clock(), parents))
        for t in evicted:
            if t in self.entries:
                self.remove(t)
        return AcceptResult(txid, fee, tuple(sorted(replaced)), tuple(sorted(evicted)))

    def _check_replacement(
        self, tx: Transaction, fee: int, conflicts: set[bytes], replaced: set[bytes]
    ) -> None:
        old_fees = sum(self.entries[t].fee for t in replaced)
        relay_cost = self.policy.incremental_feerate * tx.size
        if fee < old_fees + relay_cost:
            raise ValidationError(
                "insufficient-fee",
                f"replacement pays {fee}, needs at least {old_fees + relay_cost:.0f}",
                ban=False,
            )
        best_conflict = max(self.entries[t].feerate for t in conflicts)
        if fee / tx.size <= best_conflict:
            raise ValidationError(
                "insufficient-feerate", "replacement fee rate not higher than original", ban=False
            )

    def _make_room(
        self, size: int, feerate: float, leaving: set[bytes], *, protected: set[bytes]
    ) -> set[bytes]:
        """Pick victims so that ``size`` new bytes fit; refuse if the newcomer is cheapest.

        ``protected`` are the newcomer's in-pool ancestors: evicting them would evict it too.
        """
        budget = self.policy.max_bytes
        projected = self.total_bytes - sum(self.entries[t].size for t in leaving) + size
        if size > budget:
            raise ValidationError("mempool-full", "transaction larger than mempool", ban=False)
        victims: set[bytes] = set()
        candidates = sorted(
            (e for t, e in self.entries.items() if t not in leaving and t not in protected),
            key=lambda e: (e.feerate, -e.time_ms),
        )
        for entry in candidates:
            if projected <= budget:
                break
            if entry.tx.txid in victims:
                continue
            if entry.feerate >= feerate:
                raise ValidationError(
                    "mempool-full", "fee rate too low to enter full pool", ban=False
                )
            package = self._with_descendants([entry.tx.txid]) - leaving
            victims |= package
            projected -= sum(self.entries[t].size for t in package)
        return victims

    # -- chain events ----------------------------------------------------------------------

    def block_connected(self, block: Block) -> set[bytes]:
        """Drop confirmed transactions and everything that now double-spends the chain.

        Returns the txids evicted as conflicts (not the ones that were confirmed).
        """
        conflicted: set[bytes] = set()
        for tx in block.txs:
            if tx.txid in self.entries:
                self._remove_one(tx.txid)
                for entry in self.entries.values():
                    entry.parents.discard(tx.txid)
        for tx in block.txs:
            if tx.is_coinbase:
                continue
            for txin in tx.inputs:
                spender = self.spends.get(txin.prevout)
                if spender is not None and spender != tx.txid:
                    conflicted |= self.remove(spender)
        return conflicted

    def resync(self, returned: Sequence[Transaction] = ()) -> tuple[list[bytes], list[bytes]]:
        """Rebuild the pool after a reorg.

        ``returned`` are transactions from disconnected blocks, in chain order. They go back
        first (they were there earlier), then the previous pool contents. Anything no longer
        valid on the new tip — double-spent, spending a vanished coinbase, now non-final — is
        dropped. Returns ``(readded, dropped)`` txids.
        """
        old = sorted(self.entries.values(), key=lambda e: e.time_ms)
        self.entries.clear()
        self.spends.clear()
        self.total_bytes = 0
        readded: list[bytes] = []
        dropped: list[bytes] = []
        candidates = [t for t in returned if not t.is_coinbase] + [e.tx for e in old]
        for tx in candidates:
            try:
                self.accept(tx)
            except (ValidationError, MissingDataError):
                dropped.append(tx.txid)
            else:
                readded.append(tx.txid)
        return readded, dropped

    # -- block template --------------------------------------------------------------------

    def select(self, max_bytes: int) -> tuple[list[Transaction], int]:
        """Greedy block template: highest fee rate first, parents always before children."""
        chosen: list[Transaction] = []
        chosen_ids: set[bytes] = set()
        used = 0
        fees = 0
        pending = sorted(self.entries.values(), key=lambda e: (-e.feerate, e.time_ms))
        progress = True
        while progress:
            progress = False
            remaining = []
            for entry in pending:
                if entry.parents <= chosen_ids and used + entry.size <= max_bytes:
                    chosen.append(entry.tx)
                    chosen_ids.add(entry.tx.txid)
                    used += entry.size
                    fees += entry.fee
                    progress = True
                else:
                    remaining.append(entry)
            pending = remaining
        return chosen, fees

    def sorted_entries(self) -> list[MempoolEntry]:
        return sorted(self.entries.values(), key=lambda e: -e.feerate)
