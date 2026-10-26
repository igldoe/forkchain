"""Chain state: block tree, most-work fork choice, reorgs and the UTXO set of the tip.

Every block we ever saw lives in ``index`` (a tree rooted at genesis). The *active chain*
is the path from genesis to the complete, valid block with the most cumulative work —
not the longest one: a short chain of hard blocks beats a long chain of easy ones.

When a heavier branch shows up, ``_activate_best_chain`` walks back to the fork point,
disconnecting blocks with their undo data, then connects the new branch block by block
with full validation. If a block on the new branch turns out invalid, it and its
descendants are marked invalid and the loop simply re-targets the best remaining branch,
which may be the chain we just left.
"""

from __future__ import annotations

import itertools
import time
from collections import OrderedDict
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from forkchain.block import Block, BlockHeader, check_block, make_genesis
from forkchain.errors import MissingDataError, ValidationError
from forkchain.params import ConsensusParams
from forkchain.pow import block_work, retarget
from forkchain.tx import Transaction
from forkchain.utxo import BlockUndo, OverlayView, UtxoSet
from forkchain.validation import MissingInputsError, ScriptVerifier, check_tx_inputs, is_final

Clock = Callable[[], int]
MAX_ORPHANS = 200
MAX_HEADERS_PER_MSG = 2000

_sequence = itertools.count()


def wall_clock_ms() -> int:
    return int(time.time() * 1000)


@dataclass(eq=False)
class BlockIndex:
    header: BlockHeader
    height: int
    chainwork: int
    parent: BlockIndex | None
    has_data: bool = False
    complete: bool = False  # this block and all ancestors have data
    invalid: bool = False
    seq: int = field(default_factory=lambda: next(_sequence))  # arrival order, breaks ties

    @property
    def hash(self) -> bytes:
        return self.header.hash

    def ancestor(self, height: int) -> BlockIndex:
        if height > self.height or height < 0:
            raise ValueError(f"no ancestor at height {height}")
        node: BlockIndex = self
        while node.height > height:
            assert node.parent is not None
            node = node.parent
        return node


@dataclass
class ChainUpdate:
    """What one ``add_block`` call did to the active chain."""

    connected: list[Block] = field(default_factory=list)
    disconnected: list[Block] = field(default_factory=list)
    invalidated: list[bytes] = field(default_factory=list)
    errors: dict[bytes, ValidationError] = field(default_factory=dict)

    @property
    def reorg_depth(self) -> int:
        """Blocks that left the active chain for good.

        A failed reorg attempt disconnects blocks and then reconnects them; those cancel
        out, so an aborted switch to an invalid branch has depth 0.
        """
        connected = {b.hash for b in self.connected}
        return len({b.hash for b in self.disconnected} - connected)

    def merge(self, other: ChainUpdate) -> None:
        self.connected += other.connected
        self.disconnected += other.disconnected
        self.invalidated += other.invalidated
        self.errors |= other.errors


@dataclass
class AddResult:
    """Outcome of ``Chain.add_block``.

    ``status`` is one of ``active`` (on the main chain now), ``side`` (valid so far, on a
    lighter branch), ``orphan`` (parent unknown), ``duplicate`` or ``invalid``. An invalid
    result still carries ``update``: a failed reorg attempt may have moved the tip back
    and forth, and the mempool must hear about it.
    """

    status: str
    index: BlockIndex | None
    update: ChainUpdate = field(default_factory=ChainUpdate)
    error: ValidationError | None = None

    def check(self) -> AddResult:
        """Raise the validation error, if any; return self for chaining."""
        if self.error is not None:
            raise self.error
        return self


def find_fork(a: BlockIndex, b: BlockIndex) -> BlockIndex:
    """Lowest common ancestor of two block index entries."""
    if a.height > b.height:
        a = a.ancestor(b.height)
    elif b.height > a.height:
        b = b.ancestor(a.height)
    while a is not b:
        assert a.parent is not None
        assert b.parent is not None
        a, b = a.parent, b.parent
    return a


class Chain:
    def __init__(
        self,
        params: ConsensusParams,
        *,
        clock: Clock = wall_clock_ms,
        verifier: ScriptVerifier | None = None,
    ) -> None:
        self.params = params
        self.clock = clock
        self.verifier = verifier
        genesis = make_genesis(params)
        self.genesis = BlockIndex(
            genesis.header, 0, block_work(genesis.header.bits), None, has_data=True, complete=True
        )
        self.index: dict[bytes, BlockIndex] = {genesis.hash: self.genesis}
        self.children: dict[bytes, list[BlockIndex]] = {}
        self.blocks: dict[bytes, Block] = {genesis.hash: genesis}
        self.undo: dict[bytes, BlockUndo] = {}
        self.active: list[BlockIndex] = [self.genesis]
        self.best_header: BlockIndex = self.genesis
        self.orphans: OrderedDict[bytes, Block] = OrderedDict()
        self.tx_index: dict[bytes, list[bytes]] = {}  # txid -> hashes of blocks containing it
        self.utxos = UtxoSet()
        self.undo[genesis.hash] = self.utxos.apply_block(genesis, 0)
        self.tx_index[genesis.txs[0].txid] = [genesis.hash]

    # -- queries ---------------------------------------------------------------------------

    @property
    def tip(self) -> BlockIndex:
        return self.active[-1]

    @property
    def height(self) -> int:
        return self.tip.height

    def contains(self, block_hash: bytes) -> bool:
        """Is the block part of the active chain?"""
        idx = self.index.get(block_hash)
        return idx is not None and idx.height <= self.height and self.active[idx.height] is idx

    def block_at(self, height: int) -> Block:
        return self.blocks[self.active[height].hash]

    def iter_index(self) -> Iterator[BlockIndex]:
        return iter(self.index.values())

    def median_time_past(self, idx: BlockIndex) -> int:
        times: list[int] = []
        node: BlockIndex | None = idx
        while node is not None and len(times) < self.params.median_time_span:
            times.append(node.header.timestamp)
            node = node.parent
        times.sort()
        return times[len(times) // 2]

    def next_bits(self, parent: BlockIndex) -> int:
        """Required ``bits`` for a block whose parent is ``parent``.

        Every ``retarget_interval`` blocks the target is rescaled by how long the previous
        window actually took. The window never includes genesis, whose timestamp is fixed
        in the params and would make the first window look arbitrarily slow.
        """
        height = parent.height + 1
        interval = self.params.retarget_interval
        if height % interval != 0:
            return parent.header.bits
        first = parent.ancestor(max(1, height - interval))
        gaps = parent.height - first.height
        if gaps <= 0:
            return parent.header.bits
        timespan = parent.header.timestamp - first.header.timestamp
        # Normalise to a full window so ``retarget`` can compare against interval * T.
        return retarget(self.params, parent.header.bits, timespan * interval // gaps)

    # -- headers-first sync helpers --------------------------------------------------------

    def locator(self) -> list[bytes]:
        """Block hashes from the tip backwards, dense at first then exponentially sparse."""
        hashes: list[bytes] = []
        step = 1
        height = self.height
        while height > 0:
            hashes.append(self.active[height].hash)
            if len(hashes) >= 10:
                step *= 2
            height -= step
        hashes.append(self.genesis.hash)
        return hashes

    def headers_after(
        self, locator: list[bytes], limit: int = MAX_HEADERS_PER_MSG
    ) -> list[BlockHeader]:
        """Active-chain headers following the first locator hash we have on our chain."""
        start = 0
        for block_hash in locator:
            if self.contains(block_hash):
                start = self.index[block_hash].height
                break
        end = min(self.height, start + limit)
        return [self.active[h].header for h in range(start + 1, end + 1)]

    def blocks_to_download(self, limit: int) -> list[bytes]:
        """Hashes of blocks we know headers for, on the most-work header chain, but lack."""
        if self.best_header.chainwork <= self.tip.chainwork:
            return []
        missing: list[bytes] = []
        node: BlockIndex | None = self.best_header
        while node is not None and not node.complete:
            if not node.has_data:
                missing.append(node.hash)
            node = node.parent
        return missing[::-1][:limit]

    # -- validation ------------------------------------------------------------------------

    def check_header_contextual(self, header: BlockHeader, parent: BlockIndex) -> None:
        expected_bits = self.next_bits(parent)
        if header.bits != expected_bits:
            raise ValidationError("bad-diffbits", f"bits {header.bits:#x} != {expected_bits:#x}")
        if header.timestamp <= self.median_time_past(parent):
            raise ValidationError("time-too-old", "timestamp not after median time past")
        if header.timestamp > self.clock() + self.params.max_future_drift_ms:
            raise ValidationError("time-too-new", "timestamp too far in the future", ban=False)

    def _verify_kwargs(self) -> dict[str, ScriptVerifier]:
        return {"verifier": self.verifier} if self.verifier is not None else {}

    def validate_block_txs(self, block: Block, height: int) -> int:
        """Check every transaction against the current tip's UTXO set; return total fees."""
        view = OverlayView(self.utxos)
        coinbase = block.txs[0]
        if coinbase.coinbase_height() != height:
            raise ValidationError("bad-cb-height", "coinbase does not commit to block height")
        fees = 0
        for tx in block.txs[1:]:
            try:
                fees += check_tx_inputs(tx, view, height, self.params, **self._verify_kwargs())
            except MissingInputsError as exc:
                raise ValidationError("bad-txns-inputs-missingorspent", str(exc)) from exc
            view.apply_tx(tx, height)
        if not is_final(coinbase, height):
            raise ValidationError("bad-txns-nonfinal", "coinbase locktime")
        allowed = self.params.block_reward(height) + fees
        if coinbase.total_out() > allowed:
            raise ValidationError(
                "bad-cb-amount", f"coinbase pays {coinbase.total_out()} > {allowed}"
            )
        return fees

    # -- accepting headers and blocks ------------------------------------------------------

    def add_header(self, header: BlockHeader) -> BlockIndex:
        """Validate a header against its parent and insert it into the block tree."""
        existing = self.index.get(header.hash)
        if existing is not None:
            if existing.invalid:
                raise ValidationError("duplicate-invalid", "header of a known-invalid block")
            return existing
        if not header.check_pow():
            raise ValidationError("high-hash", "proof of work does not meet target")
        parent = self.index.get(header.prev_hash)
        if parent is None:
            raise MissingDataError(f"unknown parent {header.prev_hash.hex()}")
        if parent.invalid:
            raise ValidationError("bad-prevblk", "parent is invalid")
        self.check_header_contextual(header, parent)
        idx = BlockIndex(
            header, parent.height + 1, parent.chainwork + block_work(header.bits), parent
        )
        self.index[idx.hash] = idx
        self.children.setdefault(parent.hash, []).append(idx)
        if idx.chainwork > self.best_header.chainwork:
            self.best_header = idx
        return idx

    def add_block(self, block: Block) -> AddResult:
        """Accept a block from anywhere (miner, peer) and update the active chain.

        Raises ``ValidationError`` for invalid blocks. A block whose parent is unknown is
        kept as an orphan (after its PoW is checked, so orphans are not free to forge) and
        connected automatically once the parent arrives.
        """
        existing = self.index.get(block.hash)
        if existing is not None and existing.has_data:
            return AddResult("duplicate", existing)
        if existing is not None and existing.invalid:
            raise ValidationError("duplicate-invalid", "block is known to be invalid")
        check_block(block, self.params)
        if block.prev_hash not in self.index:
            self._store_orphan(block)
            return AddResult("orphan", None)

        idx = self._accept(block)
        # Orphans waiting on this block (and on their own children) can now be attached.
        pending = [idx.hash]
        while pending:
            parent_hash = pending.pop()
            for orphan in [o for o in self.orphans.values() if o.prev_hash == parent_hash]:
                del self.orphans[orphan.hash]
                try:
                    pending.append(self._accept(orphan).hash)
                except ValidationError:
                    continue
        update = self._activate_best_chain()
        if idx.invalid:
            error = update.errors.get(idx.hash) or ValidationError(
                "bad-prevblk", "block descends from an invalid block"
            )
            return AddResult("invalid", idx, update, error)
        return AddResult("active" if self.contains(idx.hash) else "side", idx, update)

    def _store_orphan(self, block: Block) -> None:
        self.orphans[block.hash] = block
        while len(self.orphans) > MAX_ORPHANS:
            self.orphans.popitem(last=False)

    def _accept(self, block: Block) -> BlockIndex:
        idx = self.add_header(block.header)
        self.blocks[idx.hash] = block
        idx.has_data = True
        for tx in block.txs:
            self.tx_index.setdefault(tx.txid, []).append(idx.hash)
        # Propagate "complete" down to descendants that arrived before this block did
        # (happens in headers-first sync when block bodies come out of order).
        stack = [idx]
        while stack:
            node = stack.pop()
            if (
                node.has_data
                and not node.complete
                and node.parent is not None
                and node.parent.complete
            ):
                node.complete = True
                stack.extend(self.children.get(node.hash, ()))
        return idx

    # -- fork choice -----------------------------------------------------------------------

    def _best_candidate(self) -> BlockIndex:
        best = self.tip
        for idx in self.index.values():
            if not idx.complete or idx.invalid:
                continue
            if idx.chainwork > best.chainwork or (
                idx.chainwork == best.chainwork and idx.seq < best.seq and best is not self.tip
            ):
                best = idx
        return best

    def _mark_invalid(self, idx: BlockIndex) -> list[bytes]:
        marked: list[bytes] = []
        stack = [idx]
        while stack:
            node = stack.pop()
            if not node.invalid:
                node.invalid = True
                marked.append(node.hash)
                stack.extend(self.children.get(node.hash, ()))
        if self.best_header.invalid:
            self.best_header = max(
                (i for i in self.index.values() if not i.invalid), key=lambda i: i.chainwork
            )
        return marked

    def _disconnect_tip(self) -> Block:
        idx = self.active.pop()
        block = self.blocks[idx.hash]
        self.utxos.undo_block(block, self.undo.pop(idx.hash))
        return block

    def _connect(self, block: Block, idx: BlockIndex) -> None:
        """Fully validate ``block`` on top of the current tip and make it the new tip."""
        assert idx.parent is self.tip
        self.validate_block_txs(block, idx.height)
        self.undo[idx.hash] = self.utxos.apply_block(block, idx.height)
        self.active.append(idx)

    def _activate_best_chain(self) -> ChainUpdate:
        update = ChainUpdate()
        while True:
            best = self._best_candidate()
            if best is self.tip or best.chainwork <= self.tip.chainwork:
                return update
            fork = find_fork(self.tip, best)
            while self.tip is not fork:
                update.disconnected.append(self._disconnect_tip())
            path: list[BlockIndex] = []
            node: BlockIndex | None = best
            while node is not fork:
                assert node is not None
                path.append(node)
                node = node.parent
            for idx in reversed(path):
                block = self.blocks[idx.hash]
                try:
                    self._connect(block, idx)
                except ValidationError as exc:
                    update.errors[idx.hash] = exc
                    update.invalidated += self._mark_invalid(idx)
                    break
                update.connected.append(block)

    def find_tx(self, txid: bytes) -> tuple[Transaction, BlockIndex] | None:
        """Locate a transaction, preferring its active-chain block over stale ones."""
        hashes = self.tx_index.get(txid, [])
        for block_hash in sorted(hashes, key=lambda h: not self.contains(h)):
            block = self.blocks[block_hash]
            for tx in block.txs:
                if tx.txid == txid:
                    return tx, self.index[block_hash]
        return None

    # -- reporting -------------------------------------------------------------------------

    def reverted_transactions(self, update: ChainUpdate) -> list[Transaction]:
        """Non-coinbase txs that were in disconnected blocks and are not on the new chain."""
        confirmed = {tx.txid for b in update.connected if self.contains(b.hash) for tx in b.txs}
        seen: set[bytes] = set()
        result: list[Transaction] = []
        for block in reversed(update.disconnected):  # oldest first
            for tx in block.txs[1:]:
                if tx.txid not in confirmed and tx.txid not in seen:
                    seen.add(tx.txid)
                    result.append(tx)
        return result
