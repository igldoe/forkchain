"""Chain state: block index, active chain, UTXO set and contextual block validation."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from forkchain.block import Block, BlockHeader, check_block, make_genesis
from forkchain.errors import ValidationError
from forkchain.params import ConsensusParams
from forkchain.pow import block_work, retarget
from forkchain.utxo import BlockUndo, OverlayView, UtxoSet
from forkchain.validation import MissingInputsError, ScriptVerifier, check_tx_inputs, is_final

Clock = Callable[[], int]


def wall_clock_ms() -> int:
    return int(time.time() * 1000)


@dataclass(eq=False)
class BlockIndex:
    header: BlockHeader
    height: int
    chainwork: int
    parent: BlockIndex | None

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
        self.genesis = BlockIndex(genesis.header, 0, block_work(genesis.header.bits), None)
        self.index: dict[bytes, BlockIndex] = {genesis.hash: self.genesis}
        self.blocks: dict[bytes, Block] = {genesis.hash: genesis}
        self.undo: dict[bytes, BlockUndo] = {}
        self.active: list[BlockIndex] = [self.genesis]
        self.utxos = UtxoSet()
        self.undo[genesis.hash] = self.utxos.apply_block(genesis, 0)

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

    def _connect(self, block: Block, idx: BlockIndex) -> None:
        """Fully validate ``block`` on top of the current tip and make it the new tip."""
        assert idx.parent is self.tip
        self.validate_block_txs(block, idx.height)
        self.undo[idx.hash] = self.utxos.apply_block(block, idx.height)
        self.active.append(idx)

    def add_block(self, block: Block) -> BlockIndex:
        """Validate and append a block that extends the current tip."""
        if block.hash in self.index:
            return self.index[block.hash]
        check_block(block, self.params)
        parent = self.index.get(block.prev_hash)
        if parent is not self.tip:
            raise ValidationError("bad-prevblk", "block does not extend the tip", ban=False)
        self.check_header_contextual(block.header, parent)
        idx = BlockIndex(
            block.header,
            parent.height + 1,
            parent.chainwork + block_work(block.header.bits),
            parent,
        )
        self._connect(block, idx)
        self.index[idx.hash] = idx
        self.blocks[idx.hash] = block
        return idx
