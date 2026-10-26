from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

import pytest

from forkchain.block import Block
from forkchain.chain import Chain
from forkchain.keys import PrivateKey
from forkchain.miner import mine_block
from forkchain.params import REGTEST, ConsensusParams
from forkchain.tx import Transaction
from forkchain.wallet import Wallet


@dataclass
class FakeClock:
    now: int = REGTEST.genesis_timestamp_ms

    def __call__(self) -> int:
        return self.now

    def tick(self, ms: int) -> None:
        self.now += ms


def wallet(seed: str) -> Wallet:
    return Wallet(PrivateKey.from_seed(seed))


class ChainHarness:
    """A chain plus a deterministic clock and helpers to mine on it."""

    def __init__(self, params: ConsensusParams = REGTEST) -> None:
        self.clock = FakeClock(params.genesis_timestamp_ms)
        self.chain = Chain(params, clock=self.clock)
        self.params = params

    def mine(
        self,
        script_pubkey: bytes,
        txs: Sequence[Transaction] = (),
        *,
        fees: int = 0,
        step_ms: int | None = None,
    ) -> Block:
        self.clock.tick(step_ms if step_ms is not None else self.params.target_block_time_ms)
        block = mine_block(self.chain, script_pubkey, txs, fees=fees)
        self.chain.add_block(block).check()
        return block

    def mine_many(self, n: int, script_pubkey: bytes) -> list[Block]:
        return [self.mine(script_pubkey) for _ in range(n)]


@pytest.fixture
def harness() -> ChainHarness:
    return ChainHarness()


@pytest.fixture
def alice() -> Wallet:
    return wallet("alice")


@pytest.fixture
def bob() -> Wallet:
    return wallet("bob")
