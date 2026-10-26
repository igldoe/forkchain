"""Consensus parameters.

All rules that must be identical on every node live here, so tests and the simulator can
spin up chains with tiny difficulty and fast halvings without touching consensus code.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

COIN = 100_000_000  # base units per coin, like satoshis


@dataclass(frozen=True)
class ConsensusParams:
    name: str = "main"
    # Easiest allowed target (compact form). 0x2000ffff ~ 1 in 256 hashes succeeds.
    pow_limit_bits: int = 0x2000FFFF
    genesis_bits: int = 0x1F00FFFF
    genesis_timestamp_ms: int = 1_767_225_600_000  # 2026-01-01T00:00:00Z
    target_block_time_ms: int = 10_000
    retarget_interval: int = 20
    max_retarget_factor: int = 4
    initial_reward: int = 50 * COIN
    halving_interval: int = 210
    coinbase_maturity: int = 10
    max_block_size: int = 1_000_000
    max_tx_size: int = 100_000
    max_future_drift_ms: int = 2 * 60 * 60 * 1000
    median_time_span: int = 11

    def block_reward(self, height: int) -> int:
        halvings = height // self.halving_interval
        if halvings >= 64:
            return 0
        return self.initial_reward >> halvings

    def with_overrides(self, **changes: object) -> ConsensusParams:
        return replace(self, **changes)  # type: ignore[arg-type]


MAIN = ConsensusParams()

# Trivial difficulty for unit tests: almost every nonce works, coinbase spendable at once.
REGTEST = ConsensusParams(
    name="regtest",
    pow_limit_bits=0x2100FFFF,
    genesis_bits=0x2100FFFF,
    target_block_time_ms=1_000,
    retarget_interval=10,
    halving_interval=50,
    coinbase_maturity=1,
)
