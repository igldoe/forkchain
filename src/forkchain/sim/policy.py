"""Fault injection for the in-process network: partitions and link latency."""

from __future__ import annotations

import random
from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass
class ChaosPolicy:
    """Implements ``forkchain.p2p.node.LinkPolicy``.

    ``partitions`` is ``None`` for a healthy network, or a list of node-name groups: two
    nodes may talk only when they are in the same group.
    """

    base_latency_ms: float = 0.0
    jitter_ms: float = 0.0
    slow_nodes: dict[str, float] = field(default_factory=dict)  # extra one-way ms
    partitions: list[frozenset[str]] | None = None
    rng: random.Random = field(default_factory=random.Random)

    def allowed(self, a: str, b: str) -> bool:
        if self.partitions is None:
            return True
        return any(a in group and b in group for group in self.partitions)

    def latency(self, a: str, b: str) -> float:
        ms = self.base_latency_ms + self.slow_nodes.get(a, 0.0) + self.slow_nodes.get(b, 0.0)
        if self.jitter_ms:
            ms += self.rng.uniform(0, self.jitter_ms)
        return ms / 1000.0

    def split(self, *groups: Iterable[str]) -> None:
        self.partitions = [frozenset(g) for g in groups]

    def heal(self) -> None:
        self.partitions = None

    def describe(self) -> str:
        if self.partitions is None:
            return "connected"
        return " | ".join(",".join(sorted(g)) for g in self.partitions)
