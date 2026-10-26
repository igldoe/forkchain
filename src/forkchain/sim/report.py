"""Simulation report: data classes plus a plain-text rendering."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class NodeReport:
    name: str
    hashrate: float
    share: float
    mined: int
    in_final_chain: int
    reorgs: int
    max_reorg_depth: int
    bans: int
    height: int
    tip: str


@dataclass
class AttackReport:
    attacker: str
    merchant: str
    hashrate_share: float
    merchant_txid: str
    double_spend_txid: str
    confirmations_before_reorg: int
    private_blocks: int
    success: bool


@dataclass
class SimReport:
    nodes: list[NodeReport]
    duration: float
    target_block_time: float
    final_height: int
    final_tip: str
    converged: bool
    total_blocks: int
    stale_blocks: int
    forks: int
    reorgs: int
    max_reorg_depth: int
    txs_sent: int
    txs_confirmed: int
    txs_reverted: int
    txs_lost: int
    partition: tuple[float, float] | None
    convergence_after_heal: float | None
    settle_time: float | None
    difficulty_start: float
    difficulty_end: float
    attack: AttackReport | None = None
    timeline: list[tuple[float, str]] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    def render(self) -> str:
        def secs(value: float | None) -> str:
            return f"{value:.2f}s" if value is not None else "n/a"

        rule = "─" * 66
        lines = [
            rule,
            " forkchain chaos simulation report",
            rule,
            f" nodes                     {len(self.nodes)}",
            f" wall time                 {self.duration:.1f}s",
            f" target block time         {self.target_block_time}s",
            f" final height / tip        {self.final_height} / {self.final_tip[:16]}…",
            f" converged                 {'yes' if self.converged else 'NO'}",
            "",
            f" blocks mined (all nodes)  {self.total_blocks}",
            f" stale (orphaned) blocks   {self.stale_blocks}",
            f" forks (fork points)       {self.forks}",
            f" reorgs (all nodes)        {self.reorgs}",
            f" deepest reorg             {self.max_reorg_depth} blocks",
            "",
            f" txs sent / confirmed      {self.txs_sent} / {self.txs_confirmed}",
            f" txs reverted by reorgs    {self.txs_reverted}",
            f"   ...lost (double-spent)  {self.txs_lost}",
            "",
        ]
        if self.partition is not None:
            start, end = self.partition
            lines.append(f" partition window          {start:.1f}s → {end:.1f}s")
        if self.partition is not None or self.attack is not None:
            lines.append(f" convergence after heal    {secs(self.convergence_after_heal)}")
        lines.append(f" settle after mining stop  {secs(self.settle_time)}")
        lines.append(
            f" difficulty                {self.difficulty_start:,.0f} → {self.difficulty_end:,.0f}"
        )
        if self.attack is not None:
            a = self.attack
            lines += [
                "",
                f" 51% attack by {a.attacker} ({a.hashrate_share:.0%} of hashrate) on {a.merchant}",
                f"   merchant confirmations  {a.confirmations_before_reorg}",
                f"   private chain length    {a.private_blocks} blocks",
                "   result                  "
                + ("DOUBLE SPEND SUCCEEDED" if a.success else "attack failed"),
            ]
        lines += [
            "",
            " node  hashrate  share  mined  in-chain  reorgs  max-depth  bans",
        ]
        for n in self.nodes:
            lines.append(
                f" {n.name:<4} {n.hashrate:>9,.0f} {n.share:>6.0%} {n.mined:>6}"
                f" {n.in_final_chain:>9} {n.reorgs:>7} {n.max_reorg_depth:>10} {n.bans:>5}"
            )
        if self.timeline:
            lines += ["", " timeline"]
            lines += [f"   {t:7.2f}s  {text}" for t, text in self.timeline]
        lines.append(rule)
        return "\n".join(lines)
