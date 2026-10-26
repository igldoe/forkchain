"""Chaos simulator: N real nodes over localhost TCP in one process, plus injected faults.

Nodes run the exact production code (``Node``); faults are injected through the node's
``LinkPolicy`` hook, so a partition really tears down TCP connections and the healed
network must find its way back through peer discovery and headers-first sync.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from forkchain.keys import PrivateKey
from forkchain.miner import coinbase_tag
from forkchain.p2p.node import Event, Node, NodeConfig
from forkchain.params import MAIN, ConsensusParams
from forkchain.pow import block_work, difficulty, target_to_bits
from forkchain.sim.policy import ChaosPolicy
from forkchain.sim.report import AttackReport, NodeReport, SimReport
from forkchain.tx import OutPoint, TxOut
from forkchain.utxo import Coin
from forkchain.wallet import Wallet


@dataclass
class SimConfig:
    nodes: int = 5
    duration: float = 40.0  # seconds of mining before the network is asked to settle
    block_time: float = 1.0  # target seconds per block for the whole network
    hashrate: float = 4_000.0  # hashes/second of an ordinary node
    whales: int = 0  # number of nodes with boosted hashrate (the first ones)
    whale_factor: float = 4.0
    latency_ms: float = 40.0
    jitter_ms: float = 30.0
    slow: dict[str, float] = field(default_factory=dict)
    partition: tuple[float, float] | None = (10.0, 25.0)  # (start, end) in seconds
    groups: list[list[str]] | None = None  # default: first half vs second half
    attack: bool = False  # 51% double spend by node n0 (overrides ``partition``)
    attack_start: float = 10.0
    attack_confirmations: int = 2
    tx_rate: float = 2.0  # random payments per second
    settle_timeout: float = 30.0
    retarget_interval: int = 10
    coinbase_maturity: int = 3
    seed: int = 1

    def names(self) -> list[str]:
        return [f"n{i}" for i in range(self.nodes)]

    def node_hashrate(self, index: int) -> float:
        if self.attack and index == 0:
            # Enough to out-mine everybody else combined, with some margin.
            return max(self.hashrate * self.whale_factor, 1.6 * self.hashrate * (self.nodes - 1))
        return self.hashrate * (self.whale_factor if index < self.whales else 1.0)

    def params(self) -> ConsensusParams:
        total = sum(self.node_hashrate(i) for i in range(self.nodes))
        expected_hashes = max(2, int(total * self.block_time))
        return MAIN.with_overrides(
            name="sim",
            pow_limit_bits=0x2100FFFF,
            genesis_bits=target_to_bits((1 << 256) // expected_hashes),
            genesis_timestamp_ms=int(time.time() * 1000) - 60_000,
            target_block_time_ms=int(self.block_time * 1000),
            retarget_interval=self.retarget_interval,
            coinbase_maturity=self.coinbase_maturity,
            halving_interval=1_000,
        )


class Simulation:
    def __init__(self, config: SimConfig, *, log: Callable[[str], None] | None = None) -> None:
        self.cfg = config
        self.params = config.params()
        self.rng = random.Random(config.seed)
        self.policy = ChaosPolicy(
            base_latency_ms=config.latency_ms,
            jitter_ms=config.jitter_ms,
            slow_nodes=dict(config.slow),
            rng=random.Random(config.seed + 1),
        )
        self.wallets = {n: Wallet(PrivateKey.from_seed(f"sim/{n}")) for n in config.names()}
        self.nodes: list[Node] = []
        self.timeline: list[tuple[float, str]] = []
        self.reorg_events: list[Event] = []
        self._log = log or (lambda _msg: None)
        self._t0 = 0.0
        self._heal_at: float | None = None
        self.convergence_after_heal: float | None = None
        self.attack_report: AttackReport | None = None
        self.txs_sent = 0
        self._running = False

    # -- helpers ---------------------------------------------------------------------------

    @property
    def now(self) -> float:
        return time.monotonic() - self._t0

    def note(self, text: str) -> None:
        self.timeline.append((round(self.now, 2), text))
        self._log(f"[t={self.now:6.2f}s] {text}")

    def node(self, name: str) -> Node:
        return next(n for n in self.nodes if n.name == name)

    def converged(self) -> bool:
        return len({n.chain.tip.hash for n in self.nodes}) == 1

    def _on_event(self, event: Event) -> None:
        if event["type"] == "reorg":
            self.reorg_events.append(event | {"t": round(self.now, 2)})
            if event["depth"] >= 2:
                self.note(
                    f"{event['node']}: reorg depth {event['depth']}, "
                    f"{len(event['reverted'])} tx reverted"
                )

    # -- lifecycle -------------------------------------------------------------------------

    async def start(self) -> None:
        self._t0 = time.monotonic()
        for i, name in enumerate(self.cfg.names()):
            config = NodeConfig(
                name=name,
                miner_script=self.wallets[name].script_pubkey,
                hashrate=self.cfg.node_hashrate(i),
                maintenance_interval=0.25,
                template_refresh=0.5,
                peer_timeout=30.0,
                target_outbound=3,
            )
            node = Node(config, self.params, policy=self.policy)
            node.listeners.append(self._on_event)
            await node.start()
            self.nodes.append(node)
        # Ring plus a chord: every node dials its two successors.
        for i, node in enumerate(self.nodes):
            for step in (1, 2):
                other = self.nodes[(i + step) % len(self.nodes)]
                if other is not node:
                    node.known_addrs.add(other.listen_addr)
            node.reconnect_known()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            wanted = min(2, len(self.nodes) - 1)
            if all(sum(p.handshake_done for p in n.peers.values()) >= wanted for n in self.nodes):
                break
            await asyncio.sleep(0.05)
        self.note(f"{len(self.nodes)} nodes up, mining started")
        for node in self.nodes:
            node.mining = True

    async def stop(self) -> None:
        for node in self.nodes:
            await node.stop()

    async def run(self) -> SimReport:
        await self.start()
        background = self.start_background()
        try:
            if self.cfg.attack:
                await self._run_attack()
            elif self.cfg.partition is not None:
                await self._run_partition(*self.cfg.partition)
            remaining = self.cfg.duration - self.now
            if remaining > 0:
                await asyncio.sleep(remaining)
            self._running = False
            settle = await self._settle()
            return self._report(settle)
        finally:
            self._running = False
            for task in background:
                task.cancel()
            await self.stop()

    def start_background(self) -> list[asyncio.Task[None]]:
        """Random payments and the convergence sampler (also used by the explorer demo)."""
        self._running = True
        return [
            asyncio.create_task(self._tx_generator()),
            asyncio.create_task(self._sampler()),
        ]

    def partition(self, groups: list[list[str]] | None = None) -> None:
        names = self.cfg.names()
        groups = groups or self.cfg.groups or [names[: len(names) // 2], names[len(names) // 2 :]]
        self.policy.split(*groups)
        self._heal_at = None
        self.convergence_after_heal = None
        for node in self.nodes:
            node.apply_policy()
        self.note(f"partition: {self.policy.describe()}")

    async def _run_partition(self, start: float, end: float) -> None:
        await asyncio.sleep(max(0.0, start - self.now))
        self.partition()
        await asyncio.sleep(max(0.0, end - self.now))
        self.heal()

    def heal(self) -> None:
        self.policy.heal()
        self._heal_at = self.now
        for node in self.nodes:
            node.reconnect_known()
        self.note("network healed")

    async def _settle(self) -> float | None:
        """Stop mining and wait until every node agrees on the tip.

        Two tips with exactly equal work are a stable state: first-seen keeps every node
        on its own block. Real networks break such ties with the next block, so if nodes
        still disagree after a short while, the strongest node mines until they agree.
        """
        for node in self.nodes:
            node.mining = False
        if self.policy.partitions is not None:
            self.heal()
        tie_breaker = max(self.nodes, key=lambda n: n.hashrate or 0.0)
        started = self.now
        deadline = time.monotonic() + self.cfg.settle_timeout
        try:
            while time.monotonic() < deadline:
                if self.converged():
                    elapsed = self.now - started
                    tie_breaker.mining = False
                    await asyncio.sleep(0.5)  # a block found just before may still be in flight
                    if self.converged():
                        self.note(f"all nodes agree on height {self.nodes[0].chain.height}")
                        return elapsed
                    continue
                if self.now - started > 2.0 and not tie_breaker.mining:
                    tie_breaker.mining = True
                    self.note(f"equal-work tips persist; {tie_breaker.name} mines a tie-breaker")
                await asyncio.sleep(0.05)
        finally:
            tie_breaker.mining = False
        self.note("network did NOT converge before the settle timeout")
        return None

    # -- background activity ---------------------------------------------------------------

    async def _sampler(self) -> None:
        while True:
            await asyncio.sleep(0.05)
            if (
                self._heal_at is not None
                and self.convergence_after_heal is None
                and self.converged()
            ):
                self.convergence_after_heal = self.now - self._heal_at
                self.note(f"converged {self.convergence_after_heal:.2f}s after heal")

    def _spendable(self, node: Node, wallet: Wallet) -> list[tuple[OutPoint, Coin]]:
        chain = node.chain
        coins: list[tuple[OutPoint, Coin]] = []
        for outpoint, coin in chain.utxos.coins_for_script(wallet.script_pubkey):
            age = chain.height + 1 - coin.height
            mature = not coin.is_coinbase or age >= self.params.coinbase_maturity
            if mature and outpoint not in node.mempool.spends:
                coins.append((outpoint, coin))
        return coins

    async def _tx_generator(self) -> None:
        if self.cfg.tx_rate <= 0:
            return
        while True:
            await asyncio.sleep(self.rng.expovariate(self.cfg.tx_rate))
            if not self._running:
                continue
            node = self.rng.choice(self.nodes)
            payer = self.wallets[node.name]
            coins = self._spendable(node, payer)
            if not coins:
                continue
            coin = self.rng.choice(coins)
            payee = self.wallets[self.rng.choice([n for n in self.wallets if n != node.name])]
            amount = max(1, coin[1].output.value // self.rng.randint(5, 50))
            try:
                tx = payer.build_payment([coin], [TxOut(amount, payee.script_pubkey)], fee=0)
                fee = (tx.size + 10) * self.rng.randint(1, 20)
                tx = payer.build_payment([coin], [TxOut(amount, payee.script_pubkey)], fee=fee)
                node.submit_tx(tx)
                self.txs_sent += 1
            except Exception:  # coin raced away, pool policy, ...: random traffic may fail
                continue

    # -- 51% double spend ------------------------------------------------------------------

    async def _run_attack(self) -> None:
        attacker, honest = self.nodes[0], self.nodes[1:]
        merchant_name = self.nodes[-1].name
        await asyncio.sleep(max(0.0, self.cfg.attack_start - self.now))
        wallet = self.wallets[attacker.name]
        coins: list[tuple[OutPoint, Coin]] = []
        while not coins:
            coins = self._spendable(attacker, wallet)
            if not coins:
                await asyncio.sleep(0.2)
        outpoint, coin = max(coins, key=lambda c: c[1].output.value)
        value = coin.output.value
        merchant = self.wallets[merchant_name]
        spend = [(outpoint, coin)]
        pay_merchant = wallet.build_payment(
            spend, [TxOut(value // 2, merchant.script_pubkey)], 5_000
        )
        pay_self = wallet.build_payment(spend, [TxOut(value // 2, wallet.script_pubkey)], 9_000)

        self.policy.split([attacker.name], [n.name for n in honest])
        for node in self.nodes:
            node.apply_policy()
        fork_height = attacker.chain.height
        self.note(f"attack: {attacker.name} goes dark at height {fork_height} and mines privately")
        honest[0].submit_tx(pay_merchant)
        attacker.submit_tx(pay_self)
        self.note(
            f"attack: {attacker.name} pays merchant {merchant_name} "
            f"{value // 2} units (tx {pay_merchant.txid.hex()[:12]})"
        )

        watcher = honest[-1]
        max_conf = 0
        deadline = self.cfg.duration - 3.0
        while self.now < deadline:
            await asyncio.sleep(0.1)
            found = watcher.chain.find_tx(pay_merchant.txid)
            conf = 0
            if found and watcher.chain.contains(found[1].hash):
                conf = watcher.chain.height - found[1].height + 1
            max_conf = max(max_conf, conf)
            # Release only with a margin of ~2 blocks of work: with a one-block lead, an
            # honest block in flight turns it into an equal-work tie the attacker may lose.
            lead = attacker.chain.tip.chainwork - max(n.chain.tip.chainwork for n in honest)
            ahead = lead >= 2 * block_work(attacker.chain.tip.header.bits)
            if max_conf >= self.cfg.attack_confirmations and ahead and conf > 0:
                break
        private_blocks = attacker.chain.height - fork_height
        self.note(
            f"attack: merchant saw {max_conf} confirmation(s); releasing private chain "
            f"({private_blocks} blocks)"
        )
        self.heal()
        for _ in range(100):  # up to 5 s for the merchant to adopt the released chain
            if watcher.chain.tip.hash == attacker.chain.tip.hash:
                break
            await asyncio.sleep(0.05)
        final = watcher.chain.find_tx(pay_merchant.txid)
        merchant_paid = final is not None and watcher.chain.contains(final[1].hash)
        self_paid_tx = watcher.chain.find_tx(pay_self.txid)
        self_paid = self_paid_tx is not None and watcher.chain.contains(self_paid_tx[1].hash)
        self.attack_report = AttackReport(
            attacker=attacker.name,
            merchant=merchant_name,
            hashrate_share=self.cfg.node_hashrate(0)
            / sum(self.cfg.node_hashrate(i) for i in range(self.cfg.nodes)),
            merchant_txid=pay_merchant.txid.hex(),
            double_spend_txid=pay_self.txid.hex(),
            confirmations_before_reorg=max_conf,
            private_blocks=private_blocks,
            success=self_paid and not merchant_paid,
        )
        self.note(
            "attack: " + ("DOUBLE SPEND SUCCEEDED" if self.attack_report.success else "failed")
        )

    # -- report ----------------------------------------------------------------------------

    def _report(self, settle_seconds: float | None) -> SimReport:
        reference = self.nodes[0].chain
        final_hashes = {idx.hash for idx in reference.active}
        union: dict[bytes, tuple[bytes, str]] = {}
        for node in self.nodes:
            for idx in node.chain.iter_index():
                block = node.chain.blocks.get(idx.hash)
                if block is not None and idx.height > 0:
                    union[idx.hash] = (idx.header.prev_hash, coinbase_tag(block))
        children: dict[bytes, int] = {}
        for parent, _ in union.values():
            children[parent] = children.get(parent, 0) + 1
        mined_in_final: dict[str, int] = {}
        for block_hash, (_, miner) in union.items():
            if block_hash in final_hashes:
                mined_in_final[miner] = mined_in_final.get(miner, 0) + 1

        reverted = {t for e in self.reorg_events for t in e["reverted"]}
        lost = set()
        for txid_hex in reverted:
            txid = bytes.fromhex(txid_hex)
            found = reference.find_tx(txid)
            on_chain = found is not None and reference.contains(found[1].hash)
            if not on_chain and not any(txid in n.mempool for n in self.nodes):
                lost.add(txid_hex)

        total_rate = sum(self.cfg.node_hashrate(i) for i in range(self.cfg.nodes))
        node_reports = [
            NodeReport(
                name=n.name,
                hashrate=self.cfg.node_hashrate(i),
                share=self.cfg.node_hashrate(i) / total_rate,
                mined=n.stats.blocks_mined,
                in_final_chain=mined_in_final.get(n.name, 0),
                reorgs=n.stats.reorgs,
                max_reorg_depth=n.stats.max_reorg_depth,
                bans=n.stats.bans,
                height=n.chain.height,
                tip=n.chain.tip.hash.hex(),
            )
            for i, n in enumerate(self.nodes)
        ]
        depths = [e["depth"] for e in self.reorg_events]
        partition = None
        if self.cfg.partition is not None and not self.cfg.attack:
            partition = self.cfg.partition
        return SimReport(
            nodes=node_reports,
            duration=round(self.now, 2),
            target_block_time=self.cfg.block_time,
            final_height=reference.height,
            final_tip=reference.tip.hash.hex(),
            converged=self.converged(),
            total_blocks=len(union),
            stale_blocks=len(union) - (len(final_hashes) - 1),
            forks=sum(1 for c in children.values() if c > 1),
            reorgs=len(depths),
            max_reorg_depth=max(depths, default=0),
            txs_sent=self.txs_sent,
            txs_confirmed=sum(
                len(reference.block_at(h).txs) - 1 for h in range(1, reference.height + 1)
            ),
            txs_reverted=len(reverted),
            txs_lost=len(lost),
            partition=partition,
            convergence_after_heal=self.convergence_after_heal,
            settle_time=settle_seconds,
            difficulty_start=difficulty(self.params.genesis_bits, self.params),
            difficulty_end=difficulty(reference.tip.header.bits, self.params),
            attack=self.attack_report,
            timeline=self.timeline,
        )


async def run_simulation(config: SimConfig, log: Callable[[str], None] | None = None) -> SimReport:
    return await Simulation(config, log=log).run()
