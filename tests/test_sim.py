"""Chaos simulator, including the 5-node partition convergence test."""

from __future__ import annotations

import json
import random

import pytest

from forkchain.cli import main, parse_slow, parse_window
from forkchain.sim.policy import ChaosPolicy
from forkchain.sim.runner import SimConfig, run_simulation

pytestmark = pytest.mark.slow


def test_policy_partition_and_latency() -> None:
    policy = ChaosPolicy(base_latency_ms=10, jitter_ms=0, slow_nodes={"c": 90})
    assert policy.allowed("a", "c")
    policy.split(["a", "b"], ["c"])
    assert policy.allowed("a", "b")
    assert not policy.allowed("a", "c")
    assert policy.describe() == "a,b | c"
    policy.heal()
    assert policy.describe() == "connected"
    assert policy.latency("a", "b") == pytest.approx(0.010)
    assert policy.latency("a", "c") == pytest.approx(0.100)
    jittery = ChaosPolicy(jitter_ms=5, rng=random.Random(0))
    assert 0 <= jittery.latency("a", "b") <= 0.005


async def test_five_nodes_converge_after_partition() -> None:
    config = SimConfig(
        nodes=5,
        duration=8.0,
        block_time=0.3,
        partition=(1.5, 5.0),
        latency_ms=10,
        jitter_ms=10,
        tx_rate=4.0,
        coinbase_maturity=1,
        seed=7,
    )
    report = await run_simulation(config)
    assert report.converged
    assert len({n.tip for n in report.nodes}) == 1
    assert report.convergence_after_heal is not None
    assert report.convergence_after_heal < 5.0
    # Both halves kept mining while split, so the lighter half must have reorged.
    assert report.stale_blocks >= 1
    assert report.max_reorg_depth >= 1
    assert report.forks >= 1
    assert "partition window" in report.render()


async def test_majority_attacker_double_spends() -> None:
    config = SimConfig(
        nodes=4,
        duration=14.0,
        block_time=0.3,
        attack=True,
        attack_start=2.5,
        latency_ms=5,
        jitter_ms=5,
        tx_rate=0,
        coinbase_maturity=1,
        seed=3,
    )
    report = await run_simulation(config)
    assert report.attack is not None
    assert report.attack.hashrate_share > 0.5
    assert report.attack.confirmations_before_reorg >= config.attack_confirmations
    assert report.attack.success
    assert report.txs_lost >= 1
    assert report.converged
    assert "DOUBLE SPEND SUCCEEDED" in report.render()


def test_cli_sim_json(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(
        ["sim", "--nodes", "3", "--duration", "2", "--block-time", "0.3", "--partition", "none",
         "--latency", "0", "--jitter", "0", "--json"]
    )  # fmt: skip
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["converged"] is True
    assert len(report["nodes"]) == 3


def test_cli_sim_argument_parsers() -> None:
    import argparse

    assert parse_window("3:9") == (3.0, 9.0)
    assert parse_window("none") is None
    assert parse_slow("n2:300") == ("n2", 300.0)
    for bad in ("9:3", "x:y", "5"):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_window(bad)
    with pytest.raises(argparse.ArgumentTypeError):
        parse_slow("n2")
