"""NodeAPI through the JSON-RPC server, plus the CLI commands that use it."""

from __future__ import annotations

import asyncio
import stat
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from forkchain.api import NodeAPI
from forkchain.cli import build_parser, format_coins, main, parse_addr, parse_coins
from forkchain.p2p.node import Node
from forkchain.params import COIN
from forkchain.rpc import RpcClient, RpcError, RpcServer
from forkchain.tx import TxOut
from forkchain.wallet import Wallet

from .conftest import wallet
from .netutil import mine_local, start_node

pytestmark = pytest.mark.slow


@dataclass
class Env:
    node: Node
    rpc: RpcServer
    client: RpcClient
    alice: Wallet

    @property
    def url(self) -> str:
        return f"127.0.0.1:{self.rpc.port}"


@pytest.fixture
async def env() -> AsyncIterator[Env]:
    node = await start_node("api")
    alice = wallet("alice")
    mine_local(node, 3, alice.script_pubkey)
    rpc = RpcServer(NodeAPI(node))
    await rpc.start()
    client = RpcClient("127.0.0.1", rpc.port)
    yield Env(node, rpc, client, alice)
    await client.close()
    await rpc.stop()
    await node.stop()


async def test_info_block_and_tree(env: Env) -> None:
    info = await env.client.call("info")
    assert info["height"] == 3
    assert info["name"] == "api"
    by_height = await env.client.call("block", ref="2")
    by_hash = await env.client.call("block", ref=by_height["hash"])
    assert by_hash == by_height
    assert by_height["status"] == "active"
    assert by_height["confirmations"] == 2
    tree = await env.client.call("tree", depth=10)
    assert [b["height"] for b in tree["blocks"]] == [0, 1, 2, 3]
    history = await env.client.call("difficulty_history")
    assert len(history) == 3


async def test_utxos_send_and_mempool(env: Env) -> None:
    bob = wallet("bob")
    utxos = await env.client.call("utxos", address=env.alice.address)
    assert utxos["spendable"] == 3 * 50 * COIN
    from forkchain.cli import build_send, spendable_coins

    tx = build_send(env.alice, spendable_coins(utxos), bob.address, COIN, fee_rate=2)
    sent = await env.client.call("send_raw_tx", hex_tx=tx.serialize().hex())
    assert sent["txid"] == tx.txid.hex()
    pool = await env.client.call("mempool")
    assert pool["count"] == 1
    after = await env.client.call("utxos", address=env.alice.address)
    assert any(c["spent_in_mempool"] for c in after["coins"])
    assert after["unconfirmed_incoming"] > 0  # change output
    detail = await env.client.call("tx", txid=tx.txid.hex())
    assert detail["status"] == "mempool"
    assert detail["fee"] == sent["fee"]
    assert detail["outputs"][0]["address"] == bob.address
    with pytest.raises(RpcError, match="rejected"):
        await env.client.call("send_raw_tx", hex_tx=tx.serialize().hex())


async def test_merkle_proof_and_script_trace(env: Env) -> None:
    bob = wallet("bob")
    coins = env.node.chain.utxos.coins_for_script(env.alice.script_pubkey)
    txs = [env.alice.build_payment([c], [TxOut(COIN, bob.script_pubkey)], fee=500) for c in coins]
    for tx in txs:
        env.node.submit_tx(tx)
    mine_local(env.node, 1, env.alice.script_pubkey)
    proof = await env.client.call("merkle_proof", txid=txs[1].txid.hex())
    assert proof["valid"] is True
    assert proof["leaves"] == 4
    assert proof["root"] == proof["computed_root"]
    trace = await env.client.call("script_trace", txid=txs[1].txid.hex(), index=0)
    assert trace["valid"] is True
    assert trace["type"] == "p2pkh"
    assert [s["op"] for s in trace["steps"]][-1] == "CHECKSIG"
    found = await env.client.call("search", query=txs[1].txid.hex())
    assert found["kind"] == "tx"
    assert found["result"]["status"] == "active"


async def test_search_variants_and_errors(env: Env) -> None:
    assert (await env.client.call("search", query="1"))["kind"] == "block"
    assert (await env.client.call("search", query=env.alice.address))["kind"] == "address"
    tip = env.node.chain.tip.hash.hex()
    assert (await env.client.call("search", query=tip))["kind"] == "block"
    with pytest.raises(RpcError, match="nothing found"):
        await env.client.call("search", query="ab" * 32)
    with pytest.raises(RpcError, match="unknown method"):
        await env.client.call("shutdown")
    with pytest.raises(RpcError, match="hex"):
        await env.client.call("block", ref="zz")
    with pytest.raises(RpcError, match="beyond tip"):
        await env.client.call("block", ref="99")
    with pytest.raises(RpcError, match="checksum"):
        await env.client.call("utxos", address="fc" + "00" * 24)
    with pytest.raises(RpcError, match="coinbase"):
        await env.client.call("script_trace", txid=env.node.chain.block_at(1).txs[0].txid.hex())
    assert isinstance(await env.client.call("events"), list)
    assert await env.client.call("peers") == []


async def test_external_miner_via_cli(env: Env) -> None:
    args = build_parser().parse_args(
        ["mine", "--rpc", env.url, "--address", env.alice.address, "--blocks", "2"]
    )
    await args.handler(args)
    assert env.node.chain.height == 5


async def test_block_template_and_bad_submit(env: Env) -> None:
    template = await env.client.call("block_template", address=env.alice.address)
    assert template["height"] == 4
    with pytest.raises(RpcError):
        await env.client.call("submit_block", hex_block=template["block"][:-2] + "ff")


async def test_cli_wallet_roundtrip(
    env: Env, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "w.json"
    assert main(["wallet", "--wallet", str(path), "new"]) == 0
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    created = Wallet.load(path)
    assert main(["wallet", "--wallet", str(path), "address"]) == 0
    assert created.address in capsys.readouterr().out

    # Fund it by mining to it, then send coins back to alice through the CLI handlers.
    mine_local(env.node, 2, created.script_pubkey)
    args = build_parser().parse_args(["wallet", "--wallet", str(path), "balance", "--rpc", env.url])
    await args.handler(args)
    assert "100.00000000" in capsys.readouterr().out
    args = build_parser().parse_args(
        ["wallet", "--wallet", str(path), "send", env.alice.address, "1.5", "--rpc", env.url]
    )
    await args.handler(args)
    assert "sent 1.50000000" in capsys.readouterr().out
    assert len(env.node.mempool) == 1


async def test_cli_node_runs_until_cancelled(capsys: pytest.CaptureFixture[str]) -> None:
    args = build_parser().parse_args(
        [
            "node",
            "--network",
            "regtest",
            "--port",
            "0",
            "--rpc-port",
            "0",
            "--status-interval",
            "0.05",
        ]
    )
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(args.handler(args), 0.3)
    out = capsys.readouterr().out
    assert "educational" in out
    assert "height=0" in out


def test_cli_parsers_and_errors(tmp_path: Path) -> None:
    assert parse_coins("1.5") == 150_000_000
    assert format_coins(150_000_000) == "1.50000000"
    assert parse_addr(":9") == ("127.0.0.1", 9)
    import argparse

    for bad in ("0", "abc", "0.000000001"):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_coins(bad)
    with pytest.raises(argparse.ArgumentTypeError):
        parse_addr("nope")
    assert main(["wallet", "--wallet", str(tmp_path / "missing.json"), "address"]) == 1
    assert main(["node", "--mine", "--port", "0", "--rpc-port", "0"]) == 1
