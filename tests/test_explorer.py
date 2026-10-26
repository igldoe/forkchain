"""Explorer backend: merged fork tree, HTTP endpoints and the WebSocket feed."""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi.testclient import TestClient

from forkchain.api import NodeAPI
from forkchain.explorer.app import LocalSource, RpcSource, build_snapshot, chaos_loop, create_app
from forkchain.miner import mine_block
from forkchain.p2p.node import Node
from forkchain.params import COIN
from forkchain.rpc import RpcServer
from forkchain.tx import TxOut

from .conftest import wallet
from .netutil import mine_local, start_node

pytestmark = pytest.mark.slow


@pytest.fixture
async def forked() -> AsyncIterator[list[Node]]:
    """Two unconnected nodes sharing 2 blocks, then each extending its own branch."""
    a = await start_node("a")
    b = await start_node("b")
    mine_local(a, 2, wallet("a").script_pubkey)
    for height in (1, 2):
        b.process_block(a.chain.block_at(height))
    mine_local(a, 2, wallet("a").script_pubkey)
    mine_local(b, 1, wallet("b").script_pubkey)
    yield [a, b]
    await a.stop()
    await b.stop()


async def test_snapshot_merges_forks(forked: list[Node]) -> None:
    snap = await build_snapshot(LocalSource(lambda: forked), None)
    blocks = {blk["hash"]: blk for blk in snap["tree"]["blocks"]}
    assert len(blocks) == 6  # genesis + 2 shared + 2 on a + 1 on b
    a, b = forked
    assert snap["tree"]["tips"] == {"a": a.chain.tip.hash.hex(), "b": b.chain.tip.hash.hex()}
    assert snap["tree"]["main_tip"] == a.chain.tip.hash.hex()  # more work
    shared = blocks[a.chain.block_at(2).hash.hex()]
    assert sorted(shared["active_on"]) == ["a", "b"]
    assert blocks[b.chain.tip.hash.hex()]["active_on"] == ["b"]
    assert snap["selected"] == "a"
    assert "difficulty" in snap
    assert "mempool" in snap


async def test_stale_block_status_after_merge(forked: list[Node]) -> None:
    a, b = forked
    # b learns a's heavier branch and reorgs: its own block is now stale everywhere.
    stale = b.chain.tip.hash.hex()
    for height in (3, 4):
        b.process_block(a.chain.block_at(height))
    snap = await build_snapshot(LocalSource(lambda: forked), "b")
    status = {blk["hash"]: blk["status"] for blk in snap["tree"]["blocks"]}
    assert status[stale] == "stale"
    assert len(set(snap["tree"]["tips"].values())) == 1


async def test_http_endpoints(forked: list[Node]) -> None:
    a, _ = forked
    alice, bob = wallet("a"), wallet("bob")
    coins = a.chain.utxos.coins_for_script(alice.script_pubkey)
    tx = alice.build_payment(coins[:1], [TxOut(COIN, bob.script_pubkey)], fee=1000)
    a.submit_tx(tx)
    a.process_block(mine_block(a.chain, alice.script_pubkey, [tx], fees=1000))
    app = create_app(LocalSource(lambda: forked))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        page = await client.get("/")
        assert page.status_code == 200
        assert "forkchain" in page.text
        assert (await client.get("/api/nodes")).json() == ["a", "b"]
        block = (await client.get(f"/api/block/{a.chain.tip.hash.hex()}")).json()
        assert block["ntx"] == 2
        # A block only b knows is still found, via the fallback to other nodes.
        only_b = forked[1].chain.tip.hash.hex()
        assert (await client.get(f"/api/block/{only_b}?node=a")).json()["hash"] == only_b
        assert (await client.get(f"/api/tx/{tx.txid.hex()}")).json()["status"] == "active"
        assert (await client.get(f"/api/merkle/{tx.txid.hex()}")).json()["valid"] is True
        assert (await client.get(f"/api/trace/{tx.txid.hex()}/0")).json()["valid"] is True
        assert (await client.get(f"/api/search?q={alice.address}")).json()["kind"] == "address"
        assert (await client.get(f"/api/address/{alice.address}")).json()["spendable"] > 0
        missing = await client.get(f"/api/tx/{'00' * 32}")
        assert missing.status_code == 404
        assert "error" in missing.json()


def test_websocket_streams_snapshots() -> None:
    import asyncio

    loop = asyncio.new_event_loop()
    node = loop.run_until_complete(start_node("ws"))
    mine_local(node, 2)
    try:
        client = TestClient(create_app(LocalSource(lambda: [node])))
        with client.websocket_connect("/ws") as socket:
            snap = socket.receive_json()
            assert snap["type"] == "snapshot"
            assert snap["nodes"][0]["info"]["height"] == 2
            socket.send_json({"select": "ws"})
            assert socket.receive_json()["selected"] == "ws"
    finally:
        loop.run_until_complete(node.stop())
        loop.close()


async def test_rpc_source_against_real_rpc(forked: list[Node]) -> None:
    servers = [RpcServer(NodeAPI(n)) for n in forked]
    for server in servers:
        await server.start()
    source = RpcSource([f"127.0.0.1:{s.port}" for s in servers] + ["127.0.0.1:1"])
    try:
        assert sorted(await source.names()) == ["a", "b"]
        snap = await build_snapshot(source, "b")
        assert snap["selected"] == "b"
        assert len(snap["tree"]["blocks"]) == 6
    finally:
        for server in servers:
            await server.stop()


async def test_empty_source_snapshot() -> None:
    snap = await build_snapshot(LocalSource(list), None)
    assert snap["nodes"] == []


async def test_chaos_loop_splits_and_heals() -> None:
    import asyncio

    class FakeSim:
        class cfg:  # noqa: N801 - mimics SimConfig attribute access
            @staticmethod
            def names() -> list[str]:
                return ["n0", "n1", "n2"]

        def __init__(self) -> None:
            self.calls: list[str] = []

        def partition(self, groups: list[list[str]]) -> None:
            assert sum(len(g) for g in groups) == 3
            self.calls.append("split")

        def heal(self) -> None:
            self.calls.append("heal")

    sim = FakeSim()
    task = asyncio.create_task(chaos_loop(sim, calm=0.01, split=0.01))
    await asyncio.sleep(0.1)
    task.cancel()
    assert sim.calls[:2] == ["split", "heal"]
