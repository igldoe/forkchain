"""Real nodes talking over localhost TCP."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import replace

import pytest

from forkchain.block import Block
from forkchain.miner import mine_block, solve
from forkchain.p2p.node import Node
from forkchain.params import COIN
from forkchain.tx import TxOut

from .conftest import wallet
from .netutil import RawClient, mine_local, start_node, wait_until

pytestmark = pytest.mark.slow


@pytest.fixture
async def nodes() -> AsyncIterator[list[Node]]:
    started: list[Node] = []
    yield started
    for node in started:
        await node.stop()


async def test_headers_first_initial_sync(nodes: list[Node]) -> None:
    a = await start_node("a")
    nodes.append(a)
    mine_local(a, 30)
    b = await start_node("b", seeds=[("127.0.0.1", a.port)])
    nodes.append(b)
    await wait_until(lambda: b.chain.tip.hash == a.chain.tip.hash)
    assert b.chain.height == 30
    assert b.stats.blocks_received == 30


async def test_block_and_tx_gossip_over_a_line(nodes: list[Node]) -> None:
    alice, bob = wallet("alice"), wallet("bob")
    a = await start_node("a")
    b = await start_node("b", seeds=[("127.0.0.1", a.port)], target_outbound=1)
    nodes += [a, b]
    c = await start_node("c", seeds=[("127.0.0.1", b.port)], target_outbound=1)
    nodes.append(c)
    await wait_until(lambda: len(b.peers) == 2)

    mine_local(a, 3, alice.script_pubkey)
    await wait_until(lambda: c.chain.height == 3)

    coins = a.chain.utxos.coins_for_script(alice.script_pubkey)
    tx = alice.build_payment(coins, [TxOut(COIN, bob.script_pubkey)], fee=1000)
    a.submit_tx(tx)
    await wait_until(lambda: tx.txid in c.mempool)

    # c mines it; the block travels back and clears everybody's mempool.
    block = mine_block(c.chain, bob.script_pubkey, [tx], fees=1000)
    c.process_block(block)
    await wait_until(lambda: a.chain.tip.hash == block.hash)
    assert tx.txid not in a.mempool


async def test_competing_tips_resolve_to_most_work(nodes: list[Node]) -> None:
    a = await start_node("a")
    b = await start_node("b")
    nodes += [a, b]
    # Different payout scripts so the two private chains really differ.
    mine_local(a, 2, wallet("a").script_pubkey)
    mine_local(b, 4, wallet("b").script_pubkey)
    task = asyncio.create_task(a.connect("127.0.0.1", b.port))
    await wait_until(lambda: a.chain.tip.hash == b.chain.tip.hash)
    assert a.chain.height == 4
    assert a.stats.max_reorg_depth == 2
    task.cancel()


async def test_builtin_miner(nodes: list[Node]) -> None:
    a = await start_node("a", mine=True, miner_script=b"\x51", hashrate=5000.0)
    b = await start_node("b")
    nodes += [a, b]
    link = asyncio.create_task(b.connect("127.0.0.1", a.port))
    await wait_until(lambda: b.chain.height >= 3)
    assert a.stats.blocks_mined >= 3
    link.cancel()


async def test_peer_exchange_finds_new_peers(nodes: list[Node]) -> None:
    hub = await start_node("hub")
    nodes.append(hub)
    x = await start_node("x", seeds=[("127.0.0.1", hub.port)])
    nodes.append(x)
    await wait_until(lambda: len(hub.peers) == 1)
    y = await start_node("y", seeds=[("127.0.0.1", hub.port)])
    nodes.append(y)
    # y learns about x from hub's addr reply and dials it on its own.
    await wait_until(lambda: any(p.info.name == "x" for p in y.peers.values()), within=10)


async def test_garbage_bytes_get_banned(nodes: list[Node]) -> None:
    node = await start_node("n")
    nodes.append(node)
    client = await RawClient.connect(node)
    client.send_raw(b"\xde\xad\xbe\xef" * 10)
    assert await client.closed()
    await wait_until(lambda: node.stats.bans == 1)


async def test_oversized_message_gets_banned(nodes: list[Node]) -> None:
    import struct

    from forkchain.p2p.protocol import HEADER_FORMAT

    node = await start_node("n")
    nodes.append(node)
    client = await RawClient.connect(node)
    client.send_raw(
        struct.pack(HEADER_FORMAT, node.magic, b"tx".ljust(12, b"\0"), 1 << 30, b"\0" * 4)
    )
    assert await client.closed()
    assert node.stats.bans == 1


async def test_message_before_handshake_is_punished(nodes: list[Node]) -> None:
    node = await start_node("n")
    nodes.append(node)
    client = await RawClient.connect(node)
    client.send("getaddr")
    assert await client.closed()
    assert node.stats.invalid_messages == 1


async def test_invalid_block_gets_peer_banned(nodes: list[Node]) -> None:
    node = await start_node("n")
    nodes.append(node)
    mine_local(node, 1)
    client = await RawClient.connect(node)
    await client.handshake()
    # Valid PoW and merkle root, but the coinbase claims more than the block reward.
    bad = mine_block(node.chain, b"\x51", fees=10**9)
    client.send("block", {"block": bad.serialize().hex()})
    assert await client.closed()
    assert node.stats.bans == 1
    assert node.chain.height == 1
    # The ban sticks: reconnecting with the same identity is refused right after version.
    again = await RawClient.connect(node)
    again.send("version", {"protocol": 1, "name": "raw", "node_id": "raw" * 4, "listen_port": 1})
    assert await again.closed()


async def test_bad_pow_header_gets_banned(nodes: list[Node]) -> None:
    node = await start_node("n")
    nodes.append(node)
    client = await RawClient.connect(node)
    await client.handshake()
    template = mine_block(node.chain, b"\x51")
    impossible = replace(template.header, bits=0x03000001)
    client.send("headers", {"headers": [impossible.serialize().hex()]})
    assert await client.closed()
    assert node.stats.bans == 1


async def test_rate_limit_eventually_bans_flooder(nodes: list[Node]) -> None:
    node = await start_node("n", rate=5.0, burst=5.0)
    nodes.append(node)
    client = await RawClient.connect(node)
    await client.handshake()
    for i in range(200):
        client.send("ping", {"nonce": i})
    assert await client.closed()
    assert node.stats.bans == 1


async def test_getdata_serves_blocks_and_notfound(nodes: list[Node]) -> None:
    node = await start_node("n")
    nodes.append(node)
    mine_local(node, 1)
    client = await RawClient.connect(node)
    await client.handshake()
    tip = node.chain.tip.hash
    client.send(
        "getdata",
        {"items": [{"type": "block", "hash": tip.hex()}, {"type": "tx", "hash": "00" * 32}]},
    )
    got: dict[str, dict[str, object]] = {}
    while not {"block", "notfound"} <= set(got):
        command, payload = await client.recv()
        got[command] = payload
    assert Block.deserialize(bytes.fromhex(str(got["block"]["block"]))).hash == tip
    client.send("ping", {"nonce": 42})
    while True:
        command, payload = await client.recv()
        if command == "pong":
            assert payload == {"nonce": 42}
            break
    client.close()


async def test_self_connection_is_dropped(nodes: list[Node]) -> None:
    node = await start_node("n")
    nodes.append(node)
    node.known_addrs.add(("127.0.0.2", node.port))  # same node, different-looking address
    await node.connect("127.0.0.2", node.port)
    assert not any(p.handshake_done for p in node.peers.values())


async def test_solve_helper_is_deterministic() -> None:
    from forkchain.chain import Chain
    from forkchain.params import REGTEST

    chain = Chain(REGTEST)
    template = mine_block(chain, b"\x51")
    assert solve(template).hash == solve(template).hash
