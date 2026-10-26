"""Helpers for tests that run real nodes on localhost."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

from forkchain.miner import mine_block
from forkchain.p2p.node import Node, NodeConfig
from forkchain.p2p.protocol import Payload, encode_message, read_message
from forkchain.params import REGTEST, ConsensusParams


async def wait_until(
    cond: Callable[[], bool], within: float = 10.0, interval: float = 0.02
) -> None:
    deadline = time.monotonic() + within
    while not cond():
        if time.monotonic() > deadline:
            raise AssertionError("condition not reached in time")
        await asyncio.sleep(interval)


def fast_config(name: str, **overrides: object) -> NodeConfig:
    cfg = NodeConfig(name=name, maintenance_interval=0.1, template_refresh=0.2)
    for key, value in overrides.items():
        setattr(cfg, key, value)
    return cfg


async def start_node(name: str, params: ConsensusParams = REGTEST, **overrides: object) -> Node:
    node = Node(fast_config(name, **overrides), params)
    await node.start()
    return node


def mine_local(node: Node, n: int, script: bytes = b"\x51") -> None:
    """Mine ``n`` blocks directly into a node (no networking involved)."""
    for _ in range(n):
        node.process_block(mine_block(node.chain, script))


class RawClient:
    """Speaks the wire protocol by hand, to test how a node treats a misbehaving peer."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, magic: bytes):
        self.reader, self.writer, self.magic = reader, writer, magic

    @classmethod
    async def connect(cls, node: Node) -> RawClient:
        reader, writer = await asyncio.open_connection("127.0.0.1", node.port)
        return cls(reader, writer, node.magic)

    def send(self, command: str, payload: Payload | None = None) -> None:
        self.writer.write(encode_message(self.magic, command, payload))

    def send_raw(self, data: bytes) -> None:
        self.writer.write(data)

    async def recv(self, within: float = 5.0) -> tuple[str, Payload]:
        return await asyncio.wait_for(read_message(self.reader, self.magic), within)

    async def handshake(self, name: str = "raw") -> None:
        self.send(
            "version",
            {"protocol": 1, "name": name, "node_id": name * 4, "listen_port": 1, "height": 0},
        )
        seen = set()
        while not {"version", "verack"} <= seen:
            command, _ = await self.recv()
            seen.add(command)
        self.send("verack")

    async def closed(self, within: float = 5.0) -> bool:
        try:
            while True:
                data = await asyncio.wait_for(self.reader.read(65536), within)
                if not data:
                    return True
        except (ConnectionError, TimeoutError):
            return True

    def close(self) -> None:
        self.writer.close()
