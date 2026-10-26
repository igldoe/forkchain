"""One TCP connection to another node: framing, send queue, rate limit, misbehaviour."""

from __future__ import annotations

import asyncio
import contextlib
import heapq
import itertools
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from forkchain.p2p.protocol import Payload, encode_message, read_message

log = logging.getLogger(__name__)

BAN_THRESHOLD = 100


class TokenBucket:
    """Classic token bucket: ``rate`` tokens per second, at most ``burst`` saved up."""

    def __init__(self, rate: float, burst: float, clock: Callable[[], float] = time.monotonic):
        self.rate = rate
        self.burst = burst
        self._tokens = burst
        self._clock = clock
        self._last = clock()

    def take(self, n: float = 1.0) -> bool:
        now = self._clock()
        self._tokens = min(self.burst, self._tokens + (now - self._last) * self.rate)
        self._last = now
        if self._tokens >= n:
            self._tokens -= n
            return True
        return False


@dataclass
class PeerInfo:
    """What we learned from the peer's ``version`` message."""

    name: str = "?"
    node_id: str = ""
    listen_port: int = 0
    height: int = 0
    protocol: int = 0
    user_agent: str = ""


@dataclass(order=True)
class _Scheduled:
    due: float
    seq: int
    data: bytes = field(compare=False)


class Peer:
    _ids = itertools.count(1)

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        magic: bytes,
        inbound: bool,
        max_message_size: int,
        rate: float = 200.0,
        burst: float = 400.0,
        latency: Callable[[], float] = lambda: 0.0,
    ) -> None:
        self.id = next(self._ids)
        self.reader = reader
        self.writer = writer
        self.magic = magic
        self.inbound = inbound
        self.max_message_size = max_message_size
        self.info = PeerInfo()
        self.handshake_done = False
        self.version_sent = False
        self.score = 0
        self.connected_at = time.time()
        self.last_seen = time.monotonic()
        self.bucket = TokenBucket(rate, burst)
        self.known_blocks: set[bytes] = set()
        self.known_txs: set[bytes] = set()
        self.bytes_sent = 0
        self.messages_received = 0
        self._latency = latency
        self._queue: list[_Scheduled] = []
        self._seq = itertools.count()
        self._wakeup = asyncio.Event()
        self._closed = False
        self._sender: asyncio.Task[None] | None = None
        peername = writer.get_extra_info("peername")
        self.host: str = peername[0] if peername else "?"
        self.port: int = peername[1] if peername else 0

    # -- identity --------------------------------------------------------------------------

    @property
    def listen_addr(self) -> tuple[str, int]:
        return self.host, self.info.listen_port or self.port

    @property
    def ban_key(self) -> str:
        host, port = self.listen_addr
        return f"{host}:{port}"

    def __repr__(self) -> str:
        return f"Peer#{self.id}({self.info.name}@{self.host}:{self.port})"

    # -- I/O -------------------------------------------------------------------------------

    def start(self) -> None:
        self._sender = asyncio.create_task(self._send_loop(), name=f"peer-{self.id}-send")

    def send(self, command: str, payload: Payload | None = None) -> None:
        """Queue a message. Latency (for the simulator) is applied per message while
        keeping FIFO order, like a slow but reliable TCP link."""
        if self._closed:
            return
        data = encode_message(self.magic, command, payload)
        due = time.monotonic() + self._latency()
        if self._queue:
            due = max(due, max(item.due for item in self._queue))
        heapq.heappush(self._queue, _Scheduled(due, next(self._seq), data))
        self._wakeup.set()

    async def _send_loop(self) -> None:
        try:
            while not self._closed:
                if not self._queue:
                    self._wakeup.clear()
                    await self._wakeup.wait()
                    continue
                delay = self._queue[0].due - time.monotonic()
                if delay > 0:
                    self._wakeup.clear()
                    with contextlib.suppress(TimeoutError):
                        await asyncio.wait_for(self._wakeup.wait(), delay)
                    continue
                item = heapq.heappop(self._queue)
                self.writer.write(item.data)
                self.bytes_sent += len(item.data)
                await self.writer.drain()
        except (ConnectionError, OSError):
            self.close()

    async def receive(self) -> tuple[str, Payload]:
        command, payload = await read_message(self.reader, self.magic, self.max_message_size)
        self.last_seen = time.monotonic()
        self.messages_received += 1
        return command, payload

    def misbehave(self, points: int, reason: str) -> bool:
        """Add to the misbehaviour score; return True once the peer deserves a ban."""
        self.score += points
        log.info("%r misbehaved (+%d = %d): %s", self, points, self.score, reason)
        return self.score >= BAN_THRESHOLD

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._wakeup.set()
        with contextlib.suppress(Exception):
            self.writer.close()

    @property
    def closed(self) -> bool:
        return self._closed

    async def wait_closed(self) -> None:
        self.close()
        if self._sender is not None:
            self._sender.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._sender
        with contextlib.suppress(Exception):
            await self.writer.wait_closed()
