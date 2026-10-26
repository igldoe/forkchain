"""A full node: chain + mempool + P2P networking + an optional built-in miner.

Sync is headers-first: on connect both sides exchange ``getheaders`` with a block locator,
validate the returned header chain (PoW, linkage, difficulty, timestamps) and only then
download the bodies of blocks on the most-work header chain. New blocks are announced
with a ``headers`` message, transactions with ``inv``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from forkchain.block import Block, BlockHeader, mine_header
from forkchain.chain import MAX_HEADERS_PER_MSG, AddResult, Chain, Clock, wall_clock_ms
from forkchain.encoding import DecodeError
from forkchain.errors import MissingDataError, ValidationError
from forkchain.mempool import AcceptResult, Mempool, MempoolPolicy
from forkchain.miner import build_template
from forkchain.p2p.peer import Peer
from forkchain.p2p.protocol import (
    MAX_ADDR,
    MAX_INV,
    MIN_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
    Payload,
    ProtocolError,
    hex_field,
    hex_list,
    network_magic,
)
from forkchain.params import ConsensusParams
from forkchain.tx import Transaction

log = logging.getLogger(__name__)

USER_AGENT = "/forkchain:0.1.0/"
MAX_BLOCKS_IN_FLIGHT = 64


class LinkPolicy(Protocol):
    """Hook for the chaos simulator: which links exist and how slow they are."""

    def allowed(self, a: str, b: str) -> bool: ...

    def latency(self, a: str, b: str) -> float:
        """One-way delay in seconds."""
        ...


@dataclass
class NodeConfig:
    name: str = "node"
    host: str = "127.0.0.1"
    port: int = 0  # 0 = pick a free port
    advertise_host: str | None = None  # address peers should use to reach us
    seeds: list[tuple[str, int]] = field(default_factory=list)
    mine: bool = False
    miner_script: bytes | None = None
    hashrate: float | None = None  # hashes per second cap; None = as fast as the CPU allows
    max_peers: int = 16
    target_outbound: int = 4
    maintenance_interval: float = 2.0
    ping_interval: float = 15.0
    peer_timeout: float = 60.0
    ban_seconds: float = 600.0
    rate: float = 200.0  # messages per second per peer
    burst: float = 400.0
    block_request_timeout: float = 10.0
    template_refresh: float = 1.0
    mempool: MempoolPolicy = field(default_factory=MempoolPolicy)


@dataclass
class NodeStats:
    blocks_mined: int = 0
    blocks_received: int = 0
    reorgs: int = 0
    max_reorg_depth: int = 0
    txs_reverted: int = 0
    txs_dropped: int = 0
    bans: int = 0
    invalid_messages: int = 0
    hashes: int = 0


Event = dict[str, Any]


class Node:
    def __init__(
        self,
        config: NodeConfig,
        params: ConsensusParams,
        *,
        policy: LinkPolicy | None = None,
        clock: Clock = wall_clock_ms,
    ) -> None:
        self.config = config
        self.name = config.name
        self.params = params
        self.policy = policy
        self.chain = Chain(params, clock=clock)
        self.mempool = Mempool(self.chain, config.mempool, clock=clock)
        self.magic = network_magic(params.name)
        self.node_id = os.urandom(8).hex()
        self.peers: dict[int, Peer] = {}
        self.known_addrs: set[tuple[str, int]] = set(config.seeds)
        self.addr_names: dict[tuple[str, int], str] = {}
        self.banned: dict[str, float] = {}
        self.in_flight: dict[bytes, tuple[int, float]] = {}
        self.recent_rejects: deque[bytes] = deque(maxlen=5000)
        self.block_meta: dict[bytes, dict[str, Any]] = {}
        self.listeners: list[Callable[[Event], None]] = []
        self.events: deque[Event] = deque(maxlen=2000)
        self.stats = NodeStats()
        self.mining = config.mine
        self.hashrate = config.hashrate
        self.port = config.port
        self._server: asyncio.Server | None = None
        self._tasks: set[asyncio.Task[Any]] = set()
        self._running = False
        self._tip_changed = asyncio.Event()

    # -- lifecycle -------------------------------------------------------------------------

    async def start(self) -> None:
        self._running = True
        self._server = await asyncio.start_server(
            self._on_inbound, self.config.host, self.config.port
        )
        self.port = self._server.sockets[0].getsockname()[1]
        self._spawn(self._maintenance_loop(), "maintenance")
        self._spawn(self._mine_loop(), "miner")
        for host, port in list(self.known_addrs):
            self._spawn(self.connect(host, port), "connect")
        self.emit("node_started", port=self.port)

    async def stop(self) -> None:
        self._running = False
        if self._server is not None:
            self._server.close()
        for peer in list(self.peers.values()):
            peer.close()
        for task in list(self._tasks):
            task.cancel()
        for task in list(self._tasks):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        for peer in list(self.peers.values()):
            await peer.wait_closed()
        self.peers.clear()
        if self._server is not None:
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    def _spawn(self, coro: Any, name: str) -> asyncio.Task[Any]:
        task = asyncio.create_task(coro, name=f"{self.name}-{name}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    @property
    def listen_addr(self) -> tuple[str, int]:
        return self.config.advertise_host or self.config.host, self.port

    # -- events ----------------------------------------------------------------------------

    def emit(self, kind: str, **data: Any) -> None:
        event: Event = {"type": kind, "node": self.name, "time": self.chain.clock(), **data}
        self.events.append(event)
        for listener in list(self.listeners):
            try:
                listener(event)
            except Exception:  # a broken observer must never take the node down
                log.exception("event listener failed")

    # -- connections -----------------------------------------------------------------------

    def is_banned(self, *keys: str) -> bool:
        now = time.monotonic()
        return any(self.banned.get(k, 0) > now for k in keys)

    def _ban(self, peer: Peer, reason: str) -> None:
        until = time.monotonic() + self.config.ban_seconds
        self.banned[peer.ban_key] = until
        if peer.info.node_id:
            self.banned[peer.info.node_id] = until
        self.stats.bans += 1
        log.warning("%s banned %r: %s", self.name, peer, reason)
        self.emit("ban", peer=peer.info.name, reason=reason)
        peer.close()

    def _punish(self, peer: Peer | None, points: int, reason: str) -> None:
        if peer is None:
            return
        self.stats.invalid_messages += 1
        if peer.misbehave(points, reason):
            self._ban(peer, reason)

    def _link_allowed(self, other: str) -> bool:
        return self.policy is None or self.policy.allowed(self.name, other)

    def apply_policy(self) -> int:
        """Drop connections the link policy no longer allows (e.g. a new partition)."""
        dropped = 0
        for peer in list(self.peers.values()):
            if peer.handshake_done and not self._link_allowed(peer.info.name):
                peer.close()
                dropped += 1
        return dropped

    def reconnect_known(self) -> None:
        """Dial every known address right away instead of waiting for maintenance."""
        connected = {p.listen_addr for p in self.peers.values()}
        for addr in self.known_addrs - connected:
            self._spawn(self.connect(*addr), "connect")

    def _latency_for(self, peer: Peer) -> float:
        if self.policy is None or not peer.info.name:
            return 0.0
        return self.policy.latency(self.name, peer.info.name)

    async def connect(self, host: str, port: int) -> None:
        if (host, port) == self.listen_addr or not self._running:
            return
        if len(self.peers) >= self.config.max_peers or self.is_banned(f"{host}:{port}"):
            return
        if any(p.listen_addr == (host, port) for p in self.peers.values()):
            return
        name = self.addr_names.get((host, port))
        if name is not None and not self._link_allowed(name):
            return
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 5)
        except (OSError, TimeoutError):
            return
        self.known_addrs.add((host, port))
        await self._run_peer(reader, writer, inbound=False, dial_port=port)

    async def _on_inbound(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if len(self.peers) >= self.config.max_peers or not self._running:
            writer.close()
            return
        task = asyncio.current_task()
        if task is not None:
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        await self._run_peer(reader, writer, inbound=True)

    async def _run_peer(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        inbound: bool,
        dial_port: int | None = None,
    ) -> None:
        peer = Peer(
            reader,
            writer,
            magic=self.magic,
            inbound=inbound,
            max_message_size=max(self.params.max_block_size * 2 + 4096, 1 << 16),
            rate=self.config.rate,
            burst=self.config.burst,
        )
        peer._latency = lambda: self._latency_for(peer)
        if dial_port is not None:
            peer.info.listen_port = dial_port
        self.peers[peer.id] = peer
        peer.start()
        if not inbound:
            self._send_version(peer)
        try:
            while self._running and not peer.closed:
                timeout = self.config.peer_timeout if peer.handshake_done else 10.0
                command, payload = await asyncio.wait_for(peer.receive(), timeout)
                if not peer.bucket.take():
                    self._punish(peer, 5, "rate limit exceeded")
                    continue
                await self._dispatch(peer, command, payload)
        except ProtocolError as exc:
            self._punish(peer, 100, f"protocol violation: {exc}")
        except (asyncio.IncompleteReadError, ConnectionError, OSError, TimeoutError):
            pass
        finally:
            self.peers.pop(peer.id, None)
            for block_hash, (pid, _) in list(self.in_flight.items()):
                if pid == peer.id:
                    del self.in_flight[block_hash]
            await peer.wait_closed()
            if peer.handshake_done:
                self.emit("peer_disconnected", peer=peer.info.name)

    def _send_version(self, peer: Peer) -> None:
        peer.version_sent = True
        peer.send(
            "version",
            {
                "protocol": PROTOCOL_VERSION,
                "name": self.name,
                "node_id": self.node_id,
                "listen_host": self.listen_addr[0],
                "listen_port": self.port,
                "height": self.chain.height,
                "user_agent": USER_AGENT,
            },
        )

    # -- dispatch --------------------------------------------------------------------------

    async def _dispatch(self, peer: Peer, command: str, payload: Payload) -> None:
        if command == "version":
            self._on_version(peer, payload)
            return
        if command == "verack":
            self._on_verack(peer)
            return
        if not peer.handshake_done:
            self._punish(peer, 10, f"{command} before handshake")
            peer.close()
            return
        handler = getattr(self, f"_on_{command}", None)
        if handler is None:  # pragma: no cover - COMMANDS and handlers are kept in sync
            return
        try:
            handler(peer, payload)
        except (DecodeError, ValueError, KeyError, TypeError) as exc:
            raise ProtocolError(f"malformed {command}: {exc}") from exc

    def _on_version(self, peer: Peer, payload: Payload) -> None:
        if peer.info.node_id:
            self._punish(peer, 10, "duplicate version")
            return
        node_id = str(payload.get("node_id", ""))
        name = str(payload.get("name", "?"))[:32]
        protocol = int(payload.get("protocol", 0))
        listen_port = int(payload.get("listen_port", 0))
        listen_host = str(payload.get("listen_host", peer.host))
        if protocol < MIN_PROTOCOL_VERSION:
            peer.send("reject", {"message": "version", "reason": "obsolete protocol"})
            peer.close()
            return
        duplicate = any(
            p.info.node_id == node_id
            for p in self.peers.values()
            if p is not peer and p.handshake_done
        )
        if node_id == self.node_id or duplicate:
            peer.close()
            return
        peer.info.node_id = node_id
        peer.info.name = name
        peer.info.protocol = protocol
        peer.info.height = int(payload.get("height", 0))
        peer.info.user_agent = str(payload.get("user_agent", ""))[:64]
        if listen_port:
            peer.info.listen_port = listen_port
        # In docker the advertised host is the service name; locally it is the peer IP.
        if listen_host and listen_host not in ("0.0.0.0", "::"):
            peer.host = listen_host
        self.addr_names[peer.listen_addr] = name
        if self.is_banned(peer.ban_key, node_id) or not self._link_allowed(name):
            peer.close()
            return
        if not peer.version_sent:
            self._send_version(peer)
        peer.send("verack")

    def _on_verack(self, peer: Peer) -> None:
        if peer.handshake_done or not peer.info.node_id:
            self._punish(peer, 10, "unexpected verack")
            return
        twin = next(
            (
                p
                for p in self.peers.values()
                if p is not peer and p.handshake_done and p.info.node_id == peer.info.node_id
            ),
            None,
        )
        if twin is not None:
            # Both nodes dialled each other. Keep the link opened by the smaller node id;
            # both ends evaluate the same rule, so exactly one connection survives.
            def initiator(p: Peer) -> str:
                return p.info.node_id if p.inbound else self.node_id

            loser = peer if initiator(peer) > initiator(twin) else twin
            loser.close()
            if loser is peer:
                return
        peer.handshake_done = True
        self.known_addrs.add(peer.listen_addr)
        peer.send("getaddr")
        self._send_getheaders(peer)
        self.emit("peer_connected", peer=peer.info.name, inbound=peer.inbound)

    def _on_ping(self, peer: Peer, payload: Payload) -> None:
        peer.send("pong", {"nonce": payload.get("nonce", 0)})

    def _on_pong(self, peer: Peer, payload: Payload) -> None:
        return None

    def _on_reject(self, peer: Peer, payload: Payload) -> None:
        log.info("%s: %r rejected %s", self.name, peer, payload)

    def _on_getaddr(self, peer: Peer, payload: Payload) -> None:
        addrs = [
            list(p.listen_addr)
            for p in self.peers.values()
            if p is not peer and p.handshake_done and p.info.listen_port
        ]
        peer.send("addr", {"addrs": addrs[:MAX_ADDR]})

    def _on_addr(self, peer: Peer, payload: Payload) -> None:
        addrs = payload.get("addrs")
        if not isinstance(addrs, list) or len(addrs) > MAX_ADDR:
            raise ProtocolError("bad addr list")
        for item in addrs:
            host, port = str(item[0]), int(item[1])
            if 0 < port < 65536 and (host, port) != self.listen_addr:
                self.known_addrs.add((host, port))

    def _on_inv(self, peer: Peer, payload: Payload) -> None:
        items = payload.get("items")
        if not isinstance(items, list) or len(items) > MAX_INV:
            raise ProtocolError("bad inv")
        wanted = []
        for item in items:
            kind = item["type"]
            item_hash = hex_field(item, "hash", size=32)
            if kind == "tx":
                peer.known_txs.add(item_hash)
                if item_hash not in self.mempool and item_hash not in self.recent_rejects:
                    wanted.append({"type": "tx", "hash": item_hash.hex()})
            elif kind == "block":
                peer.known_blocks.add(item_hash)
                if item_hash not in self.chain.index:
                    self._send_getheaders(peer)
        if wanted:
            peer.send("getdata", {"items": wanted})

    def _on_getdata(self, peer: Peer, payload: Payload) -> None:
        items = payload.get("items")
        if not isinstance(items, list) or len(items) > MAX_INV:
            raise ProtocolError("bad getdata")
        missing = []
        for item in items:
            item_hash = hex_field(item, "hash", size=32)
            if item["type"] == "block" and item_hash in self.chain.blocks:
                peer.known_blocks.add(item_hash)
                peer.send("block", {"block": self.chain.blocks[item_hash].serialize().hex()})
            elif item["type"] == "tx" and (tx := self.mempool.get(item_hash)) is not None:
                peer.send("tx", {"tx": tx.serialize().hex()})
            else:
                missing.append(item)
        if missing:
            peer.send("notfound", {"items": missing})

    def _on_notfound(self, peer: Peer, payload: Payload) -> None:
        for item in payload.get("items", [])[:MAX_INV]:
            self.in_flight.pop(hex_field(item, "hash", size=32), None)

    def _on_getheaders(self, peer: Peer, payload: Payload) -> None:
        locator = hex_list(payload, "locator", limit=101, size=32)
        headers = self.chain.headers_after(locator, MAX_HEADERS_PER_MSG)
        peer.send("headers", {"headers": [h.serialize().hex() for h in headers]})

    def _on_headers(self, peer: Peer, payload: Payload) -> None:
        raw_headers = hex_list(payload, "headers", limit=MAX_HEADERS_PER_MSG)
        headers = [BlockHeader.deserialize(raw) for raw in raw_headers]
        announced: list[bytes] = []
        for header in headers:
            peer.known_blocks.add(header.hash)
            try:
                idx = self.chain.add_header(header)
            except MissingDataError:
                # We are missing the ancestry: ask for the path from our locator.
                self._send_getheaders(peer)
                return
            except ValidationError as exc:
                if exc.ban:
                    self._punish(peer, 100, f"invalid header: {exc}")
                return
            peer.info.height = max(peer.info.height, idx.height)
            announced.append(idx.hash)
        self._request_blocks(peer, announced)
        if len(headers) == MAX_HEADERS_PER_MSG:
            self._send_getheaders(peer, start=headers[-1].hash)

    def _on_block(self, peer: Peer, payload: Payload) -> None:
        try:
            block = Block.deserialize(hex_field(payload, "block"))
        except ValueError as exc:
            raise ProtocolError(f"undecodable block: {exc}") from exc
        peer.known_blocks.add(block.hash)
        self.stats.blocks_received += 1
        self.process_block(block, peer)

    def _on_tx(self, peer: Peer, payload: Payload) -> None:
        tx = Transaction.deserialize(hex_field(payload, "tx"))
        peer.known_txs.add(tx.txid)
        # Rejections are handled (and punished) inside process_tx; a tx spending unknown
        # outputs is simply dropped, we keep no orphan-transaction pool.
        with contextlib.suppress(ValidationError, MissingDataError):
            self.process_tx(tx, peer)

    # -- sync ------------------------------------------------------------------------------

    def _send_getheaders(self, peer: Peer, start: bytes | None = None) -> None:
        locator = self.chain.locator()
        if start is not None:
            locator = [start, *locator]
        peer.send("getheaders", {"locator": [h.hex() for h in locator[:101]]})

    def _request_blocks(self, peer: Peer, announced: Sequence[bytes] = ()) -> None:
        """Ask ``peer`` for block bodies we have headers for.

        Downloads the most-work header chain, plus freshly announced blocks that are at
        least as heavy as our tip (so competing tips at the same height are seen, which is
        what makes forks visible in the explorer).
        """
        now = time.monotonic()
        budget = MAX_BLOCKS_IN_FLIGHT - len(self.in_flight)
        wanted = self.chain.blocks_to_download(MAX_BLOCKS_IN_FLIGHT)
        for block_hash in announced:
            idx = self.chain.index[block_hash]
            if not idx.has_data and idx.chainwork >= self.chain.tip.chainwork:
                wanted.append(block_hash)
        items = []
        for block_hash in dict.fromkeys(wanted):
            if budget <= 0:
                break
            if block_hash in self.chain.blocks:
                continue
            flight = self.in_flight.get(block_hash)
            if flight is not None and now - flight[1] < self.config.block_request_timeout:
                continue
            self.in_flight[block_hash] = (peer.id, now)
            items.append({"type": "block", "hash": block_hash.hex()})
            budget -= 1
        if items:
            peer.send("getdata", {"items": items})

    # -- processing ------------------------------------------------------------------------

    def process_block(self, block: Block, source: Peer | None = None) -> AddResult | None:
        self.in_flight.pop(block.hash, None)
        try:
            result = self.chain.add_block(block)
        except ValidationError as exc:
            log.info("%s rejected block %s: %s", self.name, block.hash.hex()[:16], exc)
            if exc.ban:
                self._punish(source, 100, f"invalid block: {exc}")
            return None
        except Exception:
            # A bug on our side is not the peer's fault: never turn it into a ban.
            log.exception("%s: internal error processing block %s", self.name, block.hash.hex())
            self.emit("internal_error", hash=block.hash.hex())
            return None
        if result.status == "duplicate":
            return result
        if result.status == "orphan":
            if source is not None:
                self._send_getheaders(source)
            return result
        sync = self.mempool.chain_updated(result.update)
        for connected in result.update.connected:
            self._note_block(connected, source if connected.hash == block.hash else None)
        self._note_block(block, source)
        if result.update.reorg_depth:
            self.stats.reorgs += 1
            self.stats.max_reorg_depth = max(self.stats.max_reorg_depth, result.update.reorg_depth)
            self.stats.txs_reverted += len(sync.reverted)
            self.stats.txs_dropped += len([t for t in sync.dropped if t in set(sync.reverted)])
            self.emit(
                "reorg",
                depth=result.update.reorg_depth,
                disconnected=[b.hash.hex() for b in result.update.disconnected],
                connected=[b.hash.hex() for b in result.update.connected],
                reverted=[t.hex() for t in sync.reverted],
                dropped=[t.hex() for t in sync.dropped],
            )
        if result.status == "invalid":
            self._punish(source, 100, f"invalid block: {result.error}")
            return result
        self.emit(
            "block",
            hash=block.hash.hex(),
            height=result.index.height if result.index else None,
            status=result.status,
            source=source.info.name if source else "self",
        )
        if result.update.connected:
            self._tip_changed.set()
        self._announce_block(block)
        if source is not None:
            self._request_blocks(source)  # keep the headers-first download going
        return result

    def _note_block(self, block: Block, source: Peer | None) -> None:
        if block.hash not in self.block_meta:
            self.block_meta[block.hash] = {
                "received": self.chain.clock(),
                "source": source.info.name if source else self.name,
            }

    def _announce_block(self, block: Block) -> None:
        for peer in self.peers.values():
            if peer.handshake_done and block.hash not in peer.known_blocks:
                peer.known_blocks.add(block.hash)
                peer.send("headers", {"headers": [block.header.serialize().hex()]})

    def process_tx(self, tx: Transaction, source: Peer | None = None) -> AcceptResult:
        """Validate and relay a transaction; raises on rejection (callers may ignore)."""
        try:
            result = self.mempool.accept(tx)
        except ValidationError as exc:
            if exc.code != "txn-already-in-mempool":
                self.recent_rejects.append(tx.txid)
            if exc.ban:
                self._punish(source, 20, f"invalid tx: {exc}")
            raise
        self.emit(
            "tx", txid=tx.txid.hex(), fee=result.fee, replaced=[t.hex() for t in result.replaced]
        )
        for peer in self.peers.values():
            if peer.handshake_done and tx.txid not in peer.known_txs:
                peer.known_txs.add(tx.txid)
                peer.send("inv", {"items": [{"type": "tx", "hash": tx.txid.hex()}]})
        return result

    def submit_tx(self, tx: Transaction) -> AcceptResult:
        return self.process_tx(tx, None)

    # -- background loops ------------------------------------------------------------------

    async def _maintenance_loop(self) -> None:
        last_ping = time.monotonic()
        while self._running:
            await asyncio.sleep(self.config.maintenance_interval)
            now = time.monotonic()
            self.banned = {k: v for k, v in self.banned.items() if v > now}
            for peer in list(self.peers.values()):
                cut_off = peer.handshake_done and not self._link_allowed(peer.info.name)
                silent = now - peer.last_seen > self.config.peer_timeout
                if cut_off or silent:
                    peer.close()
            if now - last_ping > self.config.ping_interval:
                last_ping = now
                for peer in self.peers.values():
                    if peer.handshake_done:
                        peer.send("ping", {"nonce": int(now)})
            # Re-request block bodies whose request timed out or whose peer is gone.
            for peer in self.peers.values():
                if peer.handshake_done:
                    self._request_blocks(peer)
            outbound = sum(1 for p in self.peers.values() if not p.inbound)
            if outbound < self.config.target_outbound:
                connected = {p.listen_addr for p in self.peers.values()}
                for addr in list(self.known_addrs - connected)[: self.config.target_outbound]:
                    self._spawn(self.connect(*addr), "connect")

    def _template(self) -> Block:
        assert self.config.miner_script is not None
        txs, fees = self.mempool.select(self.params.max_block_size - 2_000)
        return build_template(
            self.chain, self.config.miner_script, txs, fees=fees, extra=self.name.encode()[:32]
        )

    async def _mine_loop(self) -> None:
        """Cooperative miner: hashes in small batches and yields to the event loop.

        With ``hashrate`` set it sleeps between batches so that the node performs about
        that many hashes per second. That is how the simulator gives one node 10x the
        "hash power" of another while they all share a single CPU.
        """
        pace_start = time.monotonic()
        paced_hashes = 0
        while self._running:
            if not self.mining or self.config.miner_script is None:
                await asyncio.sleep(0.1)
                pace_start, paced_hashes = time.monotonic(), 0
                continue
            template = self._template()
            tip = self.chain.tip
            started = time.monotonic()
            nonce = int.from_bytes(os.urandom(4), "little") << 24
            self._tip_changed.clear()
            while (
                self._running
                and self.mining
                and self.chain.tip is tip
                and time.monotonic() - started < self.config.template_refresh
            ):
                rate = self.hashrate
                batch = max(1, int(rate * 0.02)) if rate else 5_000
                solved = mine_header(template.header, nonce, batch)
                nonce += batch
                self.stats.hashes += batch
                paced_hashes += batch
                if solved is not None:
                    self.stats.blocks_mined += 1
                    block = Block(solved, template.txs)
                    self.emit("mined", hash=block.hash.hex(), height=tip.height + 1)
                    self.process_block(block, None)
                    break
                if not rate:
                    await asyncio.sleep(0)
                    continue
                # Pace against a running budget rather than sleeping batch/rate each time:
                # event-loop overhead would otherwise silently lower the real hashrate.
                ahead = paced_hashes / rate - (time.monotonic() - pace_start)
                if ahead < -1.0:  # fell far behind (busy loop): forget the debt, no bursts
                    pace_start, paced_hashes = time.monotonic(), 0
                await asyncio.sleep(max(0.0, ahead))

    # -- introspection ---------------------------------------------------------------------

    def peer_summary(self) -> list[dict[str, Any]]:
        return [
            {
                "id": p.id,
                "name": p.info.name,
                "addr": f"{p.listen_addr[0]}:{p.listen_addr[1]}",
                "inbound": p.inbound,
                "height": p.info.height,
                "score": p.score,
                "handshake": p.handshake_done,
                "latency_ms": round(self._latency_for(p) * 1000),
            }
            for p in self.peers.values()
        ]
