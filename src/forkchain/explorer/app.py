"""Live block explorer: FastAPI + WebSocket backend for a single static HTML page.

The explorer can watch several nodes at once and merges their block trees, so a fork is
visible as two branches even though each node only follows one of them. Data comes from a
``Source``: in-process nodes (simulator / demo) or remote nodes over JSON-RPC.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import random
from collections.abc import Callable, Sequence
from importlib import resources
from typing import Any, Protocol

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

from forkchain.api import ApiError, NodeAPI
from forkchain.p2p.node import Node
from forkchain.rpc import RpcClient, RpcError

SNAPSHOT_INTERVAL = 0.7
TREE_DEPTH = 45
INTERESTING_EVENTS = {"reorg", "ban", "peer_connected", "peer_disconnected"}


class Source(Protocol):
    async def names(self) -> list[str]: ...

    async def call(self, node: str, method: str, **params: Any) -> Any: ...


class LocalSource:
    """Nodes living in this process (the simulator). ``get_nodes`` is read lazily so the
    explorer can be started before the simulation has created its nodes."""

    def __init__(self, get_nodes: Callable[[], Sequence[Node]]) -> None:
        self._get_nodes = get_nodes
        self._apis: dict[str, NodeAPI] = {}

    async def names(self) -> list[str]:
        return [n.name for n in self._get_nodes()]

    async def call(self, node: str, method: str, **params: Any) -> Any:
        api = self._apis.get(node)
        if api is None:
            match = next((n for n in self._get_nodes() if n.name == node), None)
            if match is None:
                raise ApiError(f"unknown node {node!r}")
            api = self._apis[node] = NodeAPI(match)
        return api.call(method, params)


class RpcSource:
    """Remote nodes reached through their JSON-RPC port."""

    def __init__(self, urls: Sequence[str]) -> None:
        self._urls = list(urls)
        self._clients: dict[str, RpcClient] = {}
        self._url_of: dict[str, str] = {}  # node name -> url

    async def _connect(self) -> None:
        for url in self._urls:
            if url in self._url_of.values():
                continue
            client = RpcClient.from_url(url)
            try:
                info = await client.call("info")
            except (OSError, RpcError):
                await client.close()
                continue
            self._clients[info["name"]] = client
            self._url_of[info["name"]] = url

    async def names(self) -> list[str]:
        if len(self._clients) < len(self._urls):
            await self._connect()
        return list(self._clients)

    async def call(self, node: str, method: str, **params: Any) -> Any:
        client = self._clients.get(node)
        if client is None:
            raise ApiError(f"unknown node {node!r}")
        try:
            return await client.call(method, **params)
        except RpcError as exc:
            raise ApiError(str(exc)) from exc
        except OSError as exc:
            del self._clients[node]
            del self._url_of[node]
            raise ApiError(f"node {node} unreachable") from exc


async def build_snapshot(source: Source, selected: str | None) -> dict[str, Any]:
    names = await source.names()
    if not names:
        return {"type": "snapshot", "nodes": [], "tree": {"blocks": [], "tips": {}}}
    if selected not in names:
        selected = names[0]
    nodes = []
    merged: dict[str, dict[str, Any]] = {}
    tips: dict[str, str] = {}
    events: list[dict[str, Any]] = []
    for name in names:
        try:
            info = await source.call(name, "info")
            peers = await source.call(name, "peers")
            tree = await source.call(name, "tree", depth=TREE_DEPTH)
            node_events = await source.call(
                name, "events", limit=40, kinds=sorted(INTERESTING_EVENTS)
            )
        except ApiError:
            continue
        nodes.append({"name": name, "info": info, "peers": peers})
        tips[name] = tree["tip"]
        events += [e for e in node_events if e["type"] in INTERESTING_EVENTS]
        for block in tree["blocks"]:
            entry = merged.setdefault(block["hash"], block | {"active_on": [], "seen_by": []})
            entry["seen_by"].append(name)
            if block["status"] == "active":
                entry["active_on"].append(name)
            if block["status"] == "invalid":
                entry["status"] = "invalid"
    blocks = sorted(merged.values(), key=lambda b: (b["height"], b["seq"]))
    for block in blocks:
        if block["status"] != "invalid":
            block["status"] = "active" if block["active_on"] else "stale"
    heaviest = max(
        (merged[t] for t in tips.values() if t in merged),
        key=lambda b: b["chainwork"],
        default=None,
    )
    result: dict[str, Any] = {
        "type": "snapshot",
        "selected": selected,
        "nodes": nodes,
        "tree": {
            "blocks": blocks,
            "tips": tips,
            "main_tip": heaviest["hash"] if heaviest else None,
        },
        "events": sorted(events, key=lambda e: e["time"])[-40:],
    }
    with contextlib.suppress(ApiError):
        result["mempool"] = await source.call(selected, "mempool", limit=40)
        result["difficulty"] = await source.call(selected, "difficulty_history", limit=150)
    return result


def create_app(source: Source) -> FastAPI:
    app = FastAPI(title="forkchain explorer", docs_url=None, redoc_url=None)
    page = resources.files("forkchain.explorer").joinpath("static/index.html").read_text()

    async def call_any(method: str, node: str | None, **params: Any) -> Any:
        """Ask the preferred node first, then the others (a stale block may only be
        known to the node that mined it)."""
        names = await source.names()
        order = ([node] if node in names else []) + [n for n in names if n != node]
        error: ApiError = ApiError("no nodes available")
        for name in order:
            try:
                return await source.call(name, method, **params)
            except ApiError as exc:
                error = exc
        raise error

    async def answer(method: str, node: str | None, **params: Any) -> JSONResponse:
        try:
            return JSONResponse(await call_any(method, node, **params))
        except (ApiError, ValueError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=404)

    @app.get("/", response_class=HTMLResponse)
    async def index() -> str:
        return page

    @app.get("/api/nodes")
    async def nodes() -> list[str]:
        return await source.names()

    @app.get("/api/search")
    async def search(q: str, node: str | None = None) -> JSONResponse:
        return await answer("search", node, query=q)

    @app.get("/api/block/{ref}")
    async def block(ref: str, node: str | None = None) -> JSONResponse:
        return await answer("block", node, ref=ref)

    @app.get("/api/tx/{txid}")
    async def tx(txid: str, node: str | None = None) -> JSONResponse:
        return await answer("tx", node, txid=txid)

    @app.get("/api/merkle/{txid}")
    async def merkle(txid: str, node: str | None = None, block: str | None = None) -> JSONResponse:
        return await answer("merkle_proof", node, txid=txid, block=block)

    @app.get("/api/trace/{txid}/{index}")
    async def trace(txid: str, index: int, node: str | None = None) -> JSONResponse:
        return await answer("script_trace", node, txid=txid, index=index)

    @app.get("/api/address/{address}")
    async def address(address: str, node: str | None = None) -> JSONResponse:
        return await answer("utxos", node, address=address)

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:
        await socket.accept()
        selected: list[str | None] = [None]

        async def reader() -> None:
            while True:
                message = json.loads(await socket.receive_text())
                if isinstance(message, dict) and isinstance(message.get("select"), str):
                    selected[0] = message["select"]

        listen = asyncio.create_task(reader())
        try:
            while not listen.done():
                await socket.send_json(await build_snapshot(source, selected[0]))
                await asyncio.wait({listen}, timeout=SNAPSHOT_INTERVAL)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            listen.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await listen

    return app


async def serve(app: FastAPI, host: str, port: int) -> None:
    import uvicorn

    config = uvicorn.Config(app, host=host, port=port, log_level="warning", lifespan="off")
    await uvicorn.Server(config).serve()


async def chaos_loop(sim: Any, *, calm: float = 14.0, split: float = 9.0, seed: int = 0) -> None:
    """Demo mode: repeatedly split the network into random halves and heal it."""
    rng = random.Random(seed)
    while True:
        await asyncio.sleep(calm)
        names = sim.cfg.names()
        rng.shuffle(names)
        cut = rng.randint(1, len(names) - 1)
        sim.partition([names[:cut], names[cut:]])
        await asyncio.sleep(split)
        sim.heal()
