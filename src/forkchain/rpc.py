"""Newline-delimited JSON-RPC over TCP, for the CLI wallet, external miner and explorer.

There is no authentication: the server binds to 127.0.0.1 by default and must not be
exposed to untrusted networks.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import Any

from forkchain.api import ApiError, NodeAPI

log = logging.getLogger(__name__)

MAX_REQUEST = 4 * 1024 * 1024


class RpcError(Exception):
    pass


class RpcServer:
    def __init__(self, api: NodeAPI, host: str = "127.0.0.1", port: int = 0) -> None:
        self.api = api
        self.host = host
        self.port = port
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle, self.host, self.port, limit=MAX_REQUEST
        )
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while line := await reader.readline():
                writer.write(json.dumps(self._respond(line)).encode() + b"\n")
                await writer.drain()
        except (ConnectionError, ValueError):
            pass
        finally:
            writer.close()

    def _respond(self, line: bytes) -> dict[str, Any]:
        request_id = None
        try:
            request = json.loads(line)
            request_id = request.get("id")
            params = request.get("params") or {}
            if not isinstance(params, dict):
                raise ApiError("params must be an object")
            result = self.api.call(str(request.get("method")), params)
        except (ApiError, ValueError, TypeError, KeyError) as exc:
            return {"id": request_id, "error": str(exc)}
        except Exception as exc:  # pragma: no cover - surfaced to the client, logged here
            log.exception("rpc failure")
            return {"id": request_id, "error": f"internal error: {exc}"}
        return {"id": request_id, "result": result}


class RpcClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 8332) -> None:
        self.host = host
        self.port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._next_id = 0
        self._lock = asyncio.Lock()

    @classmethod
    def from_url(cls, url: str) -> RpcClient:
        host, _, port = url.rpartition(":")
        return cls(host or "127.0.0.1", int(port))

    async def call(self, method: str, **params: Any) -> Any:
        async with self._lock:
            if self._writer is None:
                self._reader, self._writer = await asyncio.open_connection(
                    self.host, self.port, limit=MAX_REQUEST
                )
            assert self._reader is not None
            self._next_id += 1
            request = {"id": self._next_id, "method": method, "params": params}
            self._writer.write(json.dumps(request).encode() + b"\n")
            await self._writer.drain()
            line = await self._reader.readline()
        if not line:
            await self.close()
            raise RpcError("connection closed by node")
        response = json.loads(line)
        if "error" in response:
            raise RpcError(response["error"])
        return response["result"]

    async def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
            with contextlib.suppress(Exception):
                await self._writer.wait_closed()
        self._reader = self._writer = None
