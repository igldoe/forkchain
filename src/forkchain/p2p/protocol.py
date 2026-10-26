"""Wire format.

Every message is a 24-byte binary header followed by a JSON payload::

    magic    4 bytes   network id; a node on another network is rejected immediately
    command 12 bytes   ASCII, NUL-padded ("version", "headers", ...)
    length   4 bytes   payload length, little-endian; checked against the limit *before*
                       the payload is read, so a peer cannot make us buffer 4 GiB
    checksum 4 bytes   first 4 bytes of sha256d(payload)

Blocks, headers and transactions inside payloads are hex strings of their canonical binary
serialization, so their hashes are exactly the ones the consensus code computes.
"""

from __future__ import annotations

import asyncio
import json
import struct
from typing import Any

from forkchain.crypto import sha256d

PROTOCOL_VERSION = 1
MIN_PROTOCOL_VERSION = 1
HEADER_FORMAT = "<4s12sI4s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_MESSAGE_SIZE = 4 * 1024 * 1024
MAX_INV = 1000
MAX_ADDR = 100

COMMANDS = frozenset(
    {
        "version",
        "verack",
        "ping",
        "pong",
        "getaddr",
        "addr",
        "inv",
        "getdata",
        "notfound",
        "block",
        "tx",
        "getheaders",
        "headers",
        "reject",
    }
)

Payload = dict[str, Any]


class ProtocolError(Exception):
    """The peer violated the wire protocol; the connection should be dropped (and punished)."""


def network_magic(network: str) -> bytes:
    return sha256d(b"forkchain/" + network.encode())[:4]


def encode_message(magic: bytes, command: str, payload: Payload | None = None) -> bytes:
    if command not in COMMANDS:
        raise ValueError(f"unknown command {command!r}")
    body = json.dumps(payload or {}, separators=(",", ":")).encode()
    if len(body) > MAX_MESSAGE_SIZE:
        raise ValueError(f"message too large: {len(body)} bytes")
    header = struct.pack(
        HEADER_FORMAT, magic, command.encode().ljust(12, b"\0"), len(body), sha256d(body)[:4]
    )
    return header + body


def decode_header(raw: bytes, magic: bytes, max_size: int) -> tuple[str, int, bytes]:
    got_magic, command_raw, length, checksum = struct.unpack(HEADER_FORMAT, raw)
    if got_magic != magic:
        raise ProtocolError("wrong network magic")
    command = command_raw.rstrip(b"\0").decode("ascii", errors="replace")
    if command not in COMMANDS:
        raise ProtocolError(f"unknown command {command!r}")
    if length > max_size:
        raise ProtocolError(f"message of {length} bytes exceeds limit {max_size}")
    return command, length, checksum


def decode_payload(body: bytes, checksum: bytes) -> Payload:
    if sha256d(body)[:4] != checksum:
        raise ProtocolError("bad checksum")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("payload is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ProtocolError("payload must be a JSON object")
    return payload


async def read_message(
    reader: asyncio.StreamReader, magic: bytes, max_size: int = MAX_MESSAGE_SIZE
) -> tuple[str, Payload]:
    raw = await reader.readexactly(HEADER_SIZE)
    command, length, checksum = decode_header(raw, magic, max_size)
    body = await reader.readexactly(length)
    return command, decode_payload(body, checksum)


def hex_field(payload: Payload, key: str, *, size: int | None = None) -> bytes:
    """Fetch a hex-encoded bytes field, raising ``ProtocolError`` on any malformation."""
    value = payload.get(key)
    if not isinstance(value, str):
        raise ProtocolError(f"field {key!r} must be a hex string")
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise ProtocolError(f"field {key!r} is not hex") from exc
    if size is not None and len(data) != size:
        raise ProtocolError(f"field {key!r} must be {size} bytes")
    return data


def hex_list(payload: Payload, key: str, *, limit: int, size: int | None = None) -> list[bytes]:
    values = payload.get(key)
    if not isinstance(values, list) or len(values) > limit:
        raise ProtocolError(f"field {key!r} must be a list of at most {limit} items")
    return [hex_field({"v": v}, "v", size=size) for v in values]
