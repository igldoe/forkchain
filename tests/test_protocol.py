import asyncio
import struct

import pytest

from forkchain.crypto import sha256d
from forkchain.p2p.peer import TokenBucket
from forkchain.p2p.protocol import (
    HEADER_FORMAT,
    ProtocolError,
    decode_header,
    decode_payload,
    encode_message,
    hex_field,
    hex_list,
    network_magic,
    read_message,
)

MAGIC = network_magic("regtest")


async def roundtrip(data: bytes, max_size: int = 1 << 20) -> tuple[str, dict[str, object]]:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return await read_message(reader, MAGIC, max_size)


async def test_roundtrip() -> None:
    assert await roundtrip(encode_message(MAGIC, "ping", {"nonce": 7})) == ("ping", {"nonce": 7})


def test_magic_differs_per_network() -> None:
    assert network_magic("main") != network_magic("regtest")


async def test_wrong_magic() -> None:
    with pytest.raises(ProtocolError, match="magic"):
        await roundtrip(encode_message(network_magic("main"), "ping"))


async def test_oversized_rejected_before_reading_body() -> None:
    header = struct.pack(HEADER_FORMAT, MAGIC, b"block".ljust(12, b"\0"), 10**9, b"\0" * 4)
    with pytest.raises(ProtocolError, match="exceeds"):
        await roundtrip(header)  # no body follows: we must not wait for 1 GB


def test_bad_checksum_and_json() -> None:
    with pytest.raises(ProtocolError, match="checksum"):
        decode_payload(b"{}", b"\0\0\0\0")
    body = b"not json"
    with pytest.raises(ProtocolError, match="JSON"):
        decode_payload(body, sha256d(body)[:4])
    body = b"[1,2]"
    with pytest.raises(ProtocolError, match="object"):
        decode_payload(body, sha256d(body)[:4])


def test_unknown_command() -> None:
    raw = struct.pack(HEADER_FORMAT, MAGIC, b"hack".ljust(12, b"\0"), 0, b"\0" * 4)
    with pytest.raises(ProtocolError, match="unknown command"):
        decode_header(raw, MAGIC, 100)
    with pytest.raises(ValueError, match="unknown command"):
        encode_message(MAGIC, "hack")


def test_hex_helpers() -> None:
    assert hex_field({"h": "ab"}, "h") == b"\xab"
    with pytest.raises(ProtocolError):
        hex_field({"h": 5}, "h")
    with pytest.raises(ProtocolError):
        hex_field({"h": "zz"}, "h")
    with pytest.raises(ProtocolError):
        hex_field({"h": "ab"}, "h", size=2)
    assert hex_list({"l": ["00", "01"]}, "l", limit=2) == [b"\0", b"\1"]
    with pytest.raises(ProtocolError):
        hex_list({"l": ["00"] * 3}, "l", limit=2)


def test_token_bucket() -> None:
    now = [0.0]
    bucket = TokenBucket(rate=10, burst=5, clock=lambda: now[0])
    assert all(bucket.take() for _ in range(5))
    assert not bucket.take()
    now[0] += 0.25  # 2.5 tokens refilled
    assert bucket.take()
    assert bucket.take()
    assert not bucket.take()
