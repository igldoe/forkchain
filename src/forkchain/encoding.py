"""Deterministic binary serialization primitives.

Everything that gets hashed (headers, transactions) goes through these helpers so that
two nodes always produce identical bytes for identical objects. Integers are little-endian,
variable-length data is prefixed with a Bitcoin-style CompactSize varint.
"""

from __future__ import annotations

import struct

MAX_VARINT = 2**64 - 1


class DecodeError(ValueError):
    """Raised when bytes cannot be decoded into a well-formed object."""


class Writer:
    __slots__ = ("_parts",)

    def __init__(self) -> None:
        self._parts: list[bytes] = []

    def u8(self, value: int) -> Writer:
        self._parts.append(struct.pack("<B", value))
        return self

    def u32(self, value: int) -> Writer:
        self._parts.append(struct.pack("<I", value))
        return self

    def u64(self, value: int) -> Writer:
        self._parts.append(struct.pack("<Q", value))
        return self

    def varint(self, value: int) -> Writer:
        self._parts.append(encode_varint(value))
        return self

    def raw(self, data: bytes) -> Writer:
        self._parts.append(data)
        return self

    def var_bytes(self, data: bytes) -> Writer:
        return self.varint(len(data)).raw(data)

    def getvalue(self) -> bytes:
        return b"".join(self._parts)


class Reader:
    __slots__ = ("_data", "_pos")

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def _take(self, n: int) -> bytes:
        if n < 0 or self._pos + n > len(self._data):
            raise DecodeError(f"unexpected end of data: need {n} bytes at offset {self._pos}")
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def u8(self) -> int:
        return int(self._take(1)[0])

    def u32(self) -> int:
        value: int = struct.unpack("<I", self._take(4))[0]
        return value

    def u64(self) -> int:
        value: int = struct.unpack("<Q", self._take(8))[0]
        return value

    def varint(self) -> int:
        prefix = self.u8()
        if prefix < 0xFD:
            return prefix
        if prefix == 0xFD:
            value: int = struct.unpack("<H", self._take(2))[0]
            minimum = 0xFD
        elif prefix == 0xFE:
            value = struct.unpack("<I", self._take(4))[0]
            minimum = 0x10000
        else:
            value = struct.unpack("<Q", self._take(8))[0]
            minimum = 0x100000000
        if value < minimum:
            # Non-canonical encodings would let two byte strings decode to the same object,
            # which breaks the "one object, one hash" invariant.
            raise DecodeError("non-canonical varint")
        return value

    def raw(self, n: int) -> bytes:
        return self._take(n)

    def var_bytes(self, max_len: int | None = None) -> bytes:
        n = self.varint()
        if max_len is not None and n > max_len:
            raise DecodeError(f"length {n} exceeds limit {max_len}")
        return self._take(n)

    @property
    def remaining(self) -> int:
        return len(self._data) - self._pos

    def expect_end(self) -> None:
        if self.remaining:
            raise DecodeError(f"{self.remaining} trailing bytes")


def encode_varint(value: int) -> bytes:
    if value < 0 or value > MAX_VARINT:
        raise ValueError(f"varint out of range: {value}")
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)
