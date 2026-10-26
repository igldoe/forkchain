"""Script byte format: opcode table, data pushes and a tokenizer.

The encoding mirrors Bitcoin Script so that anyone who knows it can read forkchain
scripts: bytes ``0x01..0x4b`` push that many bytes, ``PUSHDATA1/2`` push longer data,
``OP_1..OP_16`` push small integers.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum


class Op(IntEnum):
    OP_0 = 0x00
    PUSHDATA1 = 0x4C
    PUSHDATA2 = 0x4D
    OP_1 = 0x51
    OP_16 = 0x60
    IF = 0x63
    ELSE = 0x67
    ENDIF = 0x68
    VERIFY = 0x69
    RETURN = 0x6A
    DROP = 0x75
    DUP = 0x76
    SWAP = 0x7C
    EQUAL = 0x87
    EQUALVERIFY = 0x88
    HASH = 0xA9
    CHECKSIG = 0xAC
    CHECKSIGVERIFY = 0xAD
    CHECKMULTISIG = 0xAE
    CHECKLOCKTIME = 0xB1


MAX_DIRECT_PUSH = 0x4B
SMALL_INT_OPS = range(Op.OP_1, Op.OP_16 + 1)


class ScriptParseError(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    """Either a data push (``data`` set) or a plain opcode."""

    opcode: int
    data: bytes | None = None

    @property
    def is_push(self) -> bool:
        return self.data is not None or self.opcode in SMALL_INT_OPS

    def name(self) -> str:
        if self.data is not None:
            return f"PUSH({len(self.data)})" if self.data else "OP_0"
        if self.opcode in SMALL_INT_OPS:
            return f"OP_{self.opcode - Op.OP_1 + 1}"
        try:
            return Op(self.opcode).name
        except ValueError:
            return f"UNKNOWN_0x{self.opcode:02x}"


def push_data(data: bytes) -> bytes:
    n = len(data)
    if n == 0:
        return bytes([Op.OP_0])
    if n <= MAX_DIRECT_PUSH:
        return bytes([n]) + data
    if n <= 0xFF:
        return bytes([Op.PUSHDATA1, n]) + data
    if n <= 0xFFFF:
        return bytes([Op.PUSHDATA2]) + n.to_bytes(2, "little") + data
    raise ValueError("push too large")


def push_int(value: int) -> bytes:
    """Push a non-negative integer using the most compact encoding."""
    if value < 0:
        raise ValueError("script integers are non-negative")
    if value == 0:
        return bytes([Op.OP_0])
    if value <= 16:
        return bytes([Op.OP_1 + value - 1])
    return push_data(value.to_bytes((value.bit_length() + 7) // 8, "little"))


def tokenize(script: bytes) -> Iterator[Token]:
    i = 0
    n = len(script)
    while i < n:
        op = script[i]
        i += 1
        if op == Op.OP_0:
            yield Token(op, b"")
            continue
        if op <= MAX_DIRECT_PUSH:
            size = op
        elif op == Op.PUSHDATA1:
            if i + 1 > n:
                raise ScriptParseError("truncated PUSHDATA1")
            size = script[i]
            i += 1
        elif op == Op.PUSHDATA2:
            if i + 2 > n:
                raise ScriptParseError("truncated PUSHDATA2")
            size = int.from_bytes(script[i : i + 2], "little")
            i += 2
        else:
            yield Token(op)
            continue
        if i + size > n:
            raise ScriptParseError(f"push of {size} bytes runs past end of script")
        yield Token(op, script[i : i + size])
        i += size


def assemble(*parts: bytes | Op) -> bytes:
    """Concatenate pre-encoded pushes and bare opcodes into a script."""
    return b"".join(bytes([p]) if isinstance(p, Op) else p for p in parts)
