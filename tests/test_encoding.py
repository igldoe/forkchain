import pytest
from hypothesis import given
from hypothesis import strategies as st

from forkchain.encoding import DecodeError, Reader, Writer, encode_varint


@given(st.integers(min_value=0, max_value=2**64 - 1))
def test_varint_roundtrip(value: int) -> None:
    r = Reader(encode_varint(value))
    assert r.varint() == value
    r.expect_end()


@pytest.mark.parametrize("raw", [b"\xfd\x01\x00", b"\xfe\xff\x00\x00\x00", b"\xff" + bytes(8)])
def test_non_canonical_varint_rejected(raw: bytes) -> None:
    with pytest.raises(DecodeError, match="non-canonical"):
        Reader(raw).varint()


def test_reader_truncated_and_trailing() -> None:
    with pytest.raises(DecodeError):
        Reader(b"\x01\x02").u32()
    r = Reader(b"\x00\x01")
    r.u8()
    with pytest.raises(DecodeError, match="trailing"):
        r.expect_end()


def test_var_bytes_limit() -> None:
    data = Writer().var_bytes(b"x" * 10).getvalue()
    assert Reader(data).var_bytes() == b"x" * 10
    with pytest.raises(DecodeError, match="exceeds"):
        Reader(data).var_bytes(max_len=5)


def test_varint_out_of_range() -> None:
    with pytest.raises(ValueError, match="out of range"):
        encode_varint(-1)
