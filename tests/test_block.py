from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from forkchain.block import (
    Block,
    BlockHeader,
    check_block,
    make_genesis,
    mine_header,
)
from forkchain.crypto import sha256d
from forkchain.encoding import DecodeError
from forkchain.errors import ValidationError
from forkchain.merkle import merkle_root
from forkchain.params import MAIN, ConsensusParams
from forkchain.tx import OutPoint, Transaction, TxIn, TxOut, make_coinbase

# Each attempt succeeds with p ~ 1/256: fast to mine, yet random headers almost always fail.
PARAMS = ConsensusParams(name="test", pow_limit_bits=0x2000FFFF, genesis_bits=0x2000FFFF)


def make_block(txs: tuple[Transaction, ...], prev: bytes = bytes(32), ts: int = 1) -> Block:
    header = BlockHeader(prev, merkle_root([t.txid for t in txs]), ts, PARAMS.pow_limit_bits)
    solved = mine_header(header)
    assert solved is not None
    return Block(solved, txs)


def spend(txid: bytes, value: int = 1) -> Transaction:
    return Transaction((TxIn(OutPoint(txid, 0), b"sig"),), (TxOut(value, b"pk"),))


def test_header_serialization_roundtrip() -> None:
    h = BlockHeader(b"\x01" * 32, b"\x02" * 32, 123456789, 0x1F00FFFF, 42)
    raw = h.serialize()
    assert len(raw) == 88
    assert BlockHeader.deserialize(raw) == h
    assert h.hash == sha256d(raw)


def test_block_serialization_roundtrip() -> None:
    cb = make_coinbase(1, (TxOut(50, b"\x51"),))
    block = make_block((cb, spend(b"\x07" * 32)))
    assert Block.deserialize(block.serialize()) == block
    with pytest.raises(DecodeError):
        Block.deserialize(block.serialize() + b"\x00")


def test_mined_block_passes_checks() -> None:
    block = make_block((make_coinbase(1, (TxOut(50, b"\x51"),)),))
    check_block(block, PARAMS)
    assert block.header.check_pow()


def test_mine_header_gives_up() -> None:
    impossible = BlockHeader(bytes(32), bytes(32), 0, 0x03000001)
    assert mine_header(impossible, count=500) is None


def test_genesis_is_deterministic() -> None:
    assert make_genesis(MAIN).hash == make_genesis(MAIN).hash
    assert make_genesis(MAIN).txs[0].is_coinbase


@pytest.mark.parametrize(
    ("mutate", "code"),
    [
        (lambda b: Block(b.header, ()), "bad-blk-empty"),
        (lambda b: Block(b.header, b.txs[1:]), "bad-cb-missing"),
        (lambda b: Block(b.header, (*b.txs, b.txs[0])), "bad-cb-multiple"),
        (lambda b: Block(b.header, (*b.txs, b.txs[1])), "bad-txns-duplicate"),
        (lambda b: Block(b.header, b.txs[:1]), "bad-merkle"),
    ],
)
def test_structural_failures(mutate: object, code: str) -> None:
    cb = make_coinbase(1, (TxOut(50, b"\x51"),))
    block = make_block((cb, spend(b"\x07" * 32)))
    bad = mutate(block)  # type: ignore[operator]
    # Keep the PoW valid so the specific rule under test is what fails.
    if bad.txs:
        bad = Block(replace(bad.header, merkle_root=block.header.merkle_root), bad.txs)
    header = mine_header(bad.header)
    assert header is not None
    with pytest.raises(ValidationError) as exc:
        check_block(Block(header, bad.txs), PARAMS)
    assert exc.value.code == code


def test_tx_level_failures() -> None:
    cb = make_coinbase(1, (TxOut(50, b"\x51"),))
    no_outputs = Transaction((TxIn(OutPoint(b"\x01" * 32, 0)),), ())
    with pytest.raises(ValidationError, match="vout-empty"):
        check_block(make_block((cb, no_outputs)), PARAMS)
    dup_in = Transaction((TxIn(OutPoint(b"\x01" * 32, 0)),) * 2, (TxOut(1, b""),))
    with pytest.raises(ValidationError, match="inputs-duplicate"):
        check_block(make_block((cb, dup_in)), PARAMS)
    null_in = Transaction(
        (TxIn(OutPoint.null()), TxIn(OutPoint(b"\x02" * 32, 0))), (TxOut(1, b""),)
    )
    with pytest.raises(ValidationError, match="prevout-null"):
        check_block(make_block((cb, null_in)), PARAMS)


def test_bits_above_pow_limit_rejected() -> None:
    cb = make_coinbase(1, (TxOut(50, b"\x51"),))
    easy = BlockHeader(bytes(32), merkle_root([cb.txid]), 0, 0x2100FFFF)
    solved = mine_header(easy)
    assert solved is not None
    with pytest.raises(ValidationError, match="bad-bits"):
        check_block(Block(solved, (cb,)), PARAMS)


def test_oversized_block_rejected() -> None:
    tiny = PARAMS.with_overrides(max_block_size=200)
    cb = make_coinbase(1, (TxOut(50, b"\x51" * 300),))
    with pytest.raises(ValidationError, match="bad-blk-size"):
        check_block(make_block((cb,)), tiny)


def test_coinbase_height() -> None:
    assert make_coinbase(1234, (TxOut(1, b""),)).coinbase_height() == 1234
    assert spend(b"\x01" * 32).coinbase_height() is None


# --- property-based: any tampering with a valid block is detected -------------------------

VALID = make_block((make_coinbase(7, (TxOut(50, b"\x51"),)), spend(b"\x09" * 32, 3)), ts=99)

header_fields = st.sampled_from(["prev_hash", "merkle_root", "timestamp", "nonce"])


@settings(max_examples=200)
@given(header_fields, st.integers(min_value=1, max_value=2**32))
def test_header_tampering_is_detected(field: str, delta: int) -> None:
    value = getattr(VALID.header, field)
    if isinstance(value, bytes):
        idx = delta % 32
        mutated = bytearray(value)
        mutated[idx] ^= (delta % 255) + 1
        new_value: object = bytes(mutated)
    else:
        new_value = value + delta
    header = replace(VALID.header, **{field: new_value})
    block = Block(header, VALID.txs)
    if field == "merkle_root":
        with pytest.raises(ValidationError, match=r"high-hash|bad-merkle"):
            check_block(block, PARAMS)
    elif not header.check_pow():
        with pytest.raises(ValidationError, match="high-hash"):
            check_block(block, PARAMS)
    else:
        # A lucky mutation can satisfy PoW (p ~ 1/256): that is a different, valid block.
        check_block(block, PARAMS)


@settings(max_examples=100)
@given(st.integers(min_value=0, max_value=len(VALID.serialize()) - 1), st.integers(1, 255))
def test_byte_flip_never_yields_same_valid_block(pos: int, xor: int) -> None:
    raw = bytearray(VALID.serialize())
    raw[pos] ^= xor
    try:
        block = Block.deserialize(bytes(raw))
    except (DecodeError, ValueError):
        return
    if block.hash == VALID.hash and block.txs == VALID.txs:
        pytest.fail("mutation produced an identical block")
    try:
        check_block(block, PARAMS)
    except ValidationError:
        return
    # Survivors must differ in a way the merkle commitment covers: header-only changes
    # that still satisfy PoW (rare) keep the same txs, everything else is caught.
    assert block.txs == VALID.txs
