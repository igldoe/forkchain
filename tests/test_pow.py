import pytest
from hypothesis import given
from hypothesis import strategies as st

from forkchain.params import MAIN, REGTEST
from forkchain.pow import (
    bits_to_target,
    block_work,
    difficulty,
    hash_meets_target,
    retarget,
    target_to_bits,
)


def test_known_bitcoin_genesis_bits() -> None:
    assert bits_to_target(0x1D00FFFF) == 0xFFFF * 2 ** (8 * (0x1D - 3))
    assert target_to_bits(bits_to_target(0x1D00FFFF)) == 0x1D00FFFF


@given(st.integers(min_value=1, max_value=2**255))
def test_compact_roundtrip_is_lossy_but_stable(target: int) -> None:
    bits = target_to_bits(target)
    decoded = bits_to_target(bits)
    assert decoded <= target  # compact form truncates, never rounds up
    assert target_to_bits(decoded) == bits
    assert bits & 0x00800000 == 0


def test_negative_and_zero_targets_rejected() -> None:
    with pytest.raises(ValueError, match="negative"):
        bits_to_target(0x04923456)
    with pytest.raises(ValueError, match="positive"):
        target_to_bits(0)


def test_small_exponent() -> None:
    assert bits_to_target(0x01120000) == 0x12
    assert bits_to_target(0x02123400) == 0x1234


def test_work_is_monotonic_in_difficulty() -> None:
    easy, hard = MAIN.pow_limit_bits, MAIN.genesis_bits
    assert block_work(hard) > block_work(easy)
    assert difficulty(MAIN.pow_limit_bits, MAIN) == 1.0


def test_hash_meets_target() -> None:
    assert hash_meets_target(bytes(32), 0x1D00FFFF)
    assert not hash_meets_target(b"\xff" * 32, 0x1D00FFFF)


def test_retarget_on_schedule_keeps_bits() -> None:
    expected = MAIN.target_block_time_ms * MAIN.retarget_interval
    assert retarget(MAIN, MAIN.genesis_bits, expected) == MAIN.genesis_bits


def test_retarget_fast_blocks_make_it_harder() -> None:
    expected = MAIN.target_block_time_ms * MAIN.retarget_interval
    new = retarget(MAIN, MAIN.genesis_bits, expected // 2)
    assert bits_to_target(new) < bits_to_target(MAIN.genesis_bits)
    assert bits_to_target(new) == pytest.approx(bits_to_target(MAIN.genesis_bits) / 2, rel=1e-3)


def test_retarget_is_clamped() -> None:
    expected = MAIN.target_block_time_ms * MAIN.retarget_interval
    clamped = retarget(MAIN, MAIN.genesis_bits, 1)
    quarter = retarget(MAIN, MAIN.genesis_bits, expected // 4)
    assert clamped == quarter


def test_retarget_never_exceeds_pow_limit() -> None:
    expected = REGTEST.target_block_time_ms * REGTEST.retarget_interval
    assert retarget(REGTEST, REGTEST.pow_limit_bits, expected * 100) == REGTEST.pow_limit_bits
