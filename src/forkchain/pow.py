"""Proof-of-work arithmetic: compact targets, chain work and difficulty retargeting."""

from __future__ import annotations

from forkchain.params import ConsensusParams

MAX_TARGET = 2**256 - 1


def bits_to_target(bits: int) -> int:
    """Decode Bitcoin's compact ``nBits`` representation into a 256-bit target."""
    exponent = bits >> 24
    mantissa = bits & 0x007FFFFF
    if bits & 0x00800000:
        raise ValueError("negative compact target")
    target = mantissa >> 8 * (3 - exponent) if exponent <= 3 else mantissa << 8 * (exponent - 3)
    if target > MAX_TARGET:
        raise ValueError("compact target overflows 256 bits")
    return target


def target_to_bits(target: int) -> int:
    if target <= 0:
        raise ValueError("target must be positive")
    size = (target.bit_length() + 7) // 8
    mantissa = target << 8 * (3 - size) if size <= 3 else target >> 8 * (size - 3)
    if mantissa & 0x00800000:
        # The high mantissa bit is a sign bit in compact form; shift to keep it clear.
        mantissa >>= 8
        size += 1
    return (size << 24) | mantissa


def block_work(bits: int) -> int:
    """Expected number of hashes needed to find a block at this target."""
    return (1 << 256) // (bits_to_target(bits) + 1)


def hash_meets_target(block_hash: bytes, bits: int) -> bool:
    return int.from_bytes(block_hash, "big") <= bits_to_target(bits)


def difficulty(bits: int, params: ConsensusParams) -> float:
    """Human-friendly difficulty: how many times harder than the easiest allowed target."""
    return bits_to_target(params.pow_limit_bits) / bits_to_target(bits)


def retarget(params: ConsensusParams, prev_bits: int, actual_timespan_ms: int) -> int:
    """Scale the target so that the next window takes about ``target_block_time`` per block.

    The measured timespan is clamped to ``[T/f, T*f]`` (``f = max_retarget_factor``) so that
    a single window with bogus timestamps cannot swing difficulty arbitrarily.
    """
    expected = params.target_block_time_ms * params.retarget_interval
    factor = params.max_retarget_factor
    timespan = min(max(actual_timespan_ms, expected // factor), expected * factor)
    new_target = bits_to_target(prev_bits) * timespan // expected
    limit = bits_to_target(params.pow_limit_bits)
    new_target = max(1, min(new_target, limit))
    return target_to_bits(new_target)
