"""Hash functions used across the protocol."""

from __future__ import annotations

import hashlib

HASH_SIZE = 32
SHORT_HASH_SIZE = 20
ZERO_HASH = bytes(HASH_SIZE)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    """Double SHA-256, as used by Bitcoin for block and transaction ids."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """SHA-256 truncated to 160 bits.

    Stand-in for Bitcoin's RIPEMD160(SHA256(x)): RIPEMD-160 is not reliably available in
    modern OpenSSL builds, and for an educational chain a truncated SHA-256 gives the same
    shape (short, collision-resistant public key / script hashes).
    """
    return hashlib.sha256(data).digest()[:SHORT_HASH_SIZE]
