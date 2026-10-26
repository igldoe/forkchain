"""ed25519 keys and human-readable addresses."""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from forkchain.crypto import SHORT_HASH_SIZE, hash160, sha256d

PUBKEY_SIZE = 32
SIGNATURE_SIZE = 64
ADDRESS_PREFIX = "fc"
_CHECKSUM_SIZE = 4


@dataclass(frozen=True)
class PublicKey:
    raw: bytes

    def __post_init__(self) -> None:
        if len(self.raw) != PUBKEY_SIZE:
            raise ValueError("ed25519 public keys are 32 bytes")

    def verify(self, signature: bytes, message: bytes) -> bool:
        if len(signature) != SIGNATURE_SIZE:
            return False
        try:
            Ed25519PublicKey.from_public_bytes(self.raw).verify(signature, message)
        except (InvalidSignature, ValueError):
            return False
        return True

    @property
    def pubkey_hash(self) -> bytes:
        return hash160(self.raw)

    @property
    def address(self) -> str:
        return address_from_hash(self.pubkey_hash)


class PrivateKey:
    __slots__ = ("_key",)

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key

    @classmethod
    def generate(cls) -> PrivateKey:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_bytes(cls, raw: bytes) -> PrivateKey:
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    @classmethod
    def from_seed(cls, seed: str) -> PrivateKey:
        """Deterministic key for tests and simulations. Never use for anything real."""
        return cls.from_bytes(sha256d(seed.encode()))

    def to_bytes(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import NoEncryption, PrivateFormat

        return self._key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def __repr__(self) -> str:  # never leak key material into logs
        return f"PrivateKey(address={self.public_key.address})"


def address_from_hash(pubkey_hash: bytes) -> str:
    checksum = sha256d(pubkey_hash)[:_CHECKSUM_SIZE]
    return ADDRESS_PREFIX + (pubkey_hash + checksum).hex()


def hash_from_address(address: str) -> bytes:
    if not address.startswith(ADDRESS_PREFIX):
        raise ValueError(f"address must start with {ADDRESS_PREFIX!r}")
    try:
        payload = bytes.fromhex(address[len(ADDRESS_PREFIX) :])
    except ValueError as exc:
        raise ValueError("address is not hex") from exc
    if len(payload) != SHORT_HASH_SIZE + _CHECKSUM_SIZE:
        raise ValueError("address has wrong length")
    pubkey_hash, checksum = payload[:SHORT_HASH_SIZE], payload[SHORT_HASH_SIZE:]
    if sha256d(pubkey_hash)[:_CHECKSUM_SIZE] != checksum:
        raise ValueError("address checksum mismatch")
    return pubkey_hash
