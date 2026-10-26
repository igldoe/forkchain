import pytest

from forkchain.keys import PrivateKey, PublicKey, address_from_hash, hash_from_address


def test_sign_and_verify() -> None:
    key = PrivateKey.generate()
    sig = key.sign(b"msg")
    assert key.public_key.verify(sig, b"msg")
    assert not key.public_key.verify(sig, b"other")
    assert not key.public_key.verify(sig[:-1], b"msg")
    assert not PrivateKey.generate().public_key.verify(sig, b"msg")


def test_key_roundtrip_and_seed_determinism() -> None:
    key = PrivateKey.from_seed("x")
    assert PrivateKey.from_bytes(key.to_bytes()).public_key == key.public_key
    assert PrivateKey.from_seed("x").public_key == key.public_key
    assert "address=" in repr(key)
    assert key.to_bytes().hex() not in repr(key)


def test_address_roundtrip() -> None:
    pub = PrivateKey.from_seed("a").public_key
    assert hash_from_address(pub.address) == pub.pubkey_hash
    assert pub.address == address_from_hash(pub.pubkey_hash)


@pytest.mark.parametrize(
    ("mangle", "error"),
    [
        (lambda a: "xx" + a[2:], "start with"),
        (lambda a: a[:-1] + ("0" if a[-1] != "0" else "1"), "checksum"),
        (lambda a: a[:-2], "length"),
        (lambda a: a[:-1] + "z", "hex"),
    ],
)
def test_bad_addresses(mangle: object, error: str) -> None:
    addr = PrivateKey.from_seed("a").public_key.address
    with pytest.raises(ValueError, match=error):
        hash_from_address(mangle(addr))  # type: ignore[operator]


def test_pubkey_size_enforced() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        PublicKey(b"\x00" * 31)


def test_verify_garbage_pubkey_does_not_raise() -> None:
    # Not every 32-byte string is a valid curve point; verification must just fail.
    assert not PublicKey(b"\xff" * 32).verify(b"\x00" * 64, b"m")
