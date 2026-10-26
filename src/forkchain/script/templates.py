"""Standard script templates."""

from __future__ import annotations

from forkchain.keys import PublicKey
from forkchain.script.opcodes import Op, assemble, push_data


def p2pkh(pubkey_hash: bytes) -> bytes:
    """Pay-to-pubkey-hash: ``DUP HASH <pkh> EQUALVERIFY CHECKSIG``."""
    return assemble(Op.DUP, Op.HASH, push_data(pubkey_hash), Op.EQUALVERIFY, Op.CHECKSIG)


def p2pkh_unlock(signature: bytes, pubkey: PublicKey) -> bytes:
    return assemble(push_data(signature), push_data(pubkey.raw))
