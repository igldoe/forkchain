"""Standard script templates, their unlocking scripts and a classifier.

| template      | locking script (scriptPubKey)                                       |
|---------------|---------------------------------------------------------------------|
| P2PKH         | DUP HASH <pkh> EQUALVERIFY CHECKSIG                                 |
| multisig m/n  | OP_m <pk_1> .. <pk_n> OP_n CHECKMULTISIG                            |
| hash-lock     | HASH <h> EQUALVERIFY DUP HASH <pkh> EQUALVERIFY CHECKSIG            |
| time-lock     | <height> CHECKLOCKTIME DROP DUP HASH <pkh> EQUALVERIFY CHECKSIG     |
| HTLC          | IF <hash-lock branch> ELSE <time-lock branch> ENDIF ...             |
"""

from __future__ import annotations

from collections.abc import Sequence

from forkchain.keys import PublicKey, address_from_hash
from forkchain.script.opcodes import (
    SMALL_INT_OPS,
    Op,
    ScriptParseError,
    Token,
    assemble,
    push_data,
    push_int,
    tokenize,
)


def _pkh_check(pubkey_hash: bytes) -> bytes:
    return assemble(Op.DUP, Op.HASH, push_data(pubkey_hash), Op.EQUALVERIFY, Op.CHECKSIG)


def p2pkh(pubkey_hash: bytes) -> bytes:
    """Pay-to-pubkey-hash: the spender reveals a key hashing to ``pubkey_hash`` and signs."""
    return _pkh_check(pubkey_hash)


def p2pkh_unlock(signature: bytes, pubkey: PublicKey) -> bytes:
    return assemble(push_data(signature), push_data(pubkey.raw))


def multisig(m: int, pubkeys: Sequence[PublicKey]) -> bytes:
    """Bare m-of-n multisig. Signatures must be supplied in key order."""
    if not 1 <= m <= len(pubkeys) <= 16:
        raise ValueError("need 1 <= m <= n <= 16")
    return assemble(
        push_int(m), *(push_data(k.raw) for k in pubkeys), push_int(len(pubkeys)), Op.CHECKMULTISIG
    )


def multisig_unlock(signatures: Sequence[bytes]) -> bytes:
    return assemble(*(push_data(s) for s in signatures))


def hashlock(digest: bytes, pubkey_hash: bytes | None = None) -> bytes:
    """Spendable by whoever reveals a preimage of ``digest`` (``HASH`` = truncated SHA-256).

    Without ``pubkey_hash`` anyone who sees the preimage in the mempool can race the
    rightful spender with their own transaction, so the keyed form is the useful one.
    """
    lock = assemble(Op.HASH, push_data(digest), Op.EQUALVERIFY if pubkey_hash else Op.EQUAL)
    return lock + _pkh_check(pubkey_hash) if pubkey_hash else lock


def hashlock_unlock(
    preimage: bytes, signature: bytes | None = None, pubkey: PublicKey | None = None
) -> bytes:
    if signature is None or pubkey is None:
        return push_data(preimage)
    return assemble(push_data(signature), push_data(pubkey.raw), push_data(preimage))


def timelock(height: int, pubkey_hash: bytes) -> bytes:
    """Spendable by ``pubkey_hash`` only by a transaction with ``locktime >= height``."""
    return assemble(push_int(height), Op.CHECKLOCKTIME, Op.DROP) + _pkh_check(pubkey_hash)


def htlc(digest: bytes, recipient_pkh: bytes, refund_pkh: bytes, timeout: int) -> bytes:
    """Hashed time-locked contract: recipient claims with the preimage, or the sender takes
    the coins back after ``timeout``. The building block of payment channels and atomic
    swaps."""
    return assemble(
        Op.IF,
        Op.HASH, push_data(digest), Op.EQUALVERIFY,
        Op.DUP, Op.HASH, push_data(recipient_pkh),
        Op.ELSE,
        push_int(timeout), Op.CHECKLOCKTIME, Op.DROP,
        Op.DUP, Op.HASH, push_data(refund_pkh),
        Op.ENDIF,
        Op.EQUALVERIFY, Op.CHECKSIG,
    )  # fmt: skip


def htlc_claim(signature: bytes, pubkey: PublicKey, preimage: bytes) -> bytes:
    return assemble(push_data(signature), push_data(pubkey.raw), push_data(preimage), push_int(1))


def htlc_refund(signature: bytes, pubkey: PublicKey) -> bytes:
    return assemble(push_data(signature), push_data(pubkey.raw), push_int(0))


# -- introspection ---------------------------------------------------------------------------


def _shape(tokens: Sequence[Token]) -> list[object]:
    """Replace pushes by their size so templates can be matched structurally."""
    return [len(t.data) if t.data is not None else t.opcode for t in tokens]


def classify(script: bytes) -> str:
    try:
        tokens = list(tokenize(script))
    except ScriptParseError:
        return "nonstandard"
    shape = _shape(tokens)
    pkh = [Op.DUP, Op.HASH, 20, Op.EQUALVERIFY, Op.CHECKSIG]
    if shape == pkh:
        return "p2pkh"
    if shape[:3] == [Op.HASH, 20, Op.EQUALVERIFY] and shape[3:] == pkh:
        return "hashlock"
    if shape == [Op.HASH, 20, Op.EQUAL]:
        return "hashlock-anyone"
    if len(shape) >= 3 and shape[1:3] == [Op.CHECKLOCKTIME, Op.DROP] and shape[3:] == pkh:
        return "timelock"
    if shape and shape[0] == Op.IF and Op.CHECKLOCKTIME in shape and Op.ELSE in shape:
        return "htlc"
    if (
        len(tokens) >= 4
        and tokens[-1].opcode == Op.CHECKMULTISIG
        and tokens[0].opcode in SMALL_INT_OPS
        and tokens[-2].opcode in SMALL_INT_OPS
        and all(t.data is not None and len(t.data) == 32 for t in tokens[1:-2])
    ):
        m, n = tokens[0].opcode - Op.OP_1 + 1, tokens[-2].opcode - Op.OP_1 + 1
        if n == len(tokens) - 3 and m <= n:
            return f"multisig-{m}-of-{n}"
    if not script:
        return "empty"
    return "nonstandard"


def address_of(script: bytes) -> str | None:
    """The address a P2PKH script pays to, if it is one."""
    if classify(script) != "p2pkh":
        return None
    data = next(t.data for t in tokenize(script) if t.data is not None)
    return address_from_hash(data)


def disassemble(script: bytes) -> list[dict[str, str]]:
    """Token-by-token view for humans: ``[{"op": "DUP"}, {"op": "PUSH(20)", "data": ...}]``."""
    out: list[dict[str, str]] = []
    try:
        for token in tokenize(script):
            item = {"op": token.name()}
            if token.data:
                item["data"] = token.data.hex()
            out.append(item)
    except ScriptParseError as exc:
        out.append({"op": "ERROR", "data": str(exc)})
    return out


def disassemble_str(script: bytes) -> str:
    return " ".join(f"<{t['data']}>" if "data" in t else t["op"] for t in disassemble(script))
