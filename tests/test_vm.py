"""Script VM: every standard template gets its own group of positive and negative cases."""

from __future__ import annotations

import contextlib
from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from forkchain.crypto import hash160
from forkchain.keys import PrivateKey, PublicKey
from forkchain.script import templates as tpl
from forkchain.script.opcodes import Op, assemble, push_data, push_int
from forkchain.script.vm import (
    ExecContext,
    Limits,
    ScriptError,
    TraceStep,
    verify_input,
    verify_script,
)
from forkchain.tx import OutPoint, Transaction, TxIn, TxOut

ALICE, BOB, CAROL, MALLORY = (PrivateKey.from_seed(n) for n in ("alice", "bob", "carol", "mallory"))
SECRET = b"open sesame"
DIGEST = hash160(SECRET)


def spending_tx(locktime: int = 0) -> Transaction:
    return Transaction(
        (TxIn(OutPoint(b"\x11" * 32, 0)),), (TxOut(1000, b"\x51"),), locktime=locktime
    )


def sign(key: PrivateKey, tx: Transaction, lock: bytes, value: int = 5000) -> bytes:
    return key.sign(tx.sighash(0, lock, value))


def run(unlock: bytes, lock: bytes, tx: Transaction, value: int = 5000) -> None:
    final = replace(tx, inputs=(replace(tx.inputs[0], script_sig=unlock),))
    verify_script(unlock, lock, ExecContext(final, 0, TxOut(value, lock)))


def code(unlock: bytes, lock: bytes, tx: Transaction) -> str:
    with pytest.raises(ScriptError) as exc:
        run(unlock, lock, tx)
    return exc.value.code


# -- P2PKH ----------------------------------------------------------------------------------


class TestP2PKH:
    lock = tpl.p2pkh(ALICE.public_key.pubkey_hash)

    def test_valid(self) -> None:
        tx = spending_tx()
        run(tpl.p2pkh_unlock(sign(ALICE, tx, self.lock), ALICE.public_key), self.lock, tx)

    def test_wrong_pubkey(self) -> None:
        tx = spending_tx()
        unlock = tpl.p2pkh_unlock(sign(BOB, tx, self.lock), BOB.public_key)
        assert code(unlock, self.lock, tx) == "equalverify"

    def test_signature_by_other_key(self) -> None:
        tx = spending_tx()
        unlock = tpl.p2pkh_unlock(sign(BOB, tx, self.lock), ALICE.public_key)
        assert code(unlock, self.lock, tx) == "eval-false"

    def test_signature_bound_to_amount(self) -> None:
        tx = spending_tx()
        sig = sign(ALICE, tx, self.lock, value=4999)  # signed for a different spent value
        assert code(tpl.p2pkh_unlock(sig, ALICE.public_key), self.lock, tx) == "eval-false"

    def test_non_push_script_sig(self) -> None:
        tx = spending_tx()
        unlock = tpl.p2pkh_unlock(sign(ALICE, tx, self.lock), ALICE.public_key) + bytes([Op.DUP])
        assert code(unlock, self.lock, tx) == "sig-pushonly"


# -- 2-of-3 multisig ------------------------------------------------------------------------


class TestMultisig:
    keys = (ALICE.public_key, BOB.public_key, CAROL.public_key)
    lock = tpl.multisig(2, keys)

    def sigs(self, tx: Transaction, *signers: PrivateKey) -> bytes:
        return tpl.multisig_unlock([sign(k, tx, self.lock) for k in signers])

    @pytest.mark.parametrize("pair", [(ALICE, BOB), (ALICE, CAROL), (BOB, CAROL)])
    def test_any_two_in_order(self, pair: tuple[PrivateKey, PrivateKey]) -> None:
        tx = spending_tx()
        run(self.sigs(tx, *pair), self.lock, tx)

    def test_one_signature_is_not_enough(self) -> None:
        tx = spending_tx()
        assert code(self.sigs(tx, ALICE), self.lock, tx) == "stack-underflow"

    def test_wrong_order_fails(self) -> None:
        tx = spending_tx()
        assert code(self.sigs(tx, CAROL, ALICE), self.lock, tx) == "eval-false"

    def test_same_signer_twice_fails(self) -> None:
        tx = spending_tx()
        assert code(self.sigs(tx, ALICE, ALICE), self.lock, tx) == "eval-false"

    def test_outsider_signature_fails(self) -> None:
        tx = spending_tx()
        assert code(self.sigs(tx, ALICE, MALLORY), self.lock, tx) == "eval-false"

    def test_template_bounds_and_classification(self) -> None:
        with pytest.raises(ValueError, match="m <= n"):
            tpl.multisig(3, self.keys[:2])
        assert tpl.classify(self.lock) == "multisig-2-of-3"

    def test_m_greater_than_n_in_raw_script(self) -> None:
        lock = assemble(push_int(3), push_data(ALICE.public_key.raw), push_int(1), Op.CHECKMULTISIG)
        assert code(b"", lock, spending_tx()) == "sig-count"


# -- hash-lock ------------------------------------------------------------------------------


class TestHashlock:
    lock = tpl.hashlock(DIGEST, BOB.public_key.pubkey_hash)

    def test_preimage_and_signature(self) -> None:
        tx = spending_tx()
        run(tpl.hashlock_unlock(SECRET, sign(BOB, tx, self.lock), BOB.public_key), self.lock, tx)

    def test_wrong_preimage(self) -> None:
        tx = spending_tx()
        unlock = tpl.hashlock_unlock(b"guess", sign(BOB, tx, self.lock), BOB.public_key)
        assert code(unlock, self.lock, tx) == "equalverify"

    def test_preimage_without_key_cannot_steal(self) -> None:
        tx = spending_tx()
        unlock = tpl.hashlock_unlock(SECRET, sign(MALLORY, tx, self.lock), MALLORY.public_key)
        assert code(unlock, self.lock, tx) == "equalverify"

    def test_anyone_can_spend_variant(self) -> None:
        lock = tpl.hashlock(DIGEST)
        assert tpl.classify(lock) == "hashlock-anyone"
        run(tpl.hashlock_unlock(SECRET), lock, spending_tx())
        assert code(tpl.hashlock_unlock(b"nope"), lock, spending_tx()) == "eval-false"

    def test_classification(self) -> None:
        assert tpl.classify(self.lock) == "hashlock"


# -- time-lock ------------------------------------------------------------------------------


class TestTimelock:
    lock = tpl.timelock(500, ALICE.public_key.pubkey_hash)

    def unlock(self, tx: Transaction) -> bytes:
        return tpl.p2pkh_unlock(sign(ALICE, tx, self.lock), ALICE.public_key)

    @pytest.mark.parametrize("locktime", [500, 501, 10_000])
    def test_spendable_once_tx_is_locked(self, locktime: int) -> None:
        tx = spending_tx(locktime)
        run(self.unlock(tx), self.lock, tx)

    def test_locktime_too_low(self) -> None:
        tx = spending_tx(499)
        assert code(self.unlock(tx), self.lock, tx) == "locktime"

    def test_changing_locktime_after_signing_breaks_signature(self) -> None:
        tx = spending_tx(400)
        unlock = self.unlock(tx)
        assert code(unlock, self.lock, replace(tx, locktime=600)) == "eval-false"

    def test_still_needs_right_key(self) -> None:
        tx = spending_tx(600)
        unlock = tpl.p2pkh_unlock(sign(BOB, tx, self.lock), BOB.public_key)
        assert code(unlock, self.lock, tx) == "equalverify"

    def test_classification_and_small_heights(self) -> None:
        assert tpl.classify(self.lock) == "timelock"
        assert tpl.classify(tpl.timelock(7, ALICE.public_key.pubkey_hash)) == "timelock"


# -- HTLC (hash-lock OR time-lock refund) ---------------------------------------------------


class TestHTLC:
    lock = tpl.htlc(DIGEST, BOB.public_key.pubkey_hash, ALICE.public_key.pubkey_hash, 100)

    def test_claim_with_preimage(self) -> None:
        tx = spending_tx()
        run(tpl.htlc_claim(sign(BOB, tx, self.lock), BOB.public_key, SECRET), self.lock, tx)

    def test_refund_after_timeout(self) -> None:
        tx = spending_tx(100)
        run(tpl.htlc_refund(sign(ALICE, tx, self.lock), ALICE.public_key), self.lock, tx)

    def test_refund_too_early(self) -> None:
        tx = spending_tx(99)
        unlock = tpl.htlc_refund(sign(ALICE, tx, self.lock), ALICE.public_key)
        assert code(unlock, self.lock, tx) == "locktime"

    def test_recipient_cannot_use_refund_path(self) -> None:
        tx = spending_tx(100)
        unlock = tpl.htlc_refund(sign(BOB, tx, self.lock), BOB.public_key)
        assert code(unlock, self.lock, tx) == "equalverify"

    def test_classification(self) -> None:
        assert tpl.classify(self.lock) == "htlc"


# -- limits and edge cases ------------------------------------------------------------------


def test_script_size_limit() -> None:
    lock = bytes([Op.OP_1]) * 1001
    assert code(b"", lock, spending_tx()) == "script-size"


def test_op_count_limit() -> None:
    lock = bytes([Op.OP_1]) + bytes([Op.DUP, Op.DROP]) * 51
    assert code(b"", lock, spending_tx()) == "op-count"
    run(b"", bytes([Op.OP_1]) + bytes([Op.DUP, Op.DROP]) * 49, spending_tx())


def test_multisig_keys_count_towards_op_limit() -> None:
    keys = [ALICE.public_key] * 16
    lock = tpl.multisig(1, keys)
    tight = Limits(max_ops=10)
    with pytest.raises(ScriptError, match="op-count"):
        verify_script(b"", lock, ExecContext(spending_tx(), 0, TxOut(1, lock)), limits=tight)


def test_stack_depth_limit() -> None:
    assert code(b"", bytes([Op.OP_1]) * 101, spending_tx()) == "stack-size"


def test_element_size_limit() -> None:
    assert code(push_data(b"x" * 521), bytes([Op.OP_1]), spending_tx()) == "push-size"


def test_num_overflow() -> None:
    lock = assemble(push_data(b"\x01" * 9), Op.CHECKLOCKTIME)
    assert code(b"", lock, spending_tx()) == "num-overflow"


@pytest.mark.parametrize(
    ("lock", "expected"),
    [
        (bytes([Op.RETURN]), "op-return"),
        (bytes([0xFE]), "bad-opcode"),
        (bytes([Op.OP_1, Op.IF]), "unbalanced-conditional"),
        (bytes([Op.ENDIF]), "unbalanced-conditional"),
        (bytes([Op.ELSE]), "unbalanced-conditional"),
        (bytes([Op.DROP]), "stack-underflow"),
        (bytes([Op.CHECKLOCKTIME]), "stack-underflow"),
        (bytes([Op.OP_0, Op.VERIFY]), "verify"),
        (b"\x05ab", "bad-encoding"),
        (b"", "eval-false"),
    ],
)
def test_failure_modes(lock: bytes, expected: str) -> None:
    assert code(b"", lock, spending_tx()) == expected


def test_nested_dead_branch_stays_dead() -> None:
    # OP_0 IF  OP_1 IF RETURN ELSE RETURN ENDIF  ENDIF OP_1
    lock = bytes(
        [Op.OP_0, Op.IF, Op.OP_1, Op.IF, Op.RETURN, Op.ELSE, Op.RETURN, Op.ENDIF, Op.ENDIF, Op.OP_1]
    )
    run(b"", lock, spending_tx())


def test_swap_and_checksigverify() -> None:
    tx = spending_tx()
    # <sig> <junk> | SWAP <pk> CHECKSIGVERIFY  -> leaves <junk> (truthy) on the stack
    lock = assemble(Op.SWAP, push_data(ALICE.public_key.raw), Op.CHECKSIGVERIFY)
    sig = sign(ALICE, tx, lock)
    run(assemble(push_data(sig), push_data(b"junk")), lock, tx)
    bad = assemble(push_data(sign(BOB, tx, lock)), push_data(b"junk"))
    assert code(bad, lock, tx) == "checksigverify"


def test_checksig_with_malformed_pubkey_is_false() -> None:
    lock = assemble(push_data(b"\x02" * 33), Op.CHECKSIG)
    assert code(push_data(b"\x00" * 64), lock, spending_tx()) == "eval-false"


def test_checksig_requires_context() -> None:
    lock = tpl.p2pkh(ALICE.public_key.pubkey_hash)
    with pytest.raises(ScriptError, match="no-context"):
        verify_script(tpl.p2pkh_unlock(b"\x00" * 64, ALICE.public_key), lock, None)


def test_trace_records_each_step() -> None:
    tx = spending_tx()
    lock = TestP2PKH.lock
    unlock = tpl.p2pkh_unlock(sign(ALICE, tx, lock), ALICE.public_key)
    final = replace(tx, inputs=(replace(tx.inputs[0], script_sig=unlock),))
    trace: list[TraceStep] = []
    verify_script(unlock, lock, ExecContext(final, 0, TxOut(5000, lock)), trace=trace)
    assert [s.op for s in trace] == [
        "PUSH(64)",
        "PUSH(32)",
        "DUP",
        "HASH",
        "PUSH(20)",
        "EQUALVERIFY",
        "CHECKSIG",
    ]
    assert trace[-1].stack == ("01",)
    assert {s.phase for s in trace} == {"unlock", "lock"}


def test_verify_input_wrapper() -> None:
    lock = tpl.p2pkh(ALICE.public_key.pubkey_hash)
    tx = spending_tx()
    signed = replace(
        tx,
        inputs=(
            replace(
                tx.inputs[0], script_sig=tpl.p2pkh_unlock(sign(ALICE, tx, lock), ALICE.public_key)
            ),
        ),
    )
    assert verify_input(signed, 0, TxOut(5000, lock))
    assert not verify_input(signed, 0, TxOut(5001, lock))


def test_disassembly_and_address() -> None:
    lock = tpl.p2pkh(ALICE.public_key.pubkey_hash)
    text = tpl.disassemble_str(lock)
    assert text.startswith("DUP HASH <")
    assert text.endswith("> EQUALVERIFY CHECKSIG")
    assert tpl.address_of(lock) == ALICE.public_key.address
    assert tpl.address_of(tpl.hashlock(DIGEST)) is None
    assert tpl.disassemble(b"\x05ab")[-1]["op"] == "ERROR"
    assert tpl.classify(b"") == "empty"
    assert tpl.classify(b"\x05ab") == "nonstandard"
    assert tpl.classify(bytes([Op.OP_1])) == "nonstandard"


@settings(max_examples=500)
@given(st.binary(max_size=200), st.binary(max_size=200))
def test_vm_never_crashes_on_garbage(unlock: bytes, lock: bytes) -> None:
    with contextlib.suppress(ScriptError):
        verify_script(unlock, lock, ExecContext(spending_tx(), 0, TxOut(1, lock)))


@settings(max_examples=200)
@given(
    st.lists(st.sampled_from([*Op, 0xFE]), max_size=40),
    st.lists(st.binary(max_size=40), max_size=5),
)
def test_vm_never_crashes_on_opcode_soup(ops: list[int], pushes: list[bytes]) -> None:
    lock = b"".join(push_data(p) for p in pushes) + bytes(int(o) for o in ops)
    with contextlib.suppress(ScriptError):
        verify_script(b"", lock, ExecContext(spending_tx(), 0, TxOut(1, lock)))


def test_pubkey_helper_types() -> None:
    assert isinstance(ALICE.public_key, PublicKey)
