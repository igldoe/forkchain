"""A small stack machine in the spirit of Bitcoin Script.

An input is valid when running its ``script_sig`` (push-only) followed by the spent
output's ``script_pubkey`` leaves a truthy value on top of the stack. Execution is bounded
by script size, operation count, stack depth and element size, so a malicious script can
cost a validator at most a few hundred cheap steps plus a bounded number of signature
checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from forkchain.crypto import hash160
from forkchain.keys import PUBKEY_SIZE, PublicKey
from forkchain.script.opcodes import SMALL_INT_OPS, Op, ScriptParseError, Token, tokenize
from forkchain.tx import Transaction, TxOut


@dataclass(frozen=True)
class Limits:
    max_script_size: int = 1_000
    max_ops: int = 100  # non-push operations, plus one per key in CHECKMULTISIG
    max_stack: int = 100
    max_element: int = 520
    max_multisig_keys: int = 16
    max_num_bytes: int = 8


DEFAULT_LIMITS = Limits()


class ScriptError(Exception):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code


@dataclass(frozen=True)
class ExecContext:
    """What a script may know about the transaction spending it."""

    tx: Transaction
    index: int
    spent: TxOut

    def sighash(self) -> bytes:
        return self.tx.sighash(self.index, self.spent.script_pubkey, self.spent.value)


@dataclass(frozen=True)
class TraceStep:
    phase: str  # "unlock" or "lock"
    op: str
    executed: bool
    stack: tuple[str, ...]  # hex of every element, bottom first, after the op ran


@dataclass
class Machine:
    ctx: ExecContext | None = None
    limits: Limits = DEFAULT_LIMITS
    trace: list[TraceStep] | None = None
    stack: list[bytes] = field(default_factory=list)
    _ops: int = 0
    _sighash: bytes | None = None

    # -- helpers ---------------------------------------------------------------------------

    def _pop(self) -> bytes:
        if not self.stack:
            raise ScriptError("stack-underflow")
        return self.stack.pop()

    def _push(self, item: bytes) -> None:
        if len(item) > self.limits.max_element:
            raise ScriptError("push-size", f"{len(item)} > {self.limits.max_element}")
        self.stack.append(item)
        if len(self.stack) > self.limits.max_stack:
            raise ScriptError("stack-size")

    def _num(self, item: bytes) -> int:
        if len(item) > self.limits.max_num_bytes:
            raise ScriptError("num-overflow")
        return int.from_bytes(item, "little")

    def _count_ops(self, n: int = 1) -> None:
        self._ops += n
        if self._ops > self.limits.max_ops:
            raise ScriptError("op-count", f"more than {self.limits.max_ops} operations")

    def _require_ctx(self) -> ExecContext:
        if self.ctx is None:
            raise ScriptError("no-context", "opcode needs a spending transaction")
        return self.ctx

    def _check_sig(self, sig: bytes, pubkey: bytes) -> bool:
        ctx = self._require_ctx()
        if len(pubkey) != PUBKEY_SIZE:
            return False
        if self._sighash is None:
            self._sighash = ctx.sighash()
        return PublicKey(pubkey).verify(sig, self._sighash)

    # -- execution -------------------------------------------------------------------------

    def run(self, script: bytes, phase: str = "lock") -> None:
        if len(script) > self.limits.max_script_size:
            raise ScriptError("script-size", f"{len(script)} > {self.limits.max_script_size}")
        try:
            tokens = list(tokenize(script))
        except ScriptParseError as exc:
            raise ScriptError("bad-encoding", str(exc)) from exc
        branches: list[bool] = []
        for token in tokens:
            executing = all(branches)
            if not token.is_push:
                self._count_ops()
            if token.opcode in (Op.IF, Op.ELSE, Op.ENDIF):
                self._flow(token.opcode, branches, executing)
            elif executing:
                self._step(token)
            if self.trace is not None:
                snapshot = tuple(x.hex() for x in self.stack)
                self.trace.append(TraceStep(phase, token.name(), executing, snapshot))
        if branches:
            raise ScriptError("unbalanced-conditional")

    def _flow(self, opcode: int, branches: list[bool], executing: bool) -> None:
        if opcode == Op.IF:
            branches.append(_truthy(self._pop()) if executing else False)
        elif not branches:
            raise ScriptError("unbalanced-conditional")
        elif opcode == Op.ELSE:
            # Only flip if the enclosing branches are live; a nested IF inside a dead branch
            # must stay dead on both sides.
            outer_live = all(branches[:-1])
            branches[-1] = outer_live and not branches[-1]
        else:
            branches.pop()

    def _step(self, token: Token) -> None:
        op = token.opcode
        if token.data is not None:
            self._push(token.data)
        elif op in SMALL_INT_OPS:
            self._push(bytes([op - Op.OP_1 + 1]))
        elif op == Op.DUP:
            top = self._pop()
            self._push(top)
            self._push(top)
        elif op == Op.DROP:
            self._pop()
        elif op == Op.SWAP:
            a, b = self._pop(), self._pop()
            self._push(a)
            self._push(b)
        elif op == Op.HASH:
            self._push(hash160(self._pop()))
        elif op in (Op.EQUAL, Op.EQUALVERIFY):
            equal = self._pop() == self._pop()
            if op == Op.EQUALVERIFY:
                if not equal:
                    raise ScriptError("equalverify")
            else:
                self._push(b"\x01" if equal else b"")
        elif op == Op.VERIFY:
            if not _truthy(self._pop()):
                raise ScriptError("verify")
        elif op == Op.RETURN:
            raise ScriptError("op-return")
        elif op in (Op.CHECKSIG, Op.CHECKSIGVERIFY):
            pubkey, sig = self._pop(), self._pop()
            ok = self._check_sig(sig, pubkey)
            if op == Op.CHECKSIGVERIFY:
                if not ok:
                    raise ScriptError("checksigverify")
            else:
                self._push(b"\x01" if ok else b"")
        elif op == Op.CHECKMULTISIG:
            self._checkmultisig()
        elif op == Op.CHECKLOCKTIME:
            self._checklocktime()
        else:
            raise ScriptError("bad-opcode", token.name())

    def _checkmultisig(self) -> None:
        """``<sig_1>..<sig_m> | m <pk_1>..<pk_n> n CHECKMULTISIG``.

        Signatures must appear in the same order as their keys. Unlike Bitcoin there is no
        extra dummy element (the historical off-by-one bug is not reproduced).
        """
        n = self._num(self._pop())
        if n > self.limits.max_multisig_keys:
            raise ScriptError("pubkey-count", f"{n} keys")
        self._count_ops(n)
        keys = [self._pop() for _ in range(n)][::-1]
        m = self._num(self._pop())
        if m > n:
            raise ScriptError("sig-count", f"{m} of {n}")
        sigs = [self._pop() for _ in range(m)][::-1]
        key_iter = iter(keys)
        matched = 0
        for sig in sigs:
            for key in key_iter:
                if self._check_sig(sig, key):
                    matched += 1
                    break
        self._push(b"\x01" if matched == m else b"")

    def _checklocktime(self) -> None:
        """Fail unless the spending tx is locked to at least the height on top of the stack.

        BIP65 semantics: the element is left on the stack, and the comparison is against
        ``tx.locktime`` (which consensus enforces) rather than the current height, so the
        result never depends on which block the transaction lands in.
        """
        ctx = self._require_ctx()
        if not self.stack:
            raise ScriptError("stack-underflow")
        required = self._num(self.stack[-1])
        if ctx.tx.locktime < required:
            raise ScriptError("locktime", f"tx locktime {ctx.tx.locktime} < {required}")


def _truthy(item: bytes) -> bool:
    return any(item)


def is_push_only(script: bytes) -> bool:
    try:
        return all(t.is_push for t in tokenize(script))
    except ScriptParseError:
        return False


def verify_script(
    script_sig: bytes,
    script_pubkey: bytes,
    ctx: ExecContext | None,
    *,
    limits: Limits = DEFAULT_LIMITS,
    trace: list[TraceStep] | None = None,
) -> None:
    """Run unlock + lock scripts; raise ``ScriptError`` unless the spend is authorised."""
    if not is_push_only(script_sig):
        raise ScriptError("sig-pushonly", "scriptSig may only push data")
    machine = Machine(ctx=ctx, limits=limits, trace=trace)
    machine.run(script_sig, phase="unlock")
    machine.run(script_pubkey, phase="lock")
    if not machine.stack or not _truthy(machine.stack[-1]):
        raise ScriptError("eval-false", "script finished with false on top of the stack")


def verify_input(tx: Transaction, index: int, spent: TxOut) -> bool:
    """``ScriptVerifier`` used by consensus validation."""
    try:
        verify_script(
            tx.inputs[index].script_sig, spent.script_pubkey, ExecContext(tx, index, spent)
        )
    except ScriptError:
        return False
    return True
