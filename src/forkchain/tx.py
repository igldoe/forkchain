"""UTXO-style transactions."""

from __future__ import annotations

from dataclasses import dataclass
from functools import cached_property

from forkchain.crypto import ZERO_HASH, sha256d
from forkchain.encoding import Reader, Writer

MAX_SCRIPT_BYTES = 10_000  # hard decode limit; consensus script limits are stricter
MAX_IO = 10_000
SEQUENCE_FINAL = 0xFFFFFFFF
COINBASE_INDEX = 0xFFFFFFFF


@dataclass(frozen=True, order=True)
class OutPoint:
    txid: bytes
    index: int

    @classmethod
    def null(cls) -> OutPoint:
        return cls(ZERO_HASH, COINBASE_INDEX)

    @property
    def is_null(self) -> bool:
        return self.txid == ZERO_HASH and self.index == COINBASE_INDEX

    def __str__(self) -> str:
        return f"{self.txid.hex()}:{self.index}"


@dataclass(frozen=True)
class TxIn:
    prevout: OutPoint
    script_sig: bytes = b""
    sequence: int = SEQUENCE_FINAL


@dataclass(frozen=True)
class TxOut:
    value: int
    script_pubkey: bytes


@dataclass(frozen=True)
class Transaction:
    inputs: tuple[TxIn, ...]
    outputs: tuple[TxOut, ...]
    locktime: int = 0
    version: int = 1

    def _write(self, w: Writer, *, blank_scripts: bool = False) -> None:
        w.u32(self.version)
        w.varint(len(self.inputs))
        for txin in self.inputs:
            w.raw(txin.prevout.txid).u32(txin.prevout.index)
            w.var_bytes(b"" if blank_scripts else txin.script_sig)
            w.u32(txin.sequence)
        w.varint(len(self.outputs))
        for txout in self.outputs:
            w.u64(txout.value).var_bytes(txout.script_pubkey)
        w.u64(self.locktime)

    @cached_property
    def _raw(self) -> bytes:
        w = Writer()
        self._write(w)
        return w.getvalue()

    def serialize(self) -> bytes:
        return self._raw

    @classmethod
    def read_from(cls, r: Reader) -> Transaction:
        version = r.u32()
        n_in = r.varint()
        if n_in > MAX_IO:
            raise ValueError("too many inputs")
        inputs = []
        for _ in range(n_in):
            prevout = OutPoint(r.raw(32), r.u32())
            inputs.append(TxIn(prevout, r.var_bytes(MAX_SCRIPT_BYTES), r.u32()))
        n_out = r.varint()
        if n_out > MAX_IO:
            raise ValueError("too many outputs")
        outputs = [TxOut(r.u64(), r.var_bytes(MAX_SCRIPT_BYTES)) for _ in range(n_out)]
        return cls(tuple(inputs), tuple(outputs), locktime=r.u64(), version=version)

    @classmethod
    def deserialize(cls, data: bytes) -> Transaction:
        r = Reader(data)
        tx = cls.read_from(r)
        r.expect_end()
        return tx

    @cached_property
    def txid(self) -> bytes:
        return sha256d(self.serialize())

    @property
    def size(self) -> int:
        return len(self.serialize())

    @property
    def is_coinbase(self) -> bool:
        return len(self.inputs) == 1 and self.inputs[0].prevout.is_null

    def total_out(self) -> int:
        return sum(o.value for o in self.outputs)

    def sighash(self, input_index: int, spent_script: bytes, spent_value: int) -> bytes:
        """Digest signed by the owner of input ``input_index`` (SIGHASH_ALL semantics).

        All scriptSigs are blanked (a signature cannot sign itself); the spent output's
        script and value are committed to so a signature cannot be replayed against a
        different output that happens to share the same key.
        """
        w = Writer()
        self._write(w, blank_scripts=True)
        w.u32(input_index).var_bytes(spent_script).u64(spent_value)
        return sha256d(w.getvalue())

    def coinbase_height(self) -> int | None:
        """Height committed in the coinbase scriptSig (BIP34-style), if any."""
        if not self.is_coinbase:
            return None
        try:
            return Reader(self.inputs[0].script_sig).varint()
        except ValueError:
            return None


def make_coinbase(height: int, outputs: tuple[TxOut, ...], extra: bytes = b"") -> Transaction:
    """Build a coinbase transaction.

    The block height is the first item of the scriptSig. That keeps every coinbase txid
    unique even when two blocks pay the same address the same amount.
    """
    script_sig = Writer().varint(height).raw(extra).getvalue()
    return Transaction(inputs=(TxIn(OutPoint.null(), script_sig),), outputs=outputs)
