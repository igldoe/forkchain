"""Contextual transaction validation against a UTXO view."""

from __future__ import annotations

from collections.abc import Callable

from forkchain.crypto import hash160
from forkchain.errors import MissingDataError, ValidationError
from forkchain.keys import PublicKey
from forkchain.params import ConsensusParams
from forkchain.script.opcodes import tokenize
from forkchain.script.templates import p2pkh
from forkchain.tx import OutPoint, Transaction, TxOut
from forkchain.utxo import UtxoView

ScriptVerifier = Callable[[Transaction, int, TxOut], bool]


class MissingInputsError(MissingDataError):
    def __init__(self, outpoint: OutPoint) -> None:
        super().__init__(f"missing or spent input {outpoint}")
        self.outpoint = outpoint


def verify_p2pkh(tx: Transaction, index: int, spent: TxOut) -> bool:
    """Signature check for pay-to-pubkey-hash outputs."""
    try:
        tokens = list(tokenize(tx.inputs[index].script_sig))
    except ValueError:
        return False
    if len(tokens) != 2 or tokens[0].data is None or tokens[1].data is None:
        return False
    signature, raw_pub = tokens[0].data, tokens[1].data
    if spent.script_pubkey != p2pkh(hash160(raw_pub)):
        return False
    try:
        pubkey = PublicKey(raw_pub)
    except ValueError:
        return False
    return pubkey.verify(signature, tx.sighash(index, spent.script_pubkey, spent.value))


def is_final(tx: Transaction, height: int) -> bool:
    """A transaction may only be mined at a height >= its locktime."""
    return tx.locktime <= height


def check_tx_inputs(
    tx: Transaction,
    view: UtxoView,
    spend_height: int,
    params: ConsensusParams,
    verifier: ScriptVerifier = verify_p2pkh,
) -> int:
    """Validate a non-coinbase transaction spending from ``view``; return its fee.

    ``spend_height`` is the height of the block that would include the transaction.
    Raises ``MissingInputsError`` when an input is unknown (orphan, or already spent) and
    ``ValidationError`` when the transaction is provably invalid.
    """
    if tx.is_coinbase:
        raise ValidationError("bad-txns-coinbase", "coinbase outside of block position 0")
    if not is_final(tx, spend_height):
        raise ValidationError("bad-txns-nonfinal", f"locktime {tx.locktime} > {spend_height}")
    total_in = 0
    spent: list[TxOut] = []
    for txin in tx.inputs:
        coin = view.get(txin.prevout)
        if coin is None:
            raise MissingInputsError(txin.prevout)
        if coin.is_coinbase and spend_height - coin.height < params.coinbase_maturity:
            raise ValidationError(
                "bad-txns-premature-spend-of-coinbase",
                f"coinbase from height {coin.height} not mature at {spend_height}",
                ban=False,
            )
        total_in += coin.output.value
        spent.append(coin.output)
    total_out = tx.total_out()
    if total_in < total_out:
        raise ValidationError("bad-txns-in-belowout", f"{total_in} < {total_out}")
    for index, out in enumerate(spent):
        if not verifier(tx, index, out):
            raise ValidationError(
                "bad-txns-script", f"script verification failed for input {index}"
            )
    return total_in - total_out
