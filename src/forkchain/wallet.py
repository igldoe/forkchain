"""A single-key P2PKH wallet.

Educational code: the private key is stored *unencrypted* in a JSON file whose permissions
are restricted to the owner (0600). Do not put real value behind these keys.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from forkchain.errors import ForkchainError
from forkchain.keys import PrivateKey
from forkchain.script.templates import p2pkh, p2pkh_unlock
from forkchain.tx import OutPoint, Transaction, TxIn, TxOut
from forkchain.utxo import Coin

WALLET_FILE_MODE = 0o600
WALLET_VERSION = 1


class InsufficientFundsError(ForkchainError):
    pass


def sign_inputs(tx: Transaction, key: PrivateKey, spent: Sequence[TxOut]) -> Transaction:
    """Fill every scriptSig with a P2PKH unlock for ``key``."""
    pub = key.public_key
    inputs = tuple(
        replace(
            txin,
            script_sig=p2pkh_unlock(key.sign(tx.sighash(i, out.script_pubkey, out.value)), pub),
        )
        for i, (txin, out) in enumerate(zip(tx.inputs, spent, strict=True))
    )
    return replace(tx, inputs=inputs)


class Wallet:
    def __init__(self, key: PrivateKey) -> None:
        self.key = key

    @property
    def address(self) -> str:
        return self.key.public_key.address

    @property
    def script_pubkey(self) -> bytes:
        return p2pkh(self.key.public_key.pubkey_hash)

    # -- persistence -----------------------------------------------------------------------

    @classmethod
    def create(cls, path: Path) -> Wallet:
        wallet = cls(PrivateKey.generate())
        wallet.save(path)
        return wallet

    def save(self, path: Path) -> None:
        payload = json.dumps(
            {
                "version": WALLET_VERSION,
                "warning": "educational wallet - unencrypted key, never use for real funds",
                "address": self.address,
                "private_key": self.key.to_bytes().hex(),
            },
            indent=2,
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        # O_EXCL: never silently overwrite an existing key. The mode is applied atomically at
        # creation, so the key is never readable by others, not even for a moment.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, WALLET_FILE_MODE)
        with os.fdopen(fd, "w") as fh:
            fh.write(payload)
        os.chmod(path, WALLET_FILE_MODE)  # umask may have stripped bits; make it exact

    @classmethod
    def load(cls, path: Path) -> Wallet:
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise ForkchainError(
                f"wallet file {path} is accessible by other users (mode {mode:o}); "
                f"run: chmod 600 {path}"
            )
        data = json.loads(path.read_text())
        return cls(PrivateKey.from_bytes(bytes.fromhex(data["private_key"])))

    # -- spending --------------------------------------------------------------------------

    def build_payment(
        self,
        coins: Sequence[tuple[OutPoint, Coin]],
        outputs: Sequence[TxOut],
        fee: int,
        *,
        locktime: int = 0,
    ) -> Transaction:
        """Pick coins (largest first), add change back to this wallet and sign."""
        need = sum(o.value for o in outputs) + fee
        picked: list[tuple[OutPoint, Coin]] = []
        total = 0
        for outpoint, coin in sorted(coins, key=lambda c: c[1].output.value, reverse=True):
            if total >= need:
                break
            picked.append((outpoint, coin))
            total += coin.output.value
        if total < need:
            raise InsufficientFundsError(f"need {need}, have {total}")
        all_outputs = list(outputs)
        if total > need:
            all_outputs.append(TxOut(total - need, self.script_pubkey))
        unsigned = Transaction(
            inputs=tuple(TxIn(op) for op, _ in picked),
            outputs=tuple(all_outputs),
            locktime=locktime,
        )
        return sign_inputs(unsigned, self.key, [c.output for _, c in picked])
