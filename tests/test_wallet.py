import os
import stat
from pathlib import Path

import pytest

from forkchain.errors import ForkchainError
from forkchain.params import COIN
from forkchain.tx import OutPoint, TxOut
from forkchain.utxo import Coin
from forkchain.validation import verify_p2pkh
from forkchain.wallet import InsufficientFundsError, Wallet


def test_wallet_file_has_mode_600(tmp_path: Path) -> None:
    path = tmp_path / "w" / "wallet.json"
    w = Wallet.create(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert Wallet.load(path).address == w.address
    assert "educational" in path.read_text()


def test_wallet_refuses_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "wallet.json"
    Wallet.create(path)
    with pytest.raises(FileExistsError):
        Wallet.create(path)


def test_wallet_refuses_world_readable_file(tmp_path: Path) -> None:
    path = tmp_path / "wallet.json"
    Wallet.create(path)
    os.chmod(path, 0o644)
    with pytest.raises(ForkchainError, match="chmod 600"):
        Wallet.load(path)


def _coins(w: Wallet, *values: int) -> list[tuple[OutPoint, Coin]]:
    return [
        (OutPoint(bytes([i + 1]) * 32, 0), Coin(TxOut(v, w.script_pubkey), 1, False))
        for i, v in enumerate(values)
    ]


def test_build_payment_selects_largest_first_and_adds_change(alice: Wallet, bob: Wallet) -> None:
    coins = _coins(alice, 1 * COIN, 5 * COIN, 2 * COIN)
    tx = alice.build_payment(coins, [TxOut(6 * COIN, bob.script_pubkey)], fee=100)
    assert len(tx.inputs) == 2  # 5 + 2
    assert tx.outputs[1] == TxOut(COIN - 100, alice.script_pubkey)
    spent = dict(coins)
    for i, txin in enumerate(tx.inputs):
        assert verify_p2pkh(tx, i, spent[txin.prevout].output)


def test_exact_amount_has_no_change(alice: Wallet, bob: Wallet) -> None:
    tx = alice.build_payment(_coins(alice, 10), [TxOut(9, bob.script_pubkey)], fee=1)
    assert len(tx.outputs) == 1


def test_insufficient_funds(alice: Wallet, bob: Wallet) -> None:
    with pytest.raises(InsufficientFundsError):
        alice.build_payment(_coins(alice, 10), [TxOut(10, bob.script_pubkey)], fee=1)
