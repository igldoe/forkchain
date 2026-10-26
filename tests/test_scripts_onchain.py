"""Non-P2PKH outputs created and spent through real blocks."""

from __future__ import annotations

from dataclasses import replace

import pytest

from forkchain.crypto import hash160
from forkchain.errors import ValidationError
from forkchain.keys import PrivateKey
from forkchain.params import COIN
from forkchain.script import templates as tpl
from forkchain.tx import OutPoint, Transaction, TxIn, TxOut
from forkchain.wallet import Wallet

from .conftest import ChainHarness


def lock_coins(h: ChainHarness, w: Wallet, lock: bytes, amount: int) -> OutPoint:
    coins = h.chain.utxos.coins_for_script(w.script_pubkey)
    tx = w.build_payment(coins, [TxOut(amount, lock)], fee=0)
    h.mine(w.script_pubkey, [tx])
    return OutPoint(tx.txid, 0)


def test_multisig_output_spent_on_chain(harness: ChainHarness, alice: Wallet) -> None:
    harness.mine_many(2, alice.script_pubkey)
    keys = [PrivateKey.from_seed(s) for s in ("k1", "k2", "k3")]
    lock = tpl.multisig(2, [k.public_key for k in keys])
    outpoint = lock_coins(harness, alice, lock, 10 * COIN)
    unsigned = Transaction((TxIn(outpoint),), (TxOut(10 * COIN, alice.script_pubkey),))
    digest = unsigned.sighash(0, lock, 10 * COIN)
    unlock = tpl.multisig_unlock([keys[0].sign(digest), keys[2].sign(digest)])
    tx = replace(unsigned, inputs=(replace(unsigned.inputs[0], script_sig=unlock),))
    harness.mine(alice.script_pubkey, [tx])
    assert harness.chain.utxos.get(outpoint) is None


def test_timelocked_output_respects_chain_height(harness: ChainHarness, alice: Wallet) -> None:
    harness.mine_many(2, alice.script_pubkey)
    key = PrivateKey.from_seed("future")
    unlock_height = 6
    lock = tpl.timelock(unlock_height, key.public_key.pubkey_hash)
    outpoint = lock_coins(harness, alice, lock, COIN)
    unsigned = Transaction(
        (TxIn(outpoint),), (TxOut(COIN, alice.script_pubkey),), locktime=unlock_height
    )
    sig = key.sign(unsigned.sighash(0, lock, COIN))
    tx = replace(
        unsigned,
        inputs=(replace(unsigned.inputs[0], script_sig=tpl.p2pkh_unlock(sig, key.public_key)),),
    )
    # Tip is at height 3: the tx satisfies its script but is not final until height 6.
    assert harness.chain.height == 3
    with pytest.raises(ValidationError, match="nonfinal"):
        harness.mine(alice.script_pubkey, [tx])
    harness.mine_many(2, alice.script_pubkey)  # heights 4 and 5
    harness.mine(alice.script_pubkey, [tx])  # height 6
    assert harness.chain.utxos.get(outpoint) is None


def test_hashlock_output_spent_by_revealing_secret(harness: ChainHarness, alice: Wallet) -> None:
    harness.mine_many(2, alice.script_pubkey)
    bob = PrivateKey.from_seed("bob")
    lock = tpl.hashlock(hash160(b"s3cret"), bob.public_key.pubkey_hash)
    outpoint = lock_coins(harness, alice, lock, COIN)
    unsigned = Transaction((TxIn(outpoint),), (TxOut(COIN, alice.script_pubkey),))
    sig = bob.sign(unsigned.sighash(0, lock, COIN))
    tx = replace(
        unsigned,
        inputs=(
            replace(
                unsigned.inputs[0], script_sig=tpl.hashlock_unlock(b"s3cret", sig, bob.public_key)
            ),
        ),
    )
    harness.mine(alice.script_pubkey, [tx])
    assert harness.chain.utxos.get(outpoint) is None
