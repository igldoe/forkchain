import pytest

from forkchain.tx import OutPoint, Transaction, TxIn, TxOut, make_coinbase
from forkchain.utxo import BlockUndo, Coin, OverlayView, UtxoSet


def test_add_spend_and_script_index() -> None:
    utxos = UtxoSet()
    op = OutPoint(b"\x01" * 32, 0)
    coin = Coin(TxOut(5, b"s"), 1, False)
    utxos.add(op, coin)
    assert op in utxos
    assert len(utxos) == 1
    assert utxos.coins_for_script(b"s") == [(op, coin)]
    with pytest.raises(KeyError):
        utxos.add(op, coin)
    assert utxos.spend(op) == coin
    assert utxos.coins_for_script(b"s") == []
    with pytest.raises(KeyError):
        utxos.spend(op)


def test_apply_and_undo_tx_chain() -> None:
    utxos = UtxoSet()
    cb = make_coinbase(1, (TxOut(50, b"a"),))
    undo = BlockUndo()
    utxos.apply_tx(cb, 1, undo)
    spend = Transaction((TxIn(OutPoint(cb.txid, 0)),), (TxOut(30, b"b"), TxOut(20, b"a")))
    utxos.apply_tx(spend, 2, undo)
    assert utxos.total_value() == 50
    assert [op for op, _ in undo.spent] == [OutPoint(cb.txid, 0)]
    assert dict(utxos)[OutPoint(spend.txid, 0)].height == 2


def test_overlay_does_not_touch_base() -> None:
    base = UtxoSet()
    op = OutPoint(b"\x02" * 32, 0)
    base.add(op, Coin(TxOut(5, b"s"), 1, False))
    view = OverlayView(base)
    tx = Transaction((TxIn(op),), (TxOut(5, b"t"),))
    view.apply_tx(tx, 2)
    assert view.get(op) is None
    assert view.get(OutPoint(tx.txid, 0)) is not None
    assert base.get(op) is not None
