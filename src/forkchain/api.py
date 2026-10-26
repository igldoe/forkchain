"""Read/write facade over a node, returning plain JSON-able data.

Used by the RPC server (CLI wallet, external miner) and by the explorer, so both see
exactly the same view of a node.
"""

from __future__ import annotations

from typing import Any

from forkchain.block import Block
from forkchain.chain import BlockIndex
from forkchain.encoding import DecodeError, Reader
from forkchain.errors import ForkchainError, MissingDataError, ValidationError
from forkchain.keys import hash_from_address
from forkchain.merkle import merkle_proof, merkle_root, verify_proof
from forkchain.miner import build_template
from forkchain.p2p.node import Node
from forkchain.pow import bits_to_target, difficulty
from forkchain.script.templates import address_of, classify, disassemble, p2pkh
from forkchain.script.vm import ExecContext, ScriptError, TraceStep, verify_script
from forkchain.tx import OutPoint, Transaction, TxOut

JSON = dict[str, Any]


class ApiError(ForkchainError):
    pass


def _hash_arg(value: str) -> bytes:
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ApiError("expected a hex hash") from exc
    if len(raw) != 32:
        raise ApiError("expected a 32-byte hash")
    return raw


def describe_output(out: TxOut) -> JSON:
    return {
        "value": out.value,
        "type": classify(out.script_pubkey),
        "address": address_of(out.script_pubkey),
        "script": out.script_pubkey.hex(),
        "asm": disassemble(out.script_pubkey),
    }


class NodeAPI:
    METHODS = frozenset(
        {
            "info",
            "block",
            "tx",
            "merkle_proof",
            "script_trace",
            "mempool",
            "peers",
            "utxos",
            "tree",
            "difficulty_history",
            "search",
            "send_raw_tx",
            "block_template",
            "submit_block",
            "events",
        }
    )

    def __init__(self, node: Node) -> None:
        self.node = node
        self.chain = node.chain

    # -- helpers ---------------------------------------------------------------------------

    def _status(self, idx: BlockIndex) -> str:
        if idx.invalid:
            return "invalid"
        if self.chain.contains(idx.hash):
            return "active"
        if not idx.has_data:
            return "header-only"
        return "stale"

    def _miner(self, block: Block) -> str:
        # Coinbase scriptSig = varint(height) + extra; the built-in miner puts its name there.
        reader = Reader(block.txs[0].inputs[0].script_sig)
        try:
            reader.varint()
        except DecodeError:
            return ""
        return reader.raw(reader.remaining).decode("utf-8", errors="replace")[:32]

    def _block_summary(self, idx: BlockIndex) -> JSON:
        block = self.chain.blocks.get(idx.hash)
        meta = self.node.block_meta.get(idx.hash, {})
        return {
            "hash": idx.hash.hex(),
            "parent": idx.header.prev_hash.hex(),
            "height": idx.height,
            "status": self._status(idx),
            "time": idx.header.timestamp,
            "bits": idx.header.bits,
            "difficulty": round(difficulty(idx.header.bits, self.chain.params), 3),
            "chainwork": idx.chainwork,
            "ntx": len(block.txs) if block else None,
            "miner": self._miner(block) if block else None,
            "source": meta.get("source"),
            "received": meta.get("received"),
            "seq": idx.seq,
        }

    def _find_spent_output(self, outpoint: OutPoint) -> TxOut | None:
        coin = self.chain.utxos.get(outpoint)
        if coin is not None:
            return coin.output
        pool_tx = self.node.mempool.get(outpoint.txid)
        found = self.chain.find_tx(outpoint.txid)
        tx = pool_tx or (found[0] if found else None)
        if tx is None or outpoint.index >= len(tx.outputs):
            return None
        return tx.outputs[outpoint.index]

    def _locate_tx(self, txid: bytes) -> tuple[Transaction, BlockIndex | None]:
        pool_tx = self.node.mempool.get(txid)
        if pool_tx is not None:
            return pool_tx, None
        found = self.chain.find_tx(txid)
        if found is None:
            raise ApiError("transaction not found")
        return found

    # -- queries ---------------------------------------------------------------------------

    def info(self) -> JSON:
        tip = self.chain.tip
        stats = self.node.stats
        return {
            "name": self.node.name,
            "network": self.chain.params.name,
            "height": tip.height,
            "tip": tip.hash.hex(),
            "bits": tip.header.bits,
            "target": f"{bits_to_target(tip.header.bits):064x}",
            "difficulty": round(difficulty(tip.header.bits, self.chain.params), 3),
            "chainwork": tip.chainwork,
            "mempool": len(self.node.mempool),
            "mempool_bytes": self.node.mempool.total_bytes,
            "peers": sum(1 for p in self.node.peers.values() if p.handshake_done),
            "mining": self.node.mining,
            "hashrate": self.node.hashrate,
            "known_blocks": len(self.chain.index),
            "orphans": len(self.chain.orphans),
            "stats": vars(stats).copy(),
        }

    def block(self, ref: str) -> JSON:
        if ref.isdigit():
            height = int(ref)
            if height > self.chain.height:
                raise ApiError("height beyond tip")
            idx = self.chain.active[height]
        else:
            found = self.chain.index.get(_hash_arg(ref))
            if found is None:
                raise ApiError("block not found")
            idx = found
        summary = self._block_summary(idx)
        block = self.chain.blocks.get(idx.hash)
        summary["confirmations"] = (
            self.chain.height - idx.height + 1 if summary["status"] == "active" else 0
        )
        summary["merkle_root"] = idx.header.merkle_root.hex()
        summary["nonce"] = idx.header.nonce
        summary["children"] = [c.hash.hex() for c in self.chain.children.get(idx.hash, [])]
        if block is not None:
            summary["size"] = block.size
            summary["txs"] = [
                {
                    "txid": tx.txid.hex(),
                    "size": tx.size,
                    "out": tx.total_out(),
                    "coinbase": tx.is_coinbase,
                }
                for tx in block.txs
            ]
        return summary

    def tx(self, txid: str) -> JSON:
        raw_id = _hash_arg(txid)
        tx, idx = self._locate_tx(raw_id)
        inputs = []
        total_in = 0
        for txin in tx.inputs:
            spent = None if txin.prevout.is_null else self._find_spent_output(txin.prevout)
            if spent is not None:
                total_in += spent.value
            inputs.append(
                {
                    "prevout": None if txin.prevout.is_null else str(txin.prevout),
                    "script_sig": txin.script_sig.hex(),
                    "asm": disassemble(txin.script_sig),
                    "spent": describe_output(spent) if spent else None,
                }
            )
        entry = self.node.mempool.entries.get(raw_id)
        return {
            "txid": tx.txid.hex(),
            "size": tx.size,
            "locktime": tx.locktime,
            "coinbase": tx.is_coinbase,
            "status": "mempool" if idx is None else self._status(idx),
            "block": idx.hash.hex() if idx else None,
            "height": idx.height if idx else None,
            "fee": entry.fee if entry else (None if tx.is_coinbase else total_in - tx.total_out()),
            "inputs": inputs,
            "outputs": [describe_output(o) for o in tx.outputs],
        }

    def merkle_proof(self, txid: str, block: str | None = None) -> JSON:
        raw_id = _hash_arg(txid)
        if block is not None:
            blk = self.chain.blocks.get(_hash_arg(block))
        else:
            found = self.chain.find_tx(raw_id)
            blk = self.chain.blocks[found[1].hash] if found else None
        if blk is None:
            raise ApiError("transaction is not in a known block")
        leaves = [t.txid for t in blk.txs]
        if raw_id not in leaves:
            raise ApiError("transaction not in that block")
        proof = merkle_proof(leaves, leaves.index(raw_id))
        root = blk.header.merkle_root
        return {
            "block": blk.hash.hex(),
            "root": root.hex(),
            "computed_root": merkle_root(leaves).hex(),
            "leaves": len(leaves),
            "proof": proof.to_json(),
            "valid": verify_proof(raw_id, proof, root),
        }

    def script_trace(self, txid: str, index: int = 0) -> JSON:
        tx, _ = self._locate_tx(_hash_arg(txid))
        if tx.is_coinbase:
            raise ApiError("coinbase inputs have no script to run")
        if not 0 <= index < len(tx.inputs):
            raise ApiError("input index out of range")
        spent = self._find_spent_output(tx.inputs[index].prevout)
        if spent is None:
            raise ApiError("spent output is unknown")
        trace: list[TraceStep] = []
        error = None
        try:
            verify_script(
                tx.inputs[index].script_sig,
                spent.script_pubkey,
                ExecContext(tx, index, spent),
                trace=trace,
            )
        except ScriptError as exc:
            error = str(exc)
        return {
            "txid": tx.txid.hex(),
            "input": index,
            "type": classify(spent.script_pubkey),
            "unlock": disassemble(tx.inputs[index].script_sig),
            "lock": disassemble(spent.script_pubkey),
            "steps": [vars(s) | {"stack": list(s.stack)} for s in trace],
            "valid": error is None,
            "error": error,
        }

    def mempool(self, limit: int = 100) -> JSON:
        entries = self.node.mempool.sorted_entries()
        return {
            "count": len(entries),
            "bytes": self.node.mempool.total_bytes,
            "max_bytes": self.node.mempool.policy.max_bytes,
            "entries": [e.to_json() for e in entries[:limit]],
        }

    def peers(self) -> list[JSON]:
        return self.node.peer_summary()

    def utxos(self, address: str) -> JSON:
        try:
            script = p2pkh(hash_from_address(address))
        except ValueError as exc:
            raise ApiError(str(exc)) from exc
        tip = self.chain.height
        maturity = self.chain.params.coinbase_maturity
        coins = []
        spendable = 0
        immature = 0
        for outpoint, coin in self.chain.utxos.coins_for_script(script):
            mature = not coin.is_coinbase or tip + 1 - coin.height >= maturity
            pending_spend = outpoint in self.node.mempool.spends
            coins.append(
                {
                    "txid": outpoint.txid.hex(),
                    "index": outpoint.index,
                    "value": coin.output.value,
                    "height": coin.height,
                    "coinbase": coin.is_coinbase,
                    "mature": mature,
                    "spent_in_mempool": pending_spend,
                }
            )
            if not mature:
                immature += coin.output.value
            elif not pending_spend:
                spendable += coin.output.value
        incoming = sum(
            out.value
            for entry in self.node.mempool.entries.values()
            for out in entry.tx.outputs
            if out.script_pubkey == script
        )
        return {
            "address": address,
            "script": script.hex(),
            "spendable": spendable,
            "immature": immature,
            "unconfirmed_incoming": incoming,
            "coins": coins,
        }

    def tree(self, depth: int = 60) -> JSON:
        """Every known block in the last ``depth`` heights: the raw material of the fork graph."""
        floor = max(0, self.chain.best_header.height - depth)
        blocks = [self._block_summary(i) for i in self.chain.iter_index() if i.height >= floor]
        blocks.sort(key=lambda b: (b["height"], b["seq"]))
        return {"tip": self.chain.tip.hash.hex(), "height": self.chain.height, "blocks": blocks}

    def difficulty_history(self, limit: int = 200) -> list[JSON]:
        start = max(1, self.chain.height - limit + 1)
        result = []
        for h in range(start, self.chain.height + 1):
            idx = self.chain.active[h]
            prev = self.chain.active[h - 1]
            result.append(
                {
                    "height": h,
                    "difficulty": difficulty(idx.header.bits, self.chain.params),
                    "interval_ms": idx.header.timestamp - prev.header.timestamp,
                    "time": idx.header.timestamp,
                }
            )
        return result

    def search(self, query: str) -> JSON:
        q = query.strip().lower()
        if q.isdigit():
            return {"kind": "block", "result": self.block(q)}
        if q.startswith("fc"):
            return {"kind": "address", "result": self.utxos(q)}
        raw = _hash_arg(q)
        if raw in self.chain.index:
            return {"kind": "block", "result": self.block(q)}
        try:
            return {"kind": "tx", "result": self.tx(q)}
        except ApiError as exc:
            raise ApiError("nothing found for that hash") from exc

    def events(self, since: int = 0, limit: int = 200) -> list[JSON]:
        return [e for e in self.node.events if e["time"] >= since][-limit:]

    # -- actions ---------------------------------------------------------------------------

    def send_raw_tx(self, hex_tx: str) -> JSON:
        tx = Transaction.deserialize(bytes.fromhex(hex_tx))
        try:
            result = self.node.submit_tx(tx)
        except (ValidationError, MissingDataError) as exc:
            raise ApiError(f"rejected: {exc}") from exc
        return {
            "txid": result.txid.hex(),
            "fee": result.fee,
            "replaced": [t.hex() for t in result.replaced],
        }

    def block_template(self, address: str) -> JSON:
        script = p2pkh(hash_from_address(address))
        txs, fees = self.node.mempool.select(self.chain.params.max_block_size - 2_000)
        template = build_template(self.chain, script, txs, fees=fees, extra=b"external")
        return {
            "block": template.serialize().hex(),
            "height": self.chain.height + 1,
            "target": f"{bits_to_target(template.header.bits):064x}",
            "prev": self.chain.tip.hash.hex(),
        }

    def submit_block(self, hex_block: str) -> JSON:
        block = Block.deserialize(bytes.fromhex(hex_block))
        result = self.node.process_block(block)
        if result is None:
            raise ApiError("block rejected")
        if result.error is not None:
            raise ApiError(f"block invalid: {result.error}")
        return {"hash": block.hash.hex(), "status": result.status}

    def call(self, method: str, params: dict[str, Any]) -> Any:
        if method not in self.METHODS:
            raise ApiError(f"unknown method {method!r}")
        return getattr(self, method)(**params)
