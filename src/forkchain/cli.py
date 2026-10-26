"""Command-line interface: ``forkchain node | wallet | mine | sim | explorer``."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import math
import sys
import time
from collections.abc import Sequence
from decimal import Decimal, InvalidOperation
from pathlib import Path

from forkchain.api import NodeAPI
from forkchain.block import Block, mine_header
from forkchain.errors import ForkchainError
from forkchain.keys import hash_from_address
from forkchain.p2p.node import Node, NodeConfig
from forkchain.params import COIN, MAIN, REGTEST, ConsensusParams
from forkchain.rpc import RpcClient, RpcError, RpcServer
from forkchain.script.templates import p2pkh
from forkchain.tx import OutPoint, Transaction, TxOut
from forkchain.utxo import Coin
from forkchain.wallet import Wallet

DEFAULT_WALLET = Path.home() / ".forkchain" / "wallet.json"
NETWORKS: dict[str, ConsensusParams] = {"main": MAIN, "regtest": REGTEST}
DISCLAIMER = "forkchain is an educational project. Never use it for real funds."


def format_coins(units: int) -> str:
    return f"{Decimal(units) / COIN:.8f}"


def parse_coins(text: str) -> int:
    try:
        value = Decimal(text) * COIN
    except InvalidOperation as exc:
        raise argparse.ArgumentTypeError(f"not an amount: {text!r}") from exc
    if value <= 0 or value != value.to_integral_value():
        raise argparse.ArgumentTypeError("amount must be positive with at most 8 decimals")
    return int(value)


def parse_addr(text: str) -> tuple[str, int]:
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit():
        raise argparse.ArgumentTypeError(f"expected host:port, got {text!r}")
    return host or "127.0.0.1", int(port)


# -- node ------------------------------------------------------------------------------------


async def run_node(args: argparse.Namespace) -> None:
    params = NETWORKS[args.network]
    script = p2pkh(hash_from_address(args.address)) if args.address else None
    if args.mine and script is None:
        raise ForkchainError("--mine needs --address to pay block rewards to")
    config = NodeConfig(
        name=args.name,
        host=args.host,
        port=args.port,
        advertise_host=args.advertise_host,
        seeds=list(args.peer),
        mine=args.mine,
        miner_script=script,
        hashrate=args.hashrate,
    )
    node = Node(config, params)
    await node.start()
    rpc = RpcServer(NodeAPI(node), args.rpc_host, args.rpc_port)
    await rpc.start()
    print(f"{DISCLAIMER}\nnode {node.name} p2p={node.port} rpc={rpc.port} network={params.name}")
    try:
        while True:
            await asyncio.sleep(args.status_interval)
            tip = node.chain.tip
            peers = sum(1 for p in node.peers.values() if p.handshake_done)
            print(
                f"[{node.name}] height={tip.height} tip={tip.hash.hex()[:16]} peers={peers} "
                f"mempool={len(node.mempool)} mined={node.stats.blocks_mined} "
                f"reorgs={node.stats.reorgs}",
                flush=True,
            )
    finally:
        await rpc.stop()
        await node.stop()


# -- wallet ----------------------------------------------------------------------------------


def wallet_new(args: argparse.Namespace) -> None:
    wallet = Wallet.create(args.wallet)
    print(f"created {args.wallet} (mode 600)\naddress: {wallet.address}\n\nWARNING: {DISCLAIMER}")
    print("The private key is stored unencrypted in that file.")


def wallet_address(args: argparse.Namespace) -> None:
    print(Wallet.load(args.wallet).address)


async def wallet_balance(args: argparse.Namespace) -> None:
    wallet = Wallet.load(args.wallet)
    client = RpcClient.from_url(args.rpc)
    try:
        info = await client.call("utxos", address=wallet.address)
    finally:
        await client.close()
    print(f"address:      {wallet.address}")
    print(f"spendable:    {format_coins(info['spendable'])}")
    print(f"immature:     {format_coins(info['immature'])}")
    print(f"incoming (unconfirmed): {format_coins(info['unconfirmed_incoming'])}")
    print(f"coins:        {len(info['coins'])}")


def spendable_coins(info: dict[str, object]) -> list[tuple[OutPoint, Coin]]:
    coins = []
    script = bytes.fromhex(str(info["script"]))
    for c in info["coins"]:  # type: ignore[attr-defined]
        if c["mature"] and not c["spent_in_mempool"]:
            outpoint = OutPoint(bytes.fromhex(c["txid"]), c["index"])
            coins.append((outpoint, Coin(TxOut(c["value"], script), c["height"], c["coinbase"])))
    return coins


def build_send(
    wallet: Wallet, coins: list[tuple[OutPoint, Coin]], to: str, amount: int, fee_rate: float
) -> Transaction:
    """Build a payment, sizing the fee from a first draft of the transaction."""
    outputs = [TxOut(amount, p2pkh(hash_from_address(to)))]
    draft = wallet.build_payment(coins, outputs, fee=0)
    fee = math.ceil((draft.size + 80) * fee_rate)  # margin for an extra input / change output
    return wallet.build_payment(coins, outputs, fee=fee)


async def wallet_send(args: argparse.Namespace) -> None:
    wallet = Wallet.load(args.wallet)
    client = RpcClient.from_url(args.rpc)
    try:
        info = await client.call("utxos", address=wallet.address)
        tx = build_send(wallet, spendable_coins(info), args.to, args.amount, args.fee_rate)
        result = await client.call("send_raw_tx", hex_tx=tx.serialize().hex())
    finally:
        await client.close()
    print(f"sent {format_coins(args.amount)} to {args.to}")
    print(f"txid: {result['txid']}  fee: {format_coins(result['fee'])}")


# -- external miner --------------------------------------------------------------------------


async def run_miner(args: argparse.Namespace) -> None:
    """getblocktemplate-style miner: grinds nonces locally, submits solved blocks."""
    client = RpcClient.from_url(args.rpc)
    found = 0
    print(f"mining to {args.address} via {args.rpc}")
    try:
        while args.blocks == 0 or found < args.blocks:
            template = await client.call("block_template", address=args.address)
            block = Block.deserialize(bytes.fromhex(template["block"]))
            started = time.monotonic()
            nonce = 0
            solved = None
            while solved is None and time.monotonic() - started < args.refresh:
                batch = 20_000
                solved = mine_header(block.header, nonce, batch)
                nonce += batch
                if args.hashrate:
                    await asyncio.sleep(batch / args.hashrate)
                info = await client.call("info") if nonce % 200_000 == 0 else None
                if info and info["tip"] != template["prev"]:
                    break  # someone else extended the chain: start over on the new tip
            if solved is None:
                continue
            result = await client.call(
                "submit_block", hex_block=Block(solved, block.txs).serialize().hex()
            )
            found += 1
            print(
                f"block {template['height']} {result['hash'][:16]} -> {result['status']}",
                flush=True,
            )
    finally:
        await client.close()


# -- simulator -------------------------------------------------------------------------------


def parse_window(text: str) -> tuple[float, float] | None:
    if text.lower() in ("none", "off", "no"):
        return None
    start, sep, end = text.partition(":")
    try:
        window = (float(start), float(end))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected START:END seconds, got {text!r}") from exc
    if not sep or window[0] >= window[1]:
        raise argparse.ArgumentTypeError("partition window must be START:END with START < END")
    return window


def parse_slow(text: str) -> tuple[str, float]:
    name, sep, ms = text.partition(":")
    if not sep:
        raise argparse.ArgumentTypeError(f"expected NODE:MS, got {text!r}")
    return name, float(ms)


async def run_sim(args: argparse.Namespace) -> None:
    from forkchain.sim.runner import SimConfig, Simulation

    groups = [g.split(",") for g in args.groups.split("|")] if args.groups else None
    config = SimConfig(
        nodes=args.nodes,
        duration=args.duration,
        block_time=args.block_time,
        hashrate=args.hashrate,
        whales=args.whales,
        whale_factor=args.whale_factor,
        latency_ms=args.latency,
        jitter_ms=args.jitter,
        slow=dict(args.slow),
        partition=args.partition,
        groups=groups,
        attack=args.attack,
        attack_start=args.attack_start,
        attack_confirmations=args.confirmations,
        tx_rate=args.tx_rate,
        seed=args.seed,
    )
    log = None if args.quiet or args.json else (lambda msg: print(msg, flush=True))
    report = await Simulation(config, log=log).run()
    if args.json:
        import json

        print(json.dumps(report.to_json(), indent=2))
    else:
        print(report.render())


# -- argument parsing ------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="forkchain", description=f"{DISCLAIMER}")
    parser.add_argument("--log-level", default="WARNING")
    sub = parser.add_subparsers(dest="command", required=True)

    node = sub.add_parser("node", help="run a full node")
    node.add_argument("--name", default="node")
    node.add_argument("--network", choices=sorted(NETWORKS), default="main")
    node.add_argument("--host", default="127.0.0.1", help="p2p bind address")
    node.add_argument("--port", type=int, default=8333)
    node.add_argument("--advertise-host", default=None, help="address peers should dial")
    node.add_argument("--rpc-host", default="127.0.0.1")
    node.add_argument("--rpc-port", type=int, default=8332)
    node.add_argument("--peer", type=parse_addr, action="append", default=[], metavar="HOST:PORT")
    node.add_argument("--mine", action="store_true", help="run the built-in miner")
    node.add_argument("--address", help="address that receives block rewards")
    node.add_argument("--hashrate", type=float, default=None, help="cap in hashes/second")
    node.add_argument("--status-interval", type=float, default=10.0)
    node.set_defaults(handler=run_node, is_async=True)

    wallet = sub.add_parser("wallet", help="manage a single-key wallet")
    wallet.add_argument("--wallet", type=Path, default=DEFAULT_WALLET)
    wsub = wallet.add_subparsers(dest="wallet_command", required=True)
    wsub.add_parser("new", help="generate a key").set_defaults(handler=wallet_new, is_async=False)
    wsub.add_parser("address", help="print the address").set_defaults(
        handler=wallet_address, is_async=False
    )
    balance = wsub.add_parser("balance", help="query a node for this wallet's coins")
    balance.add_argument("--rpc", default="127.0.0.1:8332")
    balance.set_defaults(handler=wallet_balance, is_async=True)
    send = wsub.add_parser("send", help="pay an address")
    send.add_argument("to")
    send.add_argument("amount", type=parse_coins)
    send.add_argument("--fee-rate", type=float, default=2.0, help="base units per byte")
    send.add_argument("--rpc", default="127.0.0.1:8332")
    send.set_defaults(handler=wallet_send, is_async=True)

    mine = sub.add_parser("mine", help="external miner talking to a node over RPC")
    mine.add_argument("--rpc", default="127.0.0.1:8332")
    mine.add_argument("--address", required=True)
    mine.add_argument("--blocks", type=int, default=0, help="stop after N blocks (0 = forever)")
    mine.add_argument("--hashrate", type=float, default=None)
    mine.add_argument("--refresh", type=float, default=5.0, help="seconds per template")
    mine.set_defaults(handler=run_miner, is_async=True)

    sim = sub.add_parser("sim", help="chaos simulation: N nodes in one process with faults")
    sim.add_argument("--nodes", type=int, default=5)
    sim.add_argument("--duration", type=float, default=40.0, help="seconds of mining")
    sim.add_argument("--block-time", type=float, default=1.0)
    sim.add_argument("--hashrate", type=float, default=4000.0, help="per ordinary node, H/s")
    sim.add_argument("--whales", type=int, default=0, help="nodes with boosted hashrate")
    sim.add_argument("--whale-factor", type=float, default=4.0)
    sim.add_argument("--latency", type=float, default=40.0, help="base one-way latency, ms")
    sim.add_argument("--jitter", type=float, default=30.0, help="random extra latency, ms")
    sim.add_argument("--slow", type=parse_slow, action="append", default=[], metavar="NODE:MS")
    sim.add_argument(
        "--partition", type=parse_window, default=(10.0, 25.0), metavar="START:END|none"
    )
    sim.add_argument("--groups", default=None, help='partition groups, e.g. "n0,n1|n2,n3,n4"')
    sim.add_argument("--attack", action="store_true", help="51%% double spend by n0")
    sim.add_argument("--attack-start", type=float, default=10.0)
    sim.add_argument("--confirmations", type=int, default=2)
    sim.add_argument("--tx-rate", type=float, default=2.0, help="random payments per second")
    sim.add_argument("--seed", type=int, default=1)
    sim.add_argument("--json", action="store_true", help="print the report as JSON")
    sim.add_argument("--quiet", action="store_true")
    sim.set_defaults(handler=run_sim, is_async=True)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), format="%(asctime)s %(name)s %(message)s")
    try:
        if args.is_async:
            with contextlib.suppress(KeyboardInterrupt):
                asyncio.run(args.handler(args))
        else:
            args.handler(args)
    except (ForkchainError, RpcError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
