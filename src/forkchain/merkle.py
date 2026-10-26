"""Merkle tree over transaction ids, with inclusion proofs.

Unlike Bitcoin, leaves and inner nodes are domain-separated (``0x00`` / ``0x01`` prefixes,
as in RFC 6962) and an odd node is promoted to the next level instead of being paired with
itself. Both choices close the CVE-2012-2459 class of bugs, where two different transaction
lists produce the same root.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from forkchain.crypto import ZERO_HASH, sha256d

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


class Side(StrEnum):
    """Which side the *sibling* sits on when folding the proof upwards."""

    LEFT = "L"
    RIGHT = "R"


@dataclass(frozen=True)
class ProofStep:
    sibling: bytes
    side: Side


@dataclass(frozen=True)
class MerkleProof:
    leaf: bytes
    index: int
    steps: tuple[ProofStep, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "leaf": self.leaf.hex(),
            "index": self.index,
            "steps": [{"sibling": s.sibling.hex(), "side": s.side.value} for s in self.steps],
        }


def hash_leaf(leaf: bytes) -> bytes:
    return sha256d(LEAF_PREFIX + leaf)


def hash_node(left: bytes, right: bytes) -> bytes:
    return sha256d(NODE_PREFIX + left + right)


def _levels(leaves: Sequence[bytes]) -> list[list[bytes]]:
    level = [hash_leaf(leaf) for leaf in leaves]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(hash_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # odd node is promoted unchanged
        levels.append(nxt)
        level = nxt
    return levels


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    if not leaves:
        return ZERO_HASH
    return _levels(leaves)[-1][0]


def merkle_proof(leaves: Sequence[bytes], index: int) -> MerkleProof:
    if not 0 <= index < len(leaves):
        raise IndexError(f"leaf index {index} out of range for {len(leaves)} leaves")
    steps: list[ProofStep] = []
    pos = index
    for level in _levels(leaves)[:-1]:
        sibling_pos = pos ^ 1
        if sibling_pos < len(level):
            side = Side.LEFT if sibling_pos < pos else Side.RIGHT
            steps.append(ProofStep(level[sibling_pos], side))
        pos //= 2
    return MerkleProof(leaf=leaves[index], index=index, steps=tuple(steps))


def compute_root_from_proof(leaf: bytes, steps: Sequence[ProofStep]) -> bytes:
    acc = hash_leaf(leaf)
    for step in steps:
        acc = (
            hash_node(step.sibling, acc) if step.side is Side.LEFT else hash_node(acc, step.sibling)
        )
    return acc


def verify_proof(leaf: bytes, proof: MerkleProof, root: bytes) -> bool:
    """Check that ``leaf`` is committed to by ``root`` according to ``proof``."""
    if leaf != proof.leaf:
        return False
    return compute_root_from_proof(leaf, proof.steps) == root
