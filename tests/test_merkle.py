from dataclasses import replace

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from forkchain.crypto import ZERO_HASH, sha256d
from forkchain.merkle import (
    MerkleProof,
    ProofStep,
    Side,
    hash_leaf,
    hash_node,
    merkle_proof,
    merkle_root,
    verify_proof,
)

leaves_st = st.lists(st.binary(min_size=32, max_size=32), min_size=1, max_size=40, unique=True)


def test_empty_and_single() -> None:
    assert merkle_root([]) == ZERO_HASH
    leaf = sha256d(b"a")
    assert merkle_root([leaf]) == hash_leaf(leaf)
    assert merkle_proof([leaf], 0).steps == ()


def test_three_leaves_promotes_odd_node() -> None:
    a, b, c = (sha256d(x) for x in (b"a", b"b", b"c"))
    expected = hash_node(hash_node(hash_leaf(a), hash_leaf(b)), hash_leaf(c))
    assert merkle_root([a, b, c]) == expected


def test_duplicate_last_leaf_changes_root() -> None:
    # CVE-2012-2459: in Bitcoin [a, b, c] and [a, b, c, c] share a root. Not here.
    a, b, c = (sha256d(x) for x in (b"a", b"b", b"c"))
    assert merkle_root([a, b, c]) != merkle_root([a, b, c, c])


def test_leaf_cannot_masquerade_as_inner_node() -> None:
    a, b = sha256d(b"a"), sha256d(b"b")
    inner = hash_node(hash_leaf(a), hash_leaf(b))
    assert merkle_root([a, b]) != merkle_root([inner])


def test_proof_index_out_of_range() -> None:
    with pytest.raises(IndexError):
        merkle_proof([ZERO_HASH], 1)


@given(leaves_st, st.data())
def test_every_proof_verifies(leaves: list[bytes], data: st.DataObject) -> None:
    root = merkle_root(leaves)
    index = data.draw(st.integers(0, len(leaves) - 1))
    proof = merkle_proof(leaves, index)
    assert verify_proof(leaves[index], proof, root)
    assert len(proof.steps) <= max(1, len(leaves)).bit_length()


@given(leaves_st, st.data())
def test_proof_rejects_other_leaf(leaves: list[bytes], data: st.DataObject) -> None:
    assume(len(leaves) > 1)
    root = merkle_root(leaves)
    i = data.draw(st.integers(0, len(leaves) - 1))
    j = data.draw(st.integers(0, len(leaves) - 1).filter(lambda x: x != i))
    proof = merkle_proof(leaves, i)
    assert not verify_proof(leaves[j], proof, root)
    assert not verify_proof(leaves[j], replace(proof, leaf=leaves[j]), root)


@given(leaves_st, st.data())
def test_tampered_proof_fails(leaves: list[bytes], data: st.DataObject) -> None:
    assume(len(leaves) > 1)
    root = merkle_root(leaves)
    index = data.draw(st.integers(0, len(leaves) - 1))
    proof = merkle_proof(leaves, index)
    step_no = data.draw(st.integers(0, len(proof.steps) - 1))
    step = proof.steps[step_no]
    flip = data.draw(st.booleans())
    if flip:
        bad = ProofStep(step.sibling, Side.LEFT if step.side is Side.RIGHT else Side.RIGHT)
    else:
        byte = data.draw(st.integers(0, 31))
        sib = bytearray(step.sibling)
        sib[byte] ^= 0x01
        bad = ProofStep(bytes(sib), step.side)
    steps = list(proof.steps)
    steps[step_no] = bad
    tampered = MerkleProof(proof.leaf, proof.index, tuple(steps))
    # Swapping sides of two identical siblings would be a no-op; leaves are unique so the
    # sibling never equals the running hash.
    assert not verify_proof(leaves[index], tampered, root)


@given(leaves_st, st.data())
def test_root_changes_when_any_leaf_changes(leaves: list[bytes], data: st.DataObject) -> None:
    index = data.draw(st.integers(0, len(leaves) - 1))
    mutated = list(leaves)
    mutated[index] = sha256d(mutated[index])
    assume(mutated[index] not in leaves)
    assert merkle_root(mutated) != merkle_root(leaves)


def test_proof_json_shape() -> None:
    leaves = [sha256d(bytes([i])) for i in range(5)]
    doc = merkle_proof(leaves, 4).to_json()
    assert doc["index"] == 4
    assert all(set(s) == {"sibling", "side"} for s in doc["steps"])  # type: ignore[union-attr]
