"""Validation error hierarchy.

The P2P layer uses the distinction to decide whether a peer should be punished: a
``ValidationError`` means the peer sent provably invalid data, while a
``MissingDataError`` means we simply lack context (unknown parent, unknown input) and
must not ban for it.
"""

from __future__ import annotations


class ForkchainError(Exception):
    pass


class ValidationError(ForkchainError):
    """Data violates consensus or policy rules."""

    def __init__(self, code: str, message: str = "", *, ban: bool = True) -> None:
        super().__init__(f"{code}: {message}" if message else code)
        self.code = code
        self.ban = ban


class MissingDataError(ForkchainError):
    """Validation cannot proceed yet: a parent block or an input is unknown."""
