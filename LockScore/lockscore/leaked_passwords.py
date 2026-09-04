"""Checks a password against a database of common / leaked passwords."""

from __future__ import annotations

import os
from pathlib import Path

from .validators import ValidationResult


_DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent / "data" / "common_passwords.txt"


class LeakedPasswordValidator:
    """Penalise passwords found in a known-bad wordlist."""

    name = "Leaked password check"
    max_score = 0

    def __init__(
        self,
        wordlist_path: str | os.PathLike[str] | None = None,
        penalty: int = 50,
    ) -> None:
        self._path = Path(wordlist_path) if wordlist_path else _DEFAULT_WORDLIST
        self._penalty = penalty
        self._wordlist: set[str] = self._load_wordlist()

    def _load_wordlist(self) -> set[str]:
        if not self._path.exists():
            return set()
        with self._path.open("r", encoding="utf-8", errors="ignore") as fh:
            return {line.strip().lower() for line in fh if line.strip()}

    def validate(self, password: str) -> ValidationResult:
        if not self._wordlist:
            return ValidationResult(
                name=self.name,
                passed=True,
                score=0,
                max_score=0,
                message="No leaked-password database loaded.",
            )

        lowered = password.lower()
        match_reason = self._find_match(lowered)
        if match_reason is None:
            return ValidationResult(
                name=self.name,
                passed=True,
                score=0,
                max_score=0,
                message="Password not found in leaked-password database.",
            )

        return ValidationResult(
            name=self.name,
            passed=False,
            score=-self._penalty,
            max_score=0,
            message=f"Password is compromised ({match_reason}).",
        )

    def _find_match(self, lowered: str) -> str | None:
        if lowered in self._wordlist:
            return "exact match in common-password list"

        # Common trivial substitutions (l33t-speak) that attackers try first.
        substitutions = str.maketrans({"0": "o", "1": "i", "3": "e", "@": "a", "$": "s"})
        normalised = lowered.translate(substitutions)
        if normalised != lowered and normalised in self._wordlist:
            return "match after reversing common substitutions"

        if lowered[::-1] in self._wordlist:
            return "reversed password found in common-password list"

        return None


__all__ = ["LeakedPasswordValidator"]