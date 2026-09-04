"""Aggregates validation results into a single LockScore."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .validators import ValidationResult


class StrengthLevel(str, Enum):
    """Qualitative strength buckets: weak / medium / strong."""

    WEAK = "Weak"
    MEDIUM = "Medium"
    STRONG = "Strong"

    @classmethod
    def from_score(cls, score: int) -> "StrengthLevel":
        if score <= 40:
            return cls.WEAK
        if score <= 70:
            return cls.MEDIUM
        return cls.STRONG


@dataclass
class ScoreBreakdown:
    results: list[ValidationResult] = field(default_factory=list)
    max_possible: int = 100
    penalties: int = 0
    total: int = 0

    @property
    def level(self) -> StrengthLevel:
        return StrengthLevel.from_score(self.total)

    @property
    def percentage(self) -> float:
        if self.max_possible <= 0:
            return 0.0
        return round((self.total / self.max_possible) * 100, 1)


class Scorer:
    """Combines validator outputs into a ``ScoreBreakdown``."""

    def __init__(self, max_possible: int = 100) -> None:
        self._max_possible = max_possible

    def score(self, results: list[ValidationResult]) -> ScoreBreakdown:
        positive = sum(r.score for r in results if r.score > 0)
        penalties = sum(abs(r.score) for r in results if r.score < 0)
        total = max(0, min(self._max_possible, positive - penalties))
        return ScoreBreakdown(
            results=results,
            max_possible=self._max_possible,
            penalties=penalties,
            total=total,
        )


__all__ = ["StrengthLevel", "ScoreBreakdown", "Scorer"]