"""The core password-checking engine."""

from __future__ import annotations

from dataclasses import dataclass, field

from .scorer import ScoreBreakdown, Scorer, StrengthLevel
from .validators import (
    LengthValidator,
    LowercaseValidator,
    NumberValidator,
    RepeatedCharacterValidator,
    SequentialPatternValidator,
    SymbolValidator,
    UppercaseValidator,
    ValidationResult,
    Validator,
)
from .leaked_passwords import LeakedPasswordValidator


@dataclass
class StrengthReport:
    password: str
    score: int
    level: StrengthLevel
    breakdown: ScoreBreakdown
    suggestions: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.level is not StrengthLevel.WEAK


class PasswordChecker:
    """Evaluate a password and produce a ``StrengthReport``."""

    def __init__(
        self,
        validators: list[Validator] | None = None,
        scorer: Scorer | None = None,
    ) -> None:
        self._validators: list[Validator] = validators or self._default_validators()
        self._scorer = scorer or Scorer()

    @staticmethod
    def _default_validators() -> list[Validator]:
        return [
            LengthValidator(),
            UppercaseValidator(),
            LowercaseValidator(),
            NumberValidator(),
            SymbolValidator(),
            SequentialPatternValidator(),
            RepeatedCharacterValidator(),
            LeakedPasswordValidator(),
        ]

    def evaluate(self, password: str) -> StrengthReport:
        if not password:
            return self._empty_report(password)

        results = [validator.validate(password) for validator in self._validators]
        breakdown = self._scorer.score(results)
        suggestions = self._build_suggestions(results)
        return StrengthReport(
            password=password,
            score=breakdown.total,
            level=breakdown.level,
            breakdown=breakdown,
            suggestions=suggestions,
        )

    def _empty_report(self, password: str) -> StrengthReport:
        empty_breakdown = ScoreBreakdown(results=[], max_possible=100, penalties=0, total=0)
        return StrengthReport(
            password=password,
            score=0,
            level=StrengthLevel.WEAK,
            breakdown=empty_breakdown,
            suggestions=["Provide a non-empty password."],
        )

    @staticmethod
    def _build_suggestions(results: list[ValidationResult]) -> list[str]:
        suggestions: list[str] = []
        for result in results:
            if result.passed:
                continue
            if result.name == "Length check":
                suggestions.append("Increase length to at least 12 characters.")
            elif result.name == "Uppercase letters":
                suggestions.append("Add one or more uppercase letters.")
            elif result.name == "Lowercase letters":
                suggestions.append("Add one or more lowercase letters.")
            elif result.name == "Numbers":
                suggestions.append("Add one or more digits.")
            elif result.name == "Symbols":
                suggestions.append("Add one or more symbols (e.g. !@#$%).")
            elif result.name == "Sequential pattern check":
                suggestions.append("Avoid sequences like 'abc', '123', or 'qwerty'.")
            elif result.name == "Repeated character check":
                suggestions.append("Avoid repeating the same character (e.g. 'aaa').")
            elif result.name == "Leaked password check":
                suggestions.append("Do not use a known leaked password; pick something unique.")
        return suggestions


__all__ = ["PasswordChecker", "StrengthReport"]