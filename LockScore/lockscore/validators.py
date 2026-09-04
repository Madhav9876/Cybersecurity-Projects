"""Individual password validation checks."""

from __future__ import annotations

import string
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class ValidationResult:
    name: str
    passed: bool
    score: int
    max_score: int
    message: str


class Validator(Protocol):
    name: str
    max_score: int

    def validate(self, password: str) -> ValidationResult:  # pragma: no cover
        ...


class LengthValidator:
    """Award points based on password length."""

    name = "Length check"
    max_score = 40

    _LENGTH_BUCKETS = (
        (20, 40),
        (16, 32),
        (12, 25),
        (8, 15),
        (0, 5),
    )

    def validate(self, password: str) -> ValidationResult:
        length = len(password)
        for threshold, score in self._LENGTH_BUCKETS:
            if length >= threshold:
                message = self._build_message(length)
                return ValidationResult(
                    name=self.name,
                    passed=length >= 8,
                    score=score,
                    max_score=self.max_score,
                    message=message,
                )
        raise RuntimeError("Length bucket selection failed")  # pragma: no cover

    @staticmethod
    def _build_message(length: int) -> str:
        if length >= 20:
            return f"Excellent length ({length} characters)."
        if length >= 16:
            return f"Great length ({length} characters)."
        if length >= 12:
            return f"Good length ({length} characters)."
        if length >= 8:
            return f"Acceptable length ({length} characters), but longer is safer."
        return f"Too short ({length} characters). Use at least 8."


class _CharacterClassValidator:
    """Shared implementation for the four character-class checks."""

    name = "Character class"
    max_score = 10
    _label = "characters"
    _charset: str = ""

    def validate(self, password: str) -> ValidationResult:
        count = sum(1 for ch in password if ch in self._charset)
        passed = count > 0
        score = self.max_score if passed else 0
        if passed:
            message = f"Contains {count} {self._label}."
        else:
            message = f"No {self._label} found."
        return ValidationResult(
            name=self.name,
            passed=passed,
            score=score,
            max_score=self.max_score,
            message=message,
        )


class UppercaseValidator(_CharacterClassValidator):
    name = "Uppercase letters"
    _label = "uppercase letter(s)"
    _charset = string.ascii_uppercase


class LowercaseValidator(_CharacterClassValidator):
    name = "Lowercase letters"
    _label = "lowercase letter(s)"
    _charset = string.ascii_lowercase


class NumberValidator(_CharacterClassValidator):
    name = "Numbers"
    _label = "digit(s)"
    _charset = string.digits


class SymbolValidator(_CharacterClassValidator):
    name = "Symbols"
    _label = "symbol(s)"
    _charset = string.punctuation


class SequentialPatternValidator:
    """Detect sequential runs such as ``abc``, ``321``, or ``qwerty``."""

    name = "Sequential pattern check"
    max_score = 0

    _ALPHA_FORWARD = "abcdefghijklmnopqrstuvwxyz"
    _ALPHA_REVERSE = "zyxwvutsrqponmlkjihgfedcba"
    _DIGIT_FORWARD = "0123456789"
    _DIGIT_REVERSE = "9876543210"
    _KEYBOARD_ROWS = (
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    )

    def validate(self, password: str) -> ValidationResult:
        lowered = password.lower()
        sequences = self._find_sequences(lowered)
        penalty = min(len(sequences) * 10, 30)
        if sequences:
            examples = ", ".join(repr(s) for s in sequences[:3])
            message = f"Sequential pattern(s) found: {examples}."
        else:
            message = "No sequential patterns detected."
        return ValidationResult(
            name=self.name,
            passed=len(sequences) == 0,
            score=-penalty,
            max_score=0,
            message=message,
        )

    def _find_sequences(self, text: str) -> list[str]:
        found: list[str] = []
        candidates = (
            [self._ALPHA_FORWARD, self._ALPHA_REVERSE]
            + [self._DIGIT_FORWARD, self._DIGIT_REVERSE]
            + list(self._KEYBOARD_ROWS)
        )
        window = 3
        for candidate in candidates:
            for i in range(len(candidate) - window + 1):
                chunk = candidate[i : i + window]
                if chunk in text and chunk not in found:
                    found.append(chunk)
        return found


class RepeatedCharacterValidator:
    """Detect runs of the same character (e.g. ``aaa``, ``111``)."""

    name = "Repeated character check"
    max_score = 0

    def validate(self, password: str) -> ValidationResult:
        runs = self._find_runs(password)
        penalty = min(len(runs) * 10, 30)
        if runs:
            examples = ", ".join(repr(r) for r in runs[:3])
            message = f"Repeated character run(s) found: {examples}."
        else:
            message = "No significant repeated characters."
        return ValidationResult(
            name=self.name,
            passed=len(runs) == 0,
            score=-penalty,
            max_score=0,
            message=message,
        )

    @staticmethod
    def _find_runs(text: str) -> list[str]:
        runs: list[str] = []
        if len(text) < 3:
            return runs
        i = 0
        while i < len(text) - 2:
            if text[i] == text[i + 1] == text[i + 2]:
                j = i + 2
                while j < len(text) and text[j] == text[i]:
                    j += 1
                runs.append(text[i:j])
                i = j
            else:
                i += 1
        return runs


__all__ = [
    "ValidationResult",
    "Validator",
    "LengthValidator",
    "UppercaseValidator",
    "LowercaseValidator",
    "NumberValidator",
    "SymbolValidator",
    "SequentialPatternValidator",
    "RepeatedCharacterValidator",
]