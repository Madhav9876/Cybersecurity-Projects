"""Unit tests for the LockScore password strength checker."""

from __future__ import annotations

import pytest

from lockscore import PasswordChecker, StrengthLevel
from lockscore.validators import (
    LengthValidator,
    NumberValidator,
    RepeatedCharacterValidator,
    SequentialPatternValidator,
    SymbolValidator,
    UppercaseValidator,
)
from lockscore.leaked_passwords import LeakedPasswordValidator


class TestLengthValidator:
    def test_short_password_is_weak(self) -> None:
        result = LengthValidator().validate("abc")
        assert result.passed is False
        assert result.score == 5

    def test_eight_chars_passes(self) -> None:
        result = LengthValidator().validate("abcdefgh")
        assert result.passed is True
        assert result.score == 15

    def test_twenty_plus_chars_max_score(self) -> None:
        result = LengthValidator().validate("a" * 20)
        assert result.score == 40


class TestCharacterClassValidators:
    def test_uppercase_detected(self) -> None:
        result = UppercaseValidator().validate("abcD")
        assert result.passed is True
        assert result.score == 10

    def test_uppercase_missing(self) -> None:
        result = UppercaseValidator().validate("abcd")
        assert result.passed is False
        assert result.score == 0

    def test_number_detected(self) -> None:
        assert NumberValidator().validate("abc1").passed is True

    def test_symbol_detected(self) -> None:
        assert SymbolValidator().validate("abc!").passed is True

    def test_symbol_missing(self) -> None:
        assert SymbolValidator().validate("abc1").passed is False


class TestSequentialPatternValidator:
    def test_alpha_sequence_detected(self) -> None:
        result = SequentialPatternValidator().validate("Passwordabc123")
        assert result.passed is False
        assert result.score < 0

    def test_no_sequence(self) -> None:
        result = SequentialPatternValidator().validate("x9#kQ2mZ")
        assert result.passed is True
        assert result.score == 0


class TestRepeatedCharacterValidator:
    def test_repeated_run_detected(self) -> None:
        result = RepeatedCharacterValidator().validate("Paaaassword")
        assert result.passed is False
        assert result.score < 0

    def test_no_repeats(self) -> None:
        result = RepeatedCharacterValidator().validate("Pxaksword")
        assert result.passed is True


class TestLeakedPasswordValidator:
    def test_known_leaked_password(self) -> None:
        validator = LeakedPasswordValidator()
        result = validator.validate("password")
        assert result.passed is False
        assert result.score == -50

    def test_leet_substitution_caught(self) -> None:
        validator = LeakedPasswordValidator()
        result = validator.validate("p@ssword")
        assert result.passed is False

    def test_safe_password_passes(self) -> None:
        validator = LeakedPasswordValidator()
        result = validator.validate("Zx9!qK#mB2vL")
        assert result.passed is True


@pytest.fixture
def checker() -> PasswordChecker:
    return PasswordChecker()


class TestPasswordChecker:
    def test_empty_password_is_weak(self, checker: PasswordChecker) -> None:
        report = checker.evaluate("")
        assert report.level is StrengthLevel.WEAK
        assert report.score == 0

    def test_common_leaked_password_is_weak(self, checker: PasswordChecker) -> None:
        report = checker.evaluate("password")
        assert report.level is StrengthLevel.WEAK

    def test_short_all_lower_is_weak(self, checker: PasswordChecker) -> None:
        report = checker.evaluate("abc")
        assert report.level is StrengthLevel.WEAK

    def test_medium_password(self, checker: PasswordChecker) -> None:
        report = checker.evaluate("Kx9!mQ2p")
        assert report.level is StrengthLevel.MEDIUM

    def test_strong_password(self, checker: PasswordChecker) -> None:
        report = checker.evaluate("C0rrectHorse-Battery9Staple!")
        assert report.level is StrengthLevel.STRONG
        assert report.score >= 71

    def test_report_contains_suggestions_when_weak(self, checker: PasswordChecker) -> None:
        report = checker.evaluate("abc")
        assert report.suggestions
        assert any("length" in tip.lower() for tip in report.suggestions)

    def test_strong_report_has_no_suggestions(self, checker: PasswordChecker) -> None:
        report = checker.evaluate("C0rrectHorse-Battery9Staple!")
        assert report.suggestions == []

    def test_score_never_exceeds_100(self, checker: PasswordChecker) -> None:
        report = checker.evaluate("A" + "a1!" * 30)
        assert report.score <= 100

    def test_score_never_below_0(self, checker: PasswordChecker) -> None:
        report = checker.evaluate("password")
        assert report.score >= 0