"""LockScore - A password strength checker."""

from __future__ import annotations

from .checker import PasswordChecker, StrengthReport, StrengthLevel
from .scorer import ScoreBreakdown
from .validators import (
    LengthValidator,
    UppercaseValidator,
    LowercaseValidator,
    NumberValidator,
    SymbolValidator,
    SequentialPatternValidator,
    RepeatedCharacterValidator,
)
from .leaked_passwords import LeakedPasswordValidator

__all__ = [
    "PasswordChecker",
    "StrengthReport",
    "StrengthLevel",
    "ScoreBreakdown",
    "LengthValidator",
    "UppercaseValidator",
    "LowercaseValidator",
    "NumberValidator",
    "SymbolValidator",
    "SequentialPatternValidator",
    "RepeatedCharacterValidator",
    "LeakedPasswordValidator",
]

__version__ = "1.0.0"