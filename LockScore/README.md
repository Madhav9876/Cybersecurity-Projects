# LockScore — Password Strength Checker

**Cyber Security · Project 1**
*Defensive phase: evaluate password risk through pure string-handling and conditional logic.*

---

## Overview

LockScore is a modular, offline password-strength checker that classifies a
password as **Weak**, **Medium**, or **Strong** and produces a transparent,
per-rule score breakdown.

The tool operates entirely offline — no password ever leaves the local machine —
making it suitable for security-conscious environments.

---

## Table of Contents

1. [Specifications](#1-specifications)
2. [Technology Stack](#2-technology-stack)
3. [System Architecture](#3-system-architecture)
4. [The LockScore Algorithm](#4-the-lockscore-algorithm)
5. [Modular Implementation Guide](#5-modular-implementation-guide)
6. [Project Structure](#6-project-structure)
7. [Installation & Usage](#7-installation--usage)
8. [Testing](#8-testing)
9. [Extending LockScore](#9-extending-lockscore)

---

## 1. Specifications

The following requirements were distilled directly from the project brief.

### 1.1 Goal

> Create a program that checks whether a password is **weak**, **medium**, or **strong**.

### 1.2 Functional Requirements

| ID | Requirement | Implementation |
|----|-------------|----------------|
| FR-1 | Check password **length** | `LengthValidator` |
| FR-2 | Check use of **numbers** | `NumberValidator` |
| FR-3 | Check use of **symbols** | `SymbolValidator` |
| FR-4 | Check use of **uppercase letters** | `UppercaseValidator` |
| FR-5 | **Display** the password-strength result | `cli.format_report` |
| FR-6 | Classify as Weak / Medium / Strong | `StrengthLevel` |

### 1.3 Key Skills

- String handling
- Condition checks
- Security fundamentals

### 1.4 Bonus Features

The project brief explicitly invited additional hardening checks. The following
have been implemented:

| Feature | Implementation |
|---------|----------------|
| Leaked-password detection | `LeakedPasswordValidator` + `data/common_passwords.txt` |
| Character variety | `LowercaseValidator` + sequential/repeat pattern detection |

### 1.5 Constraints

- Emphasis on **pure string-handling and conditional logic** — no external
  entropy libraries or network calls are required.
- The project must be verifiable for quality (the brief states *"All projects
  must be verified for quality"*), so a comprehensive test suite is included.

---

## 2. Technology Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| **Language** | Python 3.10+ | First-class string handling, readable conditionals, and the de-facto language of cybersecurity tooling. |
| **Standard library** | `string`, `getpass`, `argparse`, `dataclasses`, `enum`, `pathlib` | Covers 100% of the core logic with zero runtime dependencies. |
| **Testing** | `pytest` | Minimal boilerplate, expressive assertions; aligns with the brief's quality-verification mandate. |
| **Packaging** | Plain package + `requirements.txt` | Keeps the project lightweight and easy to distribute. |
| **Interface** | CLI (interactive + inline + batch) | Satisfies the "display password strength result" requirement while remaining fully scriptable. |

---

## 3. System Architecture

LockScore follows a **Strategy + Pipeline** architecture:

```
                         ┌──────────────────────────────────────────┐
                         │                 CLI / API                │
                         │   (argparse, getpass, batch reader)      │
                         └────────────────────┬─────────────────────┘
                                              │  password: str
                                              ▼
                         ┌──────────────────────────────────────────┐
                         │            PasswordChecker               │
                         │   (orchestrator / facade)                │
                         └────────────────────┬─────────────────────┘
                                              │
            ┌─────────────────────────────────┼─────────────────────────────────┐
            ▼                                 ▼                                 ▼
  ┌──────────────────┐         ┌──────────────────────┐         ┌────────────────────┐
  │   Validators     │         │       Scorer         │         │  LeakedPassword    │
  │  (Strategy list) │ ──results──▶ │ (aggregator)   │         │  Validator          │
  │                  │         │                      │         │  (+ wordlist data)  │
  │ - Length         │         │  positive - penalties│         └────────────────────┘
  │ - Uppercase      │         │  → 0..100 score      │
  │ - Lowercase      │         │  → StrengthLevel      │
  │ - Numbers        │         └──────────┬───────────┘
  │ - Symbols        │                    │
  │ - Sequential     │                    ▼
  │ - Repeated       │         ┌──────────────────────┐
  └──────────────────┘         │   StrengthReport      │ ──▶ format_report ──▶ user
                               │  (score, level,      │
                               │   breakdown, tips)   │
                               └──────────────────────┘
```

### Design Principles

- **Single Responsibility**: Each validator checks exactly one rule.
- **Open/Closed**: Add a new check by implementing the `Validator` protocol —
  no edits to `PasswordChecker` are required.
- **Side-effect Free**: Validators are pure functions of the password string,
  making them trivial to unit-test.
- **Offline by Design**: The leaked-password wordlist is a local text file, so
  no password ever leaves the machine.

---

## 4. The LockScore Algorithm

The score is a 0–100 integer combining **positive points** for good practices
and **penalties** for risky patterns.

### 4.1 Positive Points (max 100)

| Rule | Max Points | Scoring Detail |
|------|-----------:|----------------|
| **Length** | 40 | `<8 → 5`, `8–11 → 15`, `12–15 → 25`, `16–19 → 32`, `20+ → 40` |
| **Uppercase letters** | 10 | `+10` if ≥1 present, else `0` |
| **Lowercase letters** | 10 | `+10` if ≥1 present, else `0` |
| **Numbers** | 10 | `+10` if ≥1 digit present, else `0` |
| **Symbols** | 10 | `+10` if ≥1 symbol present, else `0` |

### 4.2 Penalties (subtracted from the positive total)

| Rule | Penalty | Detail |
|------|--------:|--------|
| **Sequential patterns** | up to −30 | `−10` per detected run (`abc`, `321`, `qwerty`, …), capped at 30 |
| **Repeated characters** | up to −30 | `−10` per run of ≥3 identical chars (`aaa`, `111`), capped at 30 |
| **Leaked password** | −50 | Exact match, l33t-substitution match, or reversed match in the wordlist |

### 4.3 Final Mapping

```
final = clamp(positive_total - penalties, 0, 100)

score ≤ 40  → Weak
score ≤ 70  → Medium
score ≥ 71  → Strong
```

### 4.4 Worked Examples

| Password | Positive | Penalties | Final | Level |
|----------|---------:|----------:|------:|-------|
| `abc` | 5 (len) + 10 (lower) = 15 | 0 | 15 | Weak |
| `password` | 15 + 10 = 25 | −50 (leaked) | 0 | Weak |
| `Abc123!x` | 15 + 10×4 = 55 | 0 | 55 | Medium |
| `C0rrectHorse-Battery9Staple!` | 40 + 10×4 = 80 | 0 | 80 | Strong |

---

## 5. Modular Implementation Guide

Each module is a building block. Implement (or extend) them in this order:

### Step 1 — `validators.py`

Define the `Validator` protocol and `ValidationResult` dataclass, then one
class per rule. Each class exposes `name`, `max_score`, and `validate()`.

### Step 2 — `scorer.py`

Implement `Scorer.score()` to sum positives, subtract penalties, and clamp.
`StrengthLevel.from_score()` maps the number to Weak/Medium/Strong.

### Step 3 — `leaked_passwords.py`

Load `data/common_passwords.txt` into a `set`, then check exact, l33t, and
reversed matches. Returns a negative-score `ValidationResult`.

### Step 4 — `checker.py`

`PasswordChecker` holds the validator list + scorer. `evaluate()` runs every
validator, scores the results, and builds a `StrengthReport` with suggestions.

### Step 5 — `cli.py`

Parse arguments, call `checker.evaluate()`, and render the report with
`format_report()`. Supports inline, interactive, and batch modes.

### Step 6 — `tests/test_checker.py`

Cover each validator in isolation, then integration-test the full checker for
the Weak/Medium/Strong boundaries and score clamping.

---

## 6. Project Structure

```
LockScore/
├── README.md                       # This document
├── requirements.txt                # pytest (core is stdlib-only)
├── main.py                         # Entry point: python main.py
├── data/
│   └── common_passwords.txt         # Local leaked-password wordlist
├── lockscore/
│   ├── __init__.py                 # Public API re-exports
│   ├── __main__.py                 # Enables `python -m lockscore`
│   ├── validators.py               # Individual rule checks
│   ├── scorer.py                    # Score aggregation + StrengthLevel
│   ├── leaked_passwords.py          # Leaked-password validator
│   ├── checker.py                   # PasswordChecker + StrengthReport
│   └── cli.py                      # Command-line interface
└── tests/
    └── test_checker.py             # Unit + integration tests
```

---

## 7. Installation & Usage

### Installation

```bash
pip install -r requirements.txt
```

### Evaluate a Single Password (Inline Mode)

```bash
python main.py "MyP@ssw0rd!"
# or
python -m lockscore "MyP@ssw0rd!"
```

### Interactive Mode

```bash
python main.py
```

In interactive mode, the password is hidden while typing for shoulder-surfing
protection. After entry, the password is echoed back so you can confirm what
was checked before the report is displayed.

#### Visible Password Entry

To display the password as you type (in addition to the post-entry echo),
pass the `--show` flag:

```bash
python main.py --show
# or
python -m lockscore --show
```

### Batch Mode

Evaluate every password listed in a file (one per line):

```bash
python main.py --batch passwords.txt
```

### Example Output

```
LockScore: 80/100  [Strong]
Strength percentage: 80.0%

Breakdown:
  [+]  +40  Length check: Excellent length (29 characters).
  [+]  +10  Uppercase letters: Contains 3 uppercase letter(s).
  [+]  +10  Lowercase letters: Contains 18 lowercase letter(s).
  [+]  +10  Numbers: Contains 3 digit(s).
  [+]  +10  Symbols: Contains 2 symbol(s).
  [+]    0  Sequential pattern check: No sequential patterns detected.
  [+]    0  Repeated character check: No significant repeated characters.
  [+]    0  Leaked password check: Password not found in leaked-password database.
```

---

## 8. Testing

```bash
python -m pytest -q
```

The test suite covers:

- Each validator in isolation (length, character classes, patterns, leaked).
- Integration paths through `PasswordChecker` for Weak / Medium / Strong.
- Edge cases: empty password, score clamping at 0 and 100.

---

## 9. Extending LockScore

To add a new rule, implement the `Validator` protocol and pass it to the
checker:

```python
from lockscore import PasswordChecker
from lockscore.validators import Validator, ValidationResult

class EntropyValidator:
    name = "Shannon entropy"
    max_score = 20

    def validate(self, password: str) -> ValidationResult:
        # ...your logic...
        return ValidationResult(self.name, passed, score, self.max_score, msg)

checker = PasswordChecker(validators=[*PasswordChecker._default_validators(),
                                      EntropyValidator()])
```

### Ideas for Further Hardening

- Expand `data/common_passwords.txt` with a larger open wordlist.
- Add a dictionary-attack simulator for common base words.
- Add a passphrase mode that rewards word count over complexity.

---

*Built for the DecodeLabs Cyber Security Project 1 — "Security Logic through
string-handling and conditional logic."*