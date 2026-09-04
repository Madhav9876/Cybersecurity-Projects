"""Command-line interface for LockScore."""

from __future__ import annotations

import argparse
import getpass
import sys
from typing import Iterable

from .checker import PasswordChecker, StrengthReport
from .scorer import StrengthLevel


_COLOURS = {
    StrengthLevel.WEAK: "\033[91m",
    StrengthLevel.MEDIUM: "\033[93m",
    StrengthLevel.STRONG: "\033[92m",
}
_RESET = "\033[0m"


def format_report(report: StrengthReport, *, use_colour: bool = True) -> str:
    colour = _COLOURS.get(report.level, "") if use_colour else ""
    reset = _RESET if use_colour else ""

    lines: list[str] = []
    lines.append(f"{colour}LockScore: {report.score}/100  [{report.level.value}]{reset}")
    lines.append(f"Strength percentage: {report.breakdown.percentage}%")
    if report.breakdown.penalties:
        lines.append(f"Penalties applied: -{report.breakdown.penalties} points")
    lines.append("")
    lines.append("Breakdown:")
    for result in report.breakdown.results:
        marker = "[+]" if result.passed else "[-]"
        score_text = f"{result.score:+d}" if result.score else "  0"
        lines.append(f"  {marker} {score_text}  {result.name}: {result.message}")

    if report.suggestions:
        lines.append("")
        lines.append("Suggestions to improve your password:")
        for tip in report.suggestions:
            lines.append(f"  * {tip}")

    return "\n".join(lines)


def _evaluate_one(checker: PasswordChecker, password: str) -> StrengthReport:
    report = checker.evaluate(password)
    print(format_report(report, use_colour=sys.stdout.isatty()))
    return report


def _iter_batch_file(path: str) -> Iterable[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pw = line.strip()
            if pw:
                yield pw


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lockscore",
        description="LockScore - check whether a password is weak, medium, or strong.",
    )
    parser.add_argument(
        "password",
        nargs="?",
        default=None,
        help="Password to evaluate. If omitted, an interactive prompt is used.",
    )
    parser.add_argument(
        "--batch",
        metavar="FILE",
        default=None,
        help="Evaluate every password listed in FILE (one per line).",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        default=False,
        help="Show the password as you type it in the interactive prompt.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    checker = PasswordChecker()

    if args.batch:
        for pw in _iter_batch_file(args.batch):
            print("=" * 60)
            _evaluate_one(checker, pw)
        return 0

    if args.password is not None:
        _evaluate_one(checker, args.password)
        return 0

    prompt_fn = input if args.show else getpass.getpass
    print("LockScore interactive mode. Type 'quit' (or Ctrl+C) to exit.")
    if args.show:
        print("Password visibility is ON (--show).")
    while True:
        try:
            pw = prompt_fn("Enter password: ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if pw.strip().lower() in {"quit", "exit"}:
            break
        if not pw:
            print("Please enter a non-empty password.")
            continue
        print(f"Entered password: {pw}")
        _evaluate_one(checker, pw)
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())