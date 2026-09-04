"""ShieldCode - interactive command-line interface.

Run with:  python main.py

The CLI presents a menu that lets the user:
  1. Encrypt text  (Caesar or Vigenere)
  2. Decrypt text  (Caesar or Vigenere)
  3. Run a built-in self-test that proves encrypt -> decrypt round-trips
  4. Quit

All user input is validated before it reaches the cipher logic.
"""

from __future__ import annotations

from .ciphers import (
    caesar_decrypt,
    caesar_encrypt,
    vigenere_decrypt,
    vigenere_encrypt,
)

BANNER = r"""
  __ _ _   _  ___ _   _ _ __ ___  __ _  ___ _ __
 / _` | | | |/ __| | | | '__/ _ \/ _` |/ _ \ '__|
| (_| | |_| | (__| |_| | | |  __/ (_| |  __/ |
 \__,_|\__,_|\___|\__,_|_|  \___|\__, |\___|_|
                                  |___/
        Basic Encryption & Decryption
"""


# --------------------------------------------------------------------------- #
# Input helpers
# --------------------------------------------------------------------------- #
def _prompt_nonempty(prompt: str) -> str:
    """Keep asking until the user provides a non-empty (non-blank) string."""
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("  ! Input cannot be empty. Please try again.")


def _prompt_int(prompt: str) -> int:
    """Keep asking until the user provides a valid integer."""
    while True:
        raw = input(prompt).strip()
        try:
            return int(raw)
        except ValueError:
            print("  ! Please enter a whole number (e.g. 3 or -5).")


def _choose_cipher() -> str:
    """Let the user pick a cipher. Returns 'caesar' or 'vigenere'."""
    while True:
        choice = input("  Cipher [1] Caesar  [2] Vigenere: ").strip()
        if choice == "1":
            return "caesar"
        if choice == "2":
            return "vigenere"
        print("  ! Invalid choice. Enter 1 or 2.")


def _get_key(cipher: str):
    """Return the appropriate key for the chosen cipher.

    For Caesar this is an int shift; for Vigenere it is a keyword string.
    """
    if cipher == "caesar":
        return _prompt_int("  Enter shift key (integer, e.g. 3): ")
    # vigenere
    while True:
        keyword = _prompt_nonempty("  Enter keyword (letters only): ")
        if any(c.isalpha() for c in keyword):
            return keyword
        print("  ! Keyword must contain at least one letter.")


# --------------------------------------------------------------------------- #
# Core actions
# --------------------------------------------------------------------------- #
def _do_encrypt() -> None:
    print("\n--- Encrypt ---")
    cipher = _choose_cipher()
    text = _prompt_nonempty("  Enter text to encrypt: ")
    key = _get_key(cipher)

    if cipher == "caesar":
        result = caesar_encrypt(text, key)
    else:
        result = vigenere_encrypt(text, key)

    print("\n  Plaintext : " + text)
    print("  Ciphertext: " + result)
    print("  (Cipher: " + cipher + ", Key: " + str(key) + ")")


def _do_decrypt() -> None:
    print("\n--- Decrypt ---")
    cipher = _choose_cipher()
    text = _prompt_nonempty("  Enter text to decrypt: ")
    key = _get_key(cipher)

    if cipher == "caesar":
        result = caesar_decrypt(text, key)
    else:
        result = vigenere_decrypt(text, key)

    print("\n  Ciphertext: " + text)
    print("  Plaintext : " + result)
    print("  (Cipher: " + cipher + ", Key: " + str(key) + ")")


def _do_self_test() -> None:
    """Run a few round-trip checks and report pass/fail."""
    print("\n--- Self-test (encrypt -> decrypt round-trip) ---")
    cases = [
        ("caesar", "Hello, World!", 3),
        ("caesar", "ShieldCode 2026", -7),
        ("caesar", "ABCXYZ abcxyz", 30),  # shift > 26
        ("vigenere", "Attack at Dawn!", "LEMON"),
    ]
    all_passed = True
    for cipher, text, key in cases:
        if cipher == "caesar":
            enc = caesar_encrypt(text, key)
            dec = caesar_decrypt(enc, key)
        else:
            enc = vigenere_encrypt(text, key)
            dec = vigenere_decrypt(enc, key)
        ok = dec == text
        all_passed = all_passed and ok
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {cipher:8} key={str(key):10} "
              f"text={text!r} -> {enc!r} -> {dec!r}")
    print("\n  All tests passed!" if all_passed else "\n  Some tests FAILED.")
    print("  This confirms decrypt(encrypt(text, key), key) == text.")


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #
def main() -> None:
    print(BANNER)
    print("  Data Confidentiality through classical ciphers.\n")

    actions = {
        "1": _do_encrypt,
        "2": _do_decrypt,
        "3": _do_self_test,
    }

    while True:
        print("\n========================================")
        print("  Menu")
        print("    1) Encrypt text")
        print("    2) Decrypt text")
        print("    3) Run self-test")
        print("    4) Quit")
        print("========================================")
        choice = input("  Select an option: ").strip()

        if choice == "4":
            print("\n  Goodbye! Stay secure.\n")
            break
        action = actions.get(choice)
        if action is None:
            print("  ! Invalid option. Please choose 1-4.")
            continue
        action()


if __name__ == "__main__":
    main()