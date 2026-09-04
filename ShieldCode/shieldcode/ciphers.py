"""
ShieldCode - Core cryptographic logic.

This module implements two classical, reversible ciphers:

1. Caesar cipher
   A monoalphabetic substitution cipher. Every letter in the plaintext is
   shifted forward by a fixed integer `key` (the "shift") within its alphabet.
   Non-letter characters (spaces, digits, punctuation) are left untouched so
   the process is fully reversible. Decryption simply shifts each letter
   backward by the same amount.

   Mathematically, for a letter with alphabet index `x` (0-based) and an
   alphabet of size `m` (26 for English):

       encrypt(x) = (x + key) mod m
       decrypt(x) = (x - key) mod m

2. Vigenere cipher
   A polyalphabetic substitution cipher. Instead of a single fixed shift, a
   repeating keyword supplies a different shift for each plaintext letter.
   The shift applied to the i-th plaintext letter is the alphabet index of the
   i-th keyword letter (cycling the keyword as needed). Non-letters are skipped
   and do not advance the keyword pointer, which keeps the mapping reversible.

   For plaintext letter index x_i and keyword letter index k_i:

       encrypt(x_i) = (x_i + k_i) mod m
       decrypt(x_i) = (x_i - k_i) mod m

Both implementations preserve the case of each letter and leave non-alphabetic
characters unchanged, guaranteeing that:

       decrypt(encrypt(text, key), key) == text
"""

from __future__ import annotations

LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_SIZE = 26  # length of the English alphabet


def _shift_char(char: str, shift: int) -> str:
    """Shift a single alphabetic `char` by `shift` positions.

    Preserves case. Non-alphabetic characters are returned unchanged.
    The shift is normalized with modulo arithmetic so it works for any
    integer (including negatives and values larger than 26).
    """
    if char in LOWERCASE:
        base = ord("a")
        return chr((ord(char) - base + shift) % ALPHABET_SIZE + base)
    if char in UPPERCASE:
        base = ord("A")
        return chr((ord(char) - base + shift) % ALPHABET_SIZE + base)
    return char


# --------------------------------------------------------------------------- #
# Caesar cipher
# --------------------------------------------------------------------------- #
def caesar_encrypt(plaintext: str, shift: int) -> str:
    """Encrypt `plaintext` using the Caesar cipher with the given `shift`.

    Parameters
    ----------
    plaintext : str
        The message to encrypt.
    shift : int
        Number of positions to shift each letter forward. Can be any integer.

    Returns
    -------
    str
        The ciphertext.
    """
    return "".join(_shift_char(char, shift) for char in plaintext)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt `ciphertext` that was encrypted with the Caesar cipher.

    Decryption is encryption with the negated shift.
    """
    return "".join(_shift_char(char, -shift) for char in ciphertext)


# --------------------------------------------------------------------------- #
# Vigenere cipher
# --------------------------------------------------------------------------- #
def _keyword_to_shifts(keyword: str) -> list[int]:
    """Convert a Vigenere `keyword` into a list of per-letter shifts.

    The shift for a keyword letter is its 0-based index in the alphabet
    (A/a -> 0, B/b -> 1, ..., Z/z -> 25). Non-letter characters in the
    keyword are ignored.
    """
    shifts: list[int] = []
    for char in keyword:
        if char in LOWERCASE:
            shifts.append(ord(char) - ord("a"))
        elif char in UPPERCASE:
            shifts.append(ord(char) - ord("A"))
    return shifts


def vigenere_encrypt(plaintext: str, keyword: str) -> str:
    """Encrypt `plaintext` using the Vigenere cipher with `keyword`.

    Non-alphabetic characters in the plaintext are copied as-is and do NOT
    consume a keyword letter, which keeps the round-trip reversible.
    """
    shifts = _keyword_to_shifts(keyword)
    if not shifts:
        raise ValueError("Vigenere keyword must contain at least one letter.")

    result: list[str] = []
    key_index = 0
    for char in plaintext:
        if char in LOWERCASE or char in UPPERCASE:
            result.append(_shift_char(char, shifts[key_index % len(shifts)]))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)


def vigenere_decrypt(ciphertext: str, keyword: str) -> str:
    """Decrypt `ciphertext` that was encrypted with the Vigenere cipher."""
    shifts = _keyword_to_shifts(keyword)
    if not shifts:
        raise ValueError("Vigenere keyword must contain at least one letter.")

    result: list[str] = []
    key_index = 0
    for char in ciphertext:
        if char in LOWERCASE or char in UPPERCASE:
            result.append(_shift_char(char, -shifts[key_index % len(shifts)]))
            key_index += 1
        else:
            result.append(char)
    return "".join(result)