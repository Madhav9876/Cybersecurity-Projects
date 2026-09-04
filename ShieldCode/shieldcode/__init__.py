"""ShieldCode - a basic encryption/decryption toolkit.

Exposes the Caesar and Vigenere cipher implementations for programmatic use:

    from shieldcode import caesar_encrypt, caesar_decrypt
    from shieldcode import vigenere_encrypt, vigenere_decrypt
"""

from .ciphers import (
    caesar_decrypt,
    caesar_encrypt,
    vigenere_decrypt,
    vigenere_encrypt,
)

__all__ = [
    "caesar_encrypt",
    "caesar_decrypt",
    "vigenere_encrypt",
    "vigenere_decrypt",
]

__version__ = "1.0.0"