# ShieldCode

**Basic Encryption & Decryption**

ShieldCode is a lightweight, dependency-free Python toolkit that demonstrates the fundamental mechanics of **data confidentiality** through two classical, reversible ciphers: the **Caesar cipher** and the **Vigenere cipher**. It provides an interactive command-line menu to encrypt user text, decrypt ciphertext, and display both outputs.

---

## Table of Contents

1. [Features](#features)
2. [Project Structure](#project-structure)
3. [Cryptographic Logic Explained](#cryptographic-logic-explained)
4. [How to Run](#how-to-run)
5. [Usage Examples](#usage-examples)
6. [Programmatic API](#programmatic-api)
7. [Self-Test](#self-test)
8. [Security Note](#security-note)

---

## Features

- **Caesar cipher** with a user-chosen integer shift key (supports negative and large shifts).
- **Vigenere cipher** with a user-chosen alphabetic keyword (polyalphabetic, stronger than Caesar).
- **Encrypt** any text and **decrypt** it back to the original.
- **Case preservation** - uppercase and lowercase letters keep their case.
- **Non-letter characters** (spaces, digits, punctuation) pass through unchanged, keeping the round-trip reversible.
- **Input validation** - empty text, non-numeric shifts, and empty keywords are rejected.
- **Built-in self-test** that proves decrypt(encrypt(text, key), key) == text.
- **Zero dependencies** - pure Python standard library.

---

## Project Structure

```
ShieldCode/
|-- main.py                # Entry point: launches the interactive CLI
|-- requirements.txt       # No third-party dependencies (standard library only)
|-- README.md              # This file: explanation + run instructions
+-- shieldcode/
    |-- __init__.py        # Package marker; re-exports cipher functions
    |-- ciphers.py         # Core cryptographic logic (Caesar + Vigenere)
    +-- cli.py             # Interactive menu-driven command-line interface
```

---

## Cryptographic Logic Explained

ShieldCode implements **symmetric** ciphers: the same key used to encrypt is used to decrypt. Both ciphers operate on the 26-letter English alphabet and use **modular arithmetic** to wrap around the alphabet.

### Caesar Cipher

The Caesar cipher is a **monoalphabetic substitution cipher**. Every letter in the plaintext is shifted forward by a fixed integer key (the shift). Decryption shifts each letter backward by the same amount.

**Mathematical formula** (for a letter with 0-based alphabet index x, alphabet size m = 26):

```
encrypt(x) = (x + key) mod m
decrypt(x) = (x - key) mod m
```

**Worked example** (shift = 3):

| Plaintext | H | E | L | L | O |
|-----------|---|---|---|---|---|
| Index x   | 7 | 4 | 11| 11| 14|
| x + 3     | 10| 7 | 14| 14| 17|
| Ciphertext| K | H | O | O | R |

So HELLO becomes KHOOR. Decryption reverses it: KHOOR becomes HELLO.

**Key points:**
- The shift is normalized with mod 26, so a shift of 30 is equivalent to 30 mod 26 = 4, and a shift of -7 works correctly too.
- Non-letter characters (spaces, punctuation, digits) are not shifted - they are copied as-is.
- Letter case is preserved: H becomes K, h becomes k.

### Vigenere Cipher

The Vigenere cipher is a **polyalphabetic substitution cipher**. Instead of a single fixed shift, a repeating **keyword** supplies a different shift for each plaintext letter. The shift applied to the i-th plaintext letter is the alphabet index of the i-th keyword letter (cycling the keyword as needed).

**Mathematical formula** (for plaintext letter index x_i and keyword letter index k_i):

```
encrypt(x_i) = (x_i + k_i) mod m
decrypt(x_i) = (x_i - k_i) mod m
```

**Worked example** (keyword = LEMON, plaintext = ATTACKATDAWN):

```
Plaintext : A T T A C K A T D A W N
Keyword   : L E M O N L E M O N L E   (repeating)
Shifts    : 11 4 12 14 13 11 4 12 14 13 11 4
Cipher    : L X F O C M X F R N H R
```

So ATTACKATDAWN becomes LXFOCMXFRNHR.

**Key points:**
- The keyword is converted to a list of shifts: A=0, B=1, ..., Z=25.
- Non-letter characters in the plaintext are copied as-is and do not advance the keyword pointer. This design choice keeps the mapping strictly reversible.
- Letter case is preserved in both plaintext and keyword (the keyword is case-insensitive for shift computation).

### Why Decryption Works

Both ciphers rely on the symmetry of modular arithmetic:

```
decrypt(encrypt(x, k), k) = (x + k - k) mod m = x mod m = x
```

Because subtraction is the exact inverse of addition under modulo m, applying the reverse operation with the same key always recovers the original letter. Non-letters are never altered, so the full text round-trips perfectly:

```
decrypt(encrypt(text, key), key) == text
```

---

## How to Run

### Prerequisites

- **Python 3.8+** (tested on Python 3.13). No external packages are required.

### Steps

1. Open a terminal and navigate to the project folder:

   ```bash
   cd "c:\Users\poude\Desktop\Decode lab\ShieldCode"
```

2. Run the program:

   ```bash
   python main.py
```

3. Use the on-screen menu:

```
   ========================================
     Menu
       1) Encrypt text
       2) Decrypt text
       3) Run self-test
       4) Quit
   ========================================
     Select an option:
```

   - Choose **1** to encrypt: pick a cipher (Caesar or Vigenere), enter your text, enter the key, and view the ciphertext.
   - Choose **2** to decrypt: pick the same cipher, paste the ciphertext, enter the same key, and view the recovered plaintext.
   - Choose **3** to run the built-in self-test.
   - Choose **4** to quit.

---

## Usage Examples

### Example 1 - Caesar Encryption

```
Select an option: 1

--- Encrypt ---
  Cipher [1] Caesar  [2] Vigenere: 1
  Enter text to encrypt: Hello, World!
  Enter shift key (integer, e.g. 3): 3

  Plaintext : Hello, World!
  Ciphertext: Khoor, Zruog!
  (Cipher: caesar, Key: 3)
```

### Example 2 - Caesar Decryption

```
Select an option: 2

--- Decrypt ---
  Cipher [1] Caesar  [2] Vigenere: 1
  Enter text to decrypt: Khoor, Zruog!
  Enter shift key (integer, e.g. 3): 3

  Ciphertext: Khoor, Zruog!
  Plaintext : Hello, World!
  (Cipher: caesar, Key: 3)
```

### Example 3 - Vigenere Encryption

```
Select an option: 1

--- Encrypt ---
  Cipher [1] Caesar  [2] Vigenere: 2
  Enter text to encrypt: Attack at Dawn!
  Enter keyword (letters only): LEMON

  Plaintext : Attack at Dawn!
  Ciphertext: Lxfopv ef Rnhr!
  (Cipher: vigenere, Key: LEMON)
```

---

## Programmatic API

You can also use the ciphers directly in your own Python code:

```python
from shieldcode import (
    caesar_encrypt, caesar_decrypt,
    vigenere_encrypt, vigenere_decrypt,
)

# Caesar
cipher = caesar_encrypt('Hello, World!', 3)
plain  = caesar_decrypt(cipher, 3)
print(cipher)  # Khoor, Zruog!
print(plain)   # Hello, World!

# Vigenere
cipher = vigenere_encrypt('Attack at Dawn!', 'LEMON')
plain  = vigenere_decrypt(cipher, 'LEMON')
print(cipher)  # Lxfopv ef Rnhr!
print(plain)   # Attack at Dawn!
```

---

## Self-Test

The CLI option 3 runs a built-in round-trip test suite covering:

- Caesar with a positive shift (3).
- Caesar with a negative shift (-7).
- Caesar with a shift larger than 26 (30).
- Vigenere with keyword LEMON.

Each case encrypts the text and then decrypts the result, verifying that the output matches the original.

---

## Security Note

ShieldCode is an **educational tool** designed to teach the fundamental mechanics of encryption and decryption. The Caesar and Vigenere ciphers are **classical ciphers** and are **not secure** by modern standards - they can be broken with frequency analysis or brute force. They should never be used to protect real sensitive data. For production systems, use modern, vetted cryptographic libraries such as **AES** (via cryptography or PyCryptodome) or **libsodium**.
