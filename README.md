# CryptoProject
# Secure SMS System

This project is the collaborative effort of Gal, Shir, Eldad, and David. We have developed a secure SMS system that leverages the strength of the Salsa20 stream cipher for message encryption/decryption. Our system also incorporates secure key exchange using the Elliptic Curve ElGamal (EC ElGamal) algorithm with the secp256k1 curve, and ensures message authenticity and integrity through Schnorr signatures.

## Features

- **Encryption & Decryption**: Utilizes the Salsa20 and XSalsa20 stream ciphers for fast, secure message encryption and decryption.
- **Secure Key Exchange**: Implements EC ElGamal algorithm with secp256k1 curve for robust, cryptographically secure key exchange.
- **Digital Signatures**: Employs Schnorr signatures for verification of message authenticity and integrity.

## Usage

### Salsa20 & XSalsa20

These functions are at the core of our message encryption/decryption process:

- `Salsa20_keystream(length, nonce, key)`: Generates a keystream of the specified length.
- `Salsa20_xor(message, nonce, key)`: Encrypts or decrypts a message by XOR'ing it with the keystream.
- `XSalsa20_keystream(length, nonce, key)`: Generates a keystream of the specified length using XSalsa20.
- `XSalsa20_xor(message, nonce, key)`: Encrypts or decrypts a message using XSalsa20.

Both encryption and decryption are performed by the same function, `XSalsa20_xor`, due to the XOR operation's reversible nature.

**Example:**

```python
from salsa20 import XSalsa20_xor
from os import urandom
IV = urandom(24)
KEY = b'*secret**secret**secret**secret*'
ciphertext = XSalsa20_xor(b"IT'S A YELLOW SUBMARINE", IV, KEY)
print(XSalsa20_xor(ciphertext, IV, KEY).decode())

EC El-Gamal Algorithm
For secure key exchange, we use the EC El-Gamal algorithm:

from ecc.curve import Curve25519
from ecc.key import gen_keypair
from ecc.cipher import ElGamal

# Plaintext
plaintext = b"I am plaintext."
# Generate key pair
pri_key, pub_key = gen_keypair(Curve25519)
# Encrypt using ElGamal algorithm
cipher_elg = ElGamal(Curve25519)
C1, C2 = cipher_elg.encrypt(plaintext, pub_key)
# Decrypt
new_plaintext = cipher_elg.decrypt(pri_key, C1, C2)

print(new_plaintext == plaintext)

Schnorr Algorithm
For message authenticity and integrity, the Schnorr signature algorithm is used:

import schnorr
from ecc.curve import secp256k1
from ecc.key import gen_keypair
from ecc.cipher import ElGamal
from os import urandom
from salsa20 import XSalsa20_xor

Alice_private, Alice_public = gen_keypair(secp256k1)
plaintext = b"message"
secret_pre = urandom(30)
secret_suf = urandom(26)
secret_total = secret_pre + secret_suf[:2]
nonce = secret_suf[2:]  # like a time stamp
ciphertext = XSalsa20_xor(plaintext, nonce, secret_total)

sig = schnorr_sign(ciphertext, Alice_private)
Alice_point = (Alice_public.x, Alice_public.y)
veri = schnorr_verify(ciphertext, Alice_point, sig)
print(veri)
```
Our system provides a comprehensive solution for secure messaging, combining the efficiency and security of the Salsa20 cipher, the robustness of EC ElGamal key exchange, and the reliability of Schnorr signatures to deliver a top-notch secure SMS service.


**Requirements**

Python 3.x

**Installation**

Clone the repository:

https://github.com/DavidZvonaruv5/CryptoProject.git

Install dependencies:
pip install .

**Contributors**

Gal
Shir
Eldad
David