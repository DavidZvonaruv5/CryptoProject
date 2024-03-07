from salsa20 import XSalsa20_xor
import base64
from os import urandom
from ecc.curve import Curve25519
from ecc.key import gen_keypair
from ecc.cipher import ElGamal


Alice_private, Alice_public = gen_keypair(Curve25519)
Bob_private, Bob_public = gen_keypair(Curve25519)

Shared_secret1 = Bob_public * Alice_private
Shared_secret2 = Alice_public * Bob_private
# -------------------------------Alice
cipher_elg = ElGamal(Curve25519)
plaintext = b"chkjsncsekjncsekjncsjkenfes"
print(plaintext)
secret_pre = urandom(30)
secret_suf = urandom(26)
secret_total = secret_pre + secret_suf[:2]
nonce = secret_suf[2:]  # like a time stamp
ciphertext = XSalsa20_xor(plaintext, nonce, secret_total)  # secret must be 32 bytes

ciphertext_base64 = base64.b64encode(ciphertext).decode("utf-8")
print(ciphertext_base64)

C1_pre, C2_pre = cipher_elg.encrypt(secret_pre, Bob_public)
C1_suf, C2_suf = cipher_elg.encrypt(secret_suf, Bob_public)

# -------------------------------Alice

# -------------------------------Bob
decrypted_secret_pre = cipher_elg.decrypt(Bob_private, C1_pre, C2_pre)
decrypted_secret_suf = cipher_elg.decrypt(Bob_private, C1_suf, C2_suf)
decrypted_secret_total = decrypted_secret_pre + decrypted_secret_suf[:2]
decrypted_message = XSalsa20_xor(
    ciphertext, decrypted_secret_suf[2:], decrypted_secret_total
)
print(decrypted_message)

# -------------------------------Bob
