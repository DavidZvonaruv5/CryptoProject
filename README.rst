
::

  def Salsa20_keystream(length, nonce, key)
  def Salsa20_xor(message, nonce, key)

  def XSalsa20_keystream(length, nonce, key)
  def XSalsa20_xor(message, nonce, key)

Use ``[X]Salsa20_keystream`` to generate a keystream of the desired length, or pass ``[X]Salsa20_xor`` a plaintext or a ciphertext to have it XOR'd with the keystream.

Being a stream cipher, ``[X]Salsa20_xor`` does both encryption and decryption.

All values must be binary strings (``str`` on Python 2, ``bytes`` on Python 3)

Example
-------

>>> from salsa20 import XSalsa20_xor
>>> from os import urandom
>>> IV = urandom(24)
>>> KEY = b'*secret**secret**secret**secret*'
>>> ciphertext = XSalsa20_xor(b"IT'S A YELLOW SUBMARINE", IV, KEY)
>>> print(XSalsa20_xor(ciphertext, IV, KEY).decode())
IT'S A YELLOW SUBMARINE

Usage of EC El-Gamal algorithm

# Plaintext
plaintext = b"I am plaintext."
# Generate key pair
pri_key, pub_key = gen_keypair(Curve25519)
print(type(pub_key), pub_key.x)
# Encrypt using ElGamal algorithm
cipher_elg = ElGamal(Curve25519)
C1, C2 = cipher_elg.encrypt(plaintext, pub_key)
# Decrypt
new_plaintext = cipher_elg.decrypt(pri_key, C1, C2)

print(new_plaintext == plaintext)

Usage of schnorr algorithm:


Alice_private, Alice_public = gen_keypair(secp256k1)
cipher_elg = ElGamal(secp256k1)
plaintext = b"message"
secret_pre = urandom(30)
secret_suf = urandom(26)
secret_total = secret_pre + secret_suf[:2]
nonce = secret_suf[2:]  # like a time stamp
ciphertext = XSalsa20_xor(plaintext, nonce, secret_total)

sig = schnorr.schnorr.schnorr_sign(ciphertext, Alice_private)
# print(sig)
# print("---------------------------------")


Alice_point = (Alice_public.x, Alice_public.y)
veri = schnorr.schnorr.schnorr_verify(ciphertext, Alice_point, sig)
print(veri)

