import schnorr
from ecc.curve import secp256k1
from ecc.key import gen_keypair
from ecc.cipher import ElGamal
from os import urandom
from salsa20 import XSalsa20_xor


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
