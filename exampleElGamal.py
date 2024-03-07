from ecc.curve import Curve25519
from ecc.key import gen_keypair
from ecc.cipher import ElGamal


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
