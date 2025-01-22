import os

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

data = b"this is the message that i want to encrypt"

# this data is shared between the two parts in communication
aad = b"this are the authenticate data shared between parts"

key = AESCCM.generate_key(bit_length=256)

aesccm = AESCCM(key)

nonce = os.urandom(13)

# on the sender side
ct = aesccm.encrypt(nonce, data, aad)

print(ct)
print(ct.hex())

# on the recipient
dt = aesccm.decrypt(nonce, ct, aad)

print(dt)

