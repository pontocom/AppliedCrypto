import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

data = b"this is the message that i want to encrypt"

# this data is shared between the two parts in communication
aad = b"this are the authenticate data shared between parts"
key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)
# on the sender side
ct = aesgcm.encrypt(nonce, data, aad)
print(ct)
print(ct.hex())
# on the recipient
dt = aesgcm.decrypt(nonce, ct, aad)
print(dt)