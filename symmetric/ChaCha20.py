import os, struct
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(32)
nonce = os.urandom(8)
counter = 0
full_nonce = struct.pack("<Q", counter) + nonce
print("KEY = " + str(base64.b64encode(key)))
print("NONCE = " + str(base64.b64encode(full_nonce)))

cleartext = b"This is my super duper secret message!"

cipher = Cipher(algorithms.ChaCha20(key, full_nonce), mode=None)
encryptor = cipher.encryptor()

ciphertext = encryptor.update(cleartext) + encryptor.finalize()
print("Ciphertext = " + str(base64.b64encode(ciphertext)))

decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

print("Plaintext = " + str(plaintext.decode('utf-8')))
