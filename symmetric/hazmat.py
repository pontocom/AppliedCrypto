import os
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# key = os.urandom(16)
key = b'QqfTttneYm+L3lVLbIc4vA=='
print(f'KEY = {str(base64.b64encode(key))}')

cleartext = b'Local da descarga: 38.489726198410345, -8.911551280242712; Dia: 31/12/2025; Hora:23:45'

if len(cleartext) % 16 != 0:
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    paddeddata = padder.update(cleartext)
    paddeddata += padder.finalize()
    print("Data (padded):" + str(paddeddata))
    cleartext = paddeddata

cipher = Cipher(algorithms.AES(key), modes.ECB())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(cleartext) + encryptor.finalize()
print(f'Ciphertext = {str(base64.b64encode(ciphertext))}')

decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
data = unpadder.update(plaintext)
plaintext_data = data + unpadder.finalize()

print(f'Plaintext = {str(plaintext.decode("utf-8"))}')
