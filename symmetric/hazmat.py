import os
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(32)
print("KEY = " + str(base64.b64encode(key)))

cleartext = b"This is my super duper secret message!"

if len(cleartext) % 16 != 0:
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    paddeddata = padder.update(cleartext)
    paddeddata += padder.finalize()
    print("Data (padded):" + str(paddeddata))
    cleartext = paddeddata

cipher = Cipher(algorithms.AES(key), modes.ECB())
encryptor = cipher.encryptor()
ciphertext = encryptor.update(cleartext) + encryptor.finalize()
print("Ciphertext = " + str(base64.b64encode(ciphertext)))

decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

#unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
#data = unpadder.update(plaintext)
#plaintext_data = data + unpadder.finalize()

print("Plaintext = " + str(plaintext.decode('utf-8')))
