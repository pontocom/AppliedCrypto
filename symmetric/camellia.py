import os
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

key = os.urandom(16)
print("KEY = " + str(base64.b64encode(key)))

cleartext = b"This is my super duper secret message!"

padder = padding.ANSIX923(algorithms.Camellia.block_size).padder()
paddeddata = padder.update(cleartext)
paddeddata += padder.finalize()
print("Data (padded):" + str(paddeddata))
cleartext = paddeddata

cipher = Cipher(algorithms.Camellia(key), modes.ECB())
encryptor = cipher.encryptor()

ciphertext = encryptor.update(cleartext) + encryptor.finalize()
print("Ciphertext = " + str(base64.b64encode(ciphertext)))

decryptor = cipher.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()

unpadder = padding.ANSIX923(algorithms.Camellia.block_size).unpadder()
data = unpadder.update(plaintext)
plaintext_data = data + unpadder.finalize()

print("Plaintext = " + str(plaintext.decode('utf-8')))
