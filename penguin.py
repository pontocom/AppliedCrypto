import os
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

headerbytes = bytes(open("tux_original.bmp", "rb").read(54))

with(open("tux_original.bmp", "rb")) as f:
    all = f.read()
    tbr = len(all) - 54
    f.seek(55)
    bodybytes = f.read(tbr)

key = os.urandom(32)
iv = os.urandom(16)
print("KEY = " + str(base64.b64encode(key)))

cleartext = bodybytes

if len(cleartext) % 16 != 0:
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    paddeddata = padder.update(cleartext)
    paddeddata += padder.finalize()
    cleartext = paddeddata

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(cleartext) + encryptor.finalize()

with(open("tux_CBC.bmp", "wb+")) as f:
    f.write(headerbytes)
    f.write(ciphertext)

f.close()

