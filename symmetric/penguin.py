import os
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# change "mode" to other modes (CBC, ECB, OFB, CFB) to check the differences in the image
mode = "CFB"

with(open("tux_original.bmp", "rb")) as f:
    file = f.read()

head = file[:54]
body = file[55:]

key = os.urandom(32)
iv = os.urandom(16)
print("KEY = " + str(base64.b64encode(key)))

cleartext = body

if len(cleartext) % 16 != 0:
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    paddeddata = padder.update(cleartext)
    paddeddata += padder.finalize()
    cleartext = paddeddata

if mode == "ECB":
    cipher = Cipher(algorithms.AES(key), modes.ECB())
if mode == "CBC":
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
if mode == "OFB":
    cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
if mode == "CFB":
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))

encryptor = cipher.encryptor()
ciphertext = encryptor.update(cleartext) + encryptor.finalize()

image = head + ciphertext

with(open("tux_" + mode + ".bmp", "wb+")) as f:
    f.write(image)

f.close()

