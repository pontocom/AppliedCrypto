import os
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

message = "This my message to compute the MAC"
# Linha em FALTA
key = os.urandom(32)

c = cmac.CMAC(algorithms.AES(key))
c.update(message.encode('ascii'))
mac = c.finalize()

print(mac.hex())