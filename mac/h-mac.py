import os
from cryptography.hazmat.primitives import hashes, hmac

message = "This my message to compute the MAC"

key = os.urandom(32)

h = hmac.HMAC(key, hashes.SHA512())
h.update(message.encode('ascii'))
mac = h.finalize()

print(mac.hex())