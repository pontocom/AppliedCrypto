from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

message = b'This is the message that I wish to sign'

private_key = Ed25519PrivateKey.generate()
signature = private_key.sign(message)

print(signature)

public_key = private_key.public_key()

try:
    public_key.verify(signature, message)
    print("Signature verified")
except InvalidSignature:
    print("Invalid Signature")
