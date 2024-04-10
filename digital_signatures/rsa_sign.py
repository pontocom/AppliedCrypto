from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

print("\nCreating a new key pair...")
private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)

pubkey = private_key.public_key()

message = b'This is the message that I wish to sign'

signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

print(signature.hex())

try:
    pubkey.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Valid Signature")
except InvalidSignature:
    print("Invalid Signature")