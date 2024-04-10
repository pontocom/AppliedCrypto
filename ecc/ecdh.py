from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

alice_private_key = ec.generate_private_key(
    ec.SECP384R1()
)

print(alice_private_key.private_numbers().private_value)
print(alice_private_key.private_numbers().public_numbers)

bob_private_key = ec.generate_private_key(
    ec.SECP384R1()
)

print(bob_private_key.private_numbers().private_value)
print(bob_private_key.private_numbers().public_numbers)

alice_shared_key = alice_private_key.exchange(
    ec.ECDH(),
    bob_private_key.public_key()
)

print(alice_shared_key.hex())

bob_shared_key = bob_private_key.exchange(
    ec.ECDH(),
    alice_private_key.public_key()
)

print(bob_shared_key.hex())

alice_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=None
).derive(alice_shared_key)

print(alice_derived_key.hex())

bob_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=None
).derive(bob_shared_key)

print(bob_derived_key.hex())