'''
This sample demonstrates how simple DH works
'''
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

parameters = dh.generate_parameters(generator=5, key_size=1024)

print("p = " + str(parameters.parameter_numbers().p))
print("g = " + str(parameters.parameter_numbers().g))

alice_private_key = parameters.generate_private_key()

print("a = " + str(alice_private_key.private_numbers().x))
print("A = " + str(alice_private_key.public_key().public_numbers().y))

bob_private_key = parameters.generate_private_key()

print("b = " + str(bob_private_key.private_numbers().x))
print("B = " + str(bob_private_key.public_key().public_numbers().y))

alice_shared_key = alice_private_key.exchange(bob_private_key.public_key())

print(alice_shared_key.hex())

bob_shared_key = bob_private_key.exchange(alice_private_key.public_key())

print(bob_shared_key.hex())

alice_derived_key = HKDF(
    algorithm=hashes.SHA3_256(),
    length=32,
    salt=None,
    info=None
).derive(alice_shared_key)

print(alice_derived_key.hex())

bob_derived_key = HKDF(
    algorithm=hashes.SHA3_256(),
    length=32,
    salt=None,
    info=None
).derive(bob_shared_key)

print(bob_derived_key.hex())

