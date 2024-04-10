from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

parameters = dh.generate_parameters(generator=2, key_size=1024)

private_key = parameters.generate_private_key()

peer_public_key = parameters.generate_private_key().public_key()

shared_key = private_key.exchange(peer_public_key)

derived_key = HKDF(
    algorithm=hashes.SHA3_256(),
    length=32,
    salt=None,
    info=None
).derive(shared_key)

print(derived_key.hex())

private_key_2 = parameters.generate_private_key()
peer_public_key_2 = parameters.generate_private_key().public_key()
shared_key_2 = private_key_2.exchange(peer_public_key_2)

derived_key_2 = HKDF(
    algorithm=hashes.SHA3_256(),
    length=32,
    salt=None,
    info=None
).derive(shared_key_2)

print(derived_key_2.hex())

private_key_3 = parameters.generate_private_key()
peer_public_key_3 = parameters.generate_private_key().public_key()
shared_key_3 = private_key_3.exchange(peer_public_key_3)

derived_key_3 = HKDF(
    algorithm=hashes.SHA3_256(),
    length=32,
    salt=None,
    info=None
).derive(shared_key_3)

print(derived_key_3.hex())