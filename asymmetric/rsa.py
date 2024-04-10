from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

print("\nCreating a new key pair...")
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

pubkey = private_key.public_key()

print("p = " + str(private_key.private_numbers().p))
print("q = " + str(private_key.private_numbers().q))
print("n = " + str(private_key.private_numbers().public_numbers.n))
print("d = " + str(private_key.private_numbers().d))
print("dmp1 = " + str(private_key.private_numbers().dmp1))
print("dmq1 = " + str(private_key.private_numbers().dmq1))
print("iqmp = " + str(private_key.private_numbers().iqmp))
print("e = " + str(private_key.private_numbers().public_numbers.e))

pem_privkey = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(b"password"))

with open("privkey.pem", "wb") as f:
    f.write(pem_privkey)

# print(pem_privkey)
# for pemprivkey in pem_privkey.splitlines():
#     print(pemprivkey)

pem_pubkey = pubkey.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
# print(pem_privkey)
# for pempubkey in pem_pubkey.splitlines():
#     print(pempubkey)

with open("pubkey.pem", "wb") as f:
    f.write(pem_pubkey)

message = b"This is the message to be encrypted"

ciphertext = pubkey.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(
            algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

print(ciphertext)

plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(
            algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))

print(plaintext)