from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID


if __name__ == '__main__':
    #create the keypair for the client

    print("Create a new keypair...")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    print("Create a new distinguished name for the CA...")

    country_name = input("Country Name:")
    state_or_province_name = input("State or Province Name:")
    locality_name = input("Locality Name:")
    organization_name = input("Organization Name:")
    common_name = input("Common Name:")

    # write key to file
    with open("./" + common_name + ".key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # create the CSR
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).sign(key, hashes.SHA256(), default_backend())

    with open("./" + common_name + ".csr", "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print("Done!")