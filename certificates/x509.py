import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=4096
)

with open("./key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(b"password")
    ))

subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lisboa"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Lisboa"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Iscte-Sintra"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Carlos Serrao")
])

issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lisboa"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Lisboa"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Iscte-Sintra"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Escola de Tecnologias Digitais"),
    x509.NameAttribute(NameOID.COMMON_NAME, "ISCTE CA")
])


cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    issuer
).public_key(
    key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.datetime.now(datetime.timezone.utc)
).not_valid_after(
    datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"serrao.me")]),
    critical=False
).sign(key, hashes.SHA256())

with open("./certificate.pem", "wb") as f:
    f.write(cert.public_bytes(
        serialization.Encoding.PEM
    ))