import datetime
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
import sqlite3
from sqlite3 import Error
import prettytable

def print_main_menu():
    """
    This function is used to display the main menu of the CA
    :return: None
    """
    print("-------------------------------")
    print("[1] Certificate Signing Requests (CSR)")
    print("[2] Certificate Revocation (CRL)")
    print("[3] List Issued Certificates")
    print("[0] Exit")
    print("-------------------------------")


def is_ca_already_setup():
    """
    Checks if the CA is already setup. If it is the function returns True. Otherwise, it will create the required
    directories and files and returns False.
    :return: Boolean value that represents if the CA ie already setup (True) or not (False).
    """
    ca_exists = os.path.isfile("./ca.crt")
    if ca_exists:
        return True
    else:
        if not os.path.exists("./requests"):
            os.mkdir("./requests")
        if not os.path.exists("./certs"):
            os.mkdir("./certs")
        return False


def setup_new_ca():
    """
    Creates and setup a new CA, creating the keypair and the self signed digital certificate.
    :return: None
    """
    # create a new keypair
    print("Create a new keypair...")

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )

    with open("./ca.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    print("Create a new distinguished name for the CA...")

    country_name = input("Country Name:")
    state_or_province_name = input("State or Province Name:")
    locality_name = input("Locality Name:")
    organization_name = input("Organization Name:")
    common_name = input("Common Name:")

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country_name),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state_or_province_name),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])

    cert = (x509.CertificateBuilder().subject_name(
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
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=5*365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=True,
            content_commitment=False,
            key_agreement=False,
            key_encipherment=False,
            crl_sign=True,
            data_encipherment=False,
            decipher_only=False,
            digital_signature=True,
            encipher_only=False
        ),
        critical=True
    ).sign(key, hashes.SHA256()))

    with open("./ca.crt", "wb") as f:
        f.write(cert.public_bytes(
            serialization.Encoding.PEM
        ))


def read_ca_key():
    """
    Reads the private key of the CA from a file
    :return: The CA private key
    """
    print("Reading CA key")
    with open("./ca.key", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def read_ca_cert():
    """
    Reads the CA certificate from the file
    :return: The CA certificate
    """
    print("Reading CA certificate")
    with open("./ca.crt", "rb") as f:
        certificate = x509.load_pem_x509_certificate(
            f.read(),
            backend=default_backend()
        )
    return certificate


def create_connection():
    """
    Creates a new connection to the CA database
    :return: The connection to the database
    """
    conn = None
    try:
        conn = sqlite3.connect('certs.db')
        return conn
    except Error as e:
        print(e)


def create_table(conn):
    """
    Creates the database tables that are required by the CA
    :param conn: The connection to the database
    :return: None
    """
    sql_create_certs_table = """ CREATE TABLE IF NOT EXISTS certs (
                                            serial integer PRIMARY KEY,
                                            dns text NOT NULL,
                                            status_date text NOT NULL,
                                            status text NOT NULL,
                                            cert text NOT NULL
                                        ); """
    try:
        c = conn.cursor()
        c.execute(sql_create_certs_table)
    except Error as e:
        print(e)


def certificate_issuance(c, ca_key, ca_issuer):
    """
    Manages the issuance of the certificates that are requested to the CA
    :param c: The database connection
    :param ca_key: The private key of the CA
    :param ca_cert: The certificate of the CA
    :return: None
    """

    while True:
        list_of_csr = list_requests()
        print("[1] Issue certificate")
        print("[0] Exit")

        choice = input("--> ")
        if choice == "0":
            return True
        elif choice == "1":
            cert_csr_option = input("Enter the CSR number [0 - to cancel]: ")
            if cert_csr_option == "0":
                continue
            else:
                # check if CSR is valid
                if list_of_csr[cert_csr_option].is_signature_valid:
                    print("CSR signature is valid!")
                    print("Subject -> " + str(list_of_csr[cert_csr_option].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value))
                    common_name = str(list_of_csr[cert_csr_option].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
                    new_cert_dn = str(list_of_csr[cert_csr_option].subject)
                    issue_choice = input("Issue the Certificate [Y][N] --> ")
                    if issue_choice == "Y" or issue_choice == "y":
                        sn = get_last_serial_number(c)
                        cert = issue_certificate(sn, list_of_csr[cert_csr_option], ca_key, ca_issuer)
                        save_certificate_db(c, sn, new_cert_dn, cert)
                        delete_csr_file(common_name)
                    else:
                        continue
                else:
                    print("CSR signature is invalid!")
            continue
        else:
            continue

    return True


def save_certificate_db(c, sn, new_cert_dn, cert):
    sql = ''' INSERT INTO certs(serial, dns, status_date, status, cert) VALUES(?,?,?,?,?) '''
    cur = c.cursor()
    date_issued = str(datetime.datetime.now(datetime.timezone.utc))
    status = "ISSUED"
    certificate = (sn, new_cert_dn, date_issued, status, cert.public_bytes(serialization.Encoding.PEM))
    cur.execute(sql, certificate)
    c.commit()
    return True


def list_requests():
    table = prettytable.PrettyTable(["Number", "CSR", "Subject"])
    number = 1
    table.align = "l"
    list_of_csr = {}
    for csr_file in os.listdir("./requests"):
        if csr_file.endswith(".csr"):
            with open(f"./requests/{csr_file}", "rb") as f:
                csr = x509.load_pem_x509_csr(f.read(), default_backend())
        table.add_row([number, csr_file, csr.subject])
        list_of_csr[str(number)] = csr
        number += 1

    print(table)
    return list_of_csr


def issue_certificate(sn, csr, key, ca_issuer):
    cert = (x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        ca_issuer
    ).public_key(
        csr.public_key()
    ).serial_number(
        sn
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=False,
            content_commitment=False,
            key_agreement=False,
            key_encipherment=True,
            crl_sign=False,
            data_encipherment=True,
            decipher_only=False,
            digital_signature=True,
            encipher_only=False
        ),
        critical=True
    ).sign(key, hashes.SHA256()))

    print("Writing...." + str(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value))

    with open("./certs/" + str(csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value) + ".crt", "wb") as f:
        f.write(cert.public_bytes(
            serialization.Encoding.PEM
        ))

    f.close()
    return cert


def certificate_revocation(c, ca_key, ca_cert):
    while True:
        list_certificates_db(c)
        option = input("Certificate to revoke [0 - Back]: ")
        if option == "0":
            break
        else:
            if revoke_on_db(c, option):
                create_or_update_crl(c, ca_key, ca_cert, option)
                continue
            else:
                continue
    return True


def revoke_on_db(c, cert_number):
    option = input("Do you really want to revoke certificate " + str(cert_number) + "? [Y/N]")
    if option.lower() == "y":
        cur = c.cursor()
        cur.execute('UPDATE certs SET status = "REVOKED", status_date=? WHERE serial=?', (str(datetime.datetime.now(datetime.timezone.utc)), cert_number,))
        c.commit()
        return True
    else:
        return False


def create_or_update_crl(c, ca_key, ca_cert, cert_serial_number):
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert)
    builder = builder.last_update(datetime.datetime.today())
    builder = builder.next_update(datetime.datetime.today() + datetime.timedelta(days=7))

    if os.path.isfile("./certs.crl"):
        """
        If the CRL already exists we want to preserve the information and add the new certificate to it
        """
        with open("./certs.crl", "rb") as f:
            crl = x509.load_pem_x509_crl(f.read())

        for i in range(0, len(crl)):
            builder = builder.add_revoked_certificate(crl[i])

    revoked_cert = (x509.RevokedCertificateBuilder()
                    .serial_number(int(cert_serial_number))
                    .revocation_date(datetime.datetime.today())
                    ).build()
    builder = builder.add_revoked_certificate(revoked_cert)

    crl = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256()
    )

    with open("./certs.crl", "wb") as f:
        f.write(crl.public_bytes(
            encoding=serialization.Encoding.PEM
        ))

    return True


def get_last_serial_number(c):
    cur = c.cursor()
    cur.execute('SELECT max(serial) as ns FROM certs')
    row = cur.fetchone()
    if row[0] is None:
        return 1
    else:
        return row[0] + 1


def list_certificates_db(c):
    table = prettytable.PrettyTable(["SN", "DN", "Data", "Status"])
    table.align = "l"
    cur = c.cursor()
    cur.execute('SELECT * FROM certs')
    rows = cur.fetchall()
    for row in rows:
        table.add_row([row[0],row[1],row[2],row[3]])

    print(table)


def delete_csr_file(filename):
    if os.path.exists("./requests/" + filename + ".csr"):
        os.remove("./requests/" + filename + ".csr")
        return True


if __name__ == '__main__':
    # validar se a CA já foi inicializada anteriormente
    if not is_ca_already_setup():
        # criar uma nova CA
        setup_new_ca()
        c = create_connection()
        create_table(c)
    else:
        # ler a chave da CA
        ca_key = read_ca_key()
        # ler o certificado da CA
        ca_cert = read_ca_cert()
        c = create_connection()

    while True:
        print_main_menu()
        choice = input("--> ")
        if choice == "0":
            break
        elif choice == "1":
            certificate_issuance(c, ca_key, ca_cert.subject)
        elif choice == "2":
            certificate_revocation(c, ca_key, ca_cert.subject)
        elif choice == "3":
            list_certificates_db(c)
        else:
            continue