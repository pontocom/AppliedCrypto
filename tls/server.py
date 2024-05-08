import socket
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS)
context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2)
context.verify_mode = ssl.CERT_OPTIONAL
context.load_verify_locations()
context.load_cert_chain()