import socket
import ssl

pemServer = "ca.crt"
keyClient = "DemoServerTest.key"
pemClient = "DemoServerTest.crt"

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)
context.verify_mode = ssl.CERT_NONE
context.load_verify_locations(pemServer)
context.load_cert_chain(certfile=pemClient, keyfile=keyClient)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client = context.wrap_socket(client)
client.connect(('127.0.0.1', 4443))

client.send(bytes("Client --> Hello, from this side...", encoding='utf-8'))

from_server = str(client.recv(4096), encoding='utf-8')

print(from_server)

client.close()

