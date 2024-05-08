import socket
import ssl

pemServer = "ca.crt"
keyClient = "DemoServerTest.key"
pemClient = "DemoServerTest.crt"

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.options |= (ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1)
context.verify_mode = ssl.CERT_OPTIONAL
context.load_verify_locations(pemServer)
context.load_cert_chain(certfile=pemClient, keyfile=keyClient)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server = context.wrap_socket(server)
server.bind(('127.0.0.1', 4443))
server.listen(5)

while True:
    print("Waiting for connection")
    conn, addr = server.accept()
    from_client = ''

    while True:
        data = str(conn.recv(4096), encoding='utf-8')
        if not data:
            break
        from_client = from_client + data
        print(from_client)

        conn.send(bytes("Server --> This is the answer", encoding='utf-8'))

    conn.close()