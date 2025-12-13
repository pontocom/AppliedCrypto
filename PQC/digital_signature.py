from pqcrypto.sign.sphincs_shake_256s_simple import generate_keypair, sign, verify

# A Alice vai gerar um par de chaves (publica e privada)
public_key, private_key = generate_keypair()

# A Alice vai assinar uma mensagem com a sua chave privada
message = b"This is the message to be signed!!!"
signature = sign(private_key, message)

print("Signature = " + str(signature.hex()))

# O Bob vai usar a chave pública da Alice para validar a sua assinatura
if verify(public_key, message, signature):
    print("Assinatura digital válida!")
else:
    print("Assinatura inválida")