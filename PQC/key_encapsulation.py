from secrets import compare_digest
from pqcrypto.kem.mceliece8192128 import generate_keypair, encrypt, decrypt

# A Alice vai gerar um par de chaves - uma pública e outra privada
public_key, private_key = generate_keypair()

# A Alice vai ter de enviar a chave pública (public_key) para o Bob
# O Bob vai derivar um segredo (bob_secret), e encripta-o usando a chave 
# pública da Alice, para produzir um ciphertext
ciphertext, bob_secret = encrypt(public_key)

# Bob envia o seu ciphertext para a Alice (ciphertext)
# Alice desencripta o ciphertext para derivar o seu segredo (alice_secret)
# No final do processo ambos os segredos da Alice e Bob são iguais
alice_secret = decrypt(private_key, ciphertext)

# Verifica se ambos os segredos são iguais
if compare_digest(bob_secret, alice_secret):
    print("Segredos são iguais!")
else:
    print("Segredos diferentes!")

print("Alice = " + str(alice_secret))
print("Bob = " + str(bob_secret))
