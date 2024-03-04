from cryptography.fernet import Fernet

key = Fernet.generate_key()
print(key)

f = Fernet(key)
encrypted = f.encrypt(b'This is my super secret message!!!')

print("Encrypted: " + str(encrypted))

decrypted = f.decrypt(encrypted)
print("Decrypted: " + str(decrypted))