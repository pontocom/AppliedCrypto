ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def encrypt(plaintext,key):
    ciphertext = ''
    for i in range(len(plaintext)):
        p = ALPHABET.index(plaintext[i])
        k = ALPHABET.index(key[i%len(key)])
        c = (p + k) % 26
        ciphertext += ALPHABET[c]
    return ciphertext

def decrypt(ciphertext, key):
    plaintext = ''
    for i in range(len(ciphertext)):
        p = ALPHABET.index(ciphertext[i])
        k = ALPHABET.index(key[i % len(key)])
        c = (p - k) % 26
        plaintext += ALPHABET[c]
    return plaintext

if __name__ == '__main__':
    ciphertext = encrypt('LOCALDAREUNIAOSECRETANOISCTE', 'XBFGDERTQWERTYUIOPAQRTUVLPOI')
    print("Ciphertext: " + ciphertext)
    plaintext = decrypt(ciphertext, 'XBFGDERTQWERTYUIOPAQRTUVLPOI')
    print("Plaintext: " + plaintext)