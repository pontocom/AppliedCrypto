def vernam_encrypt(plaintext, keyword):
    # Check if plaintext and keyword are of the same length
    if len(plaintext) != len(keyword):
        raise ValueError("For Vernam Cipher, the plaintext and keyword must be of the same length.")

    ciphertext = ""
    for p, k in zip(plaintext, keyword):
        p_idx = ord(p) - ord('A')
        k_idx = ord(k) - ord('A')
        c_idx = p_idx ^ k_idx
        ciphertext += chr(c_idx + ord('A'))

    return ciphertext


def vernam_decrypt(ciphertext, keyword):
    # Check if ciphertext and keyword are of the same length
    if len(ciphertext) != len(keyword):
        raise ValueError("For Vernam Cipher, the ciphertext and keyword must be of the same length.")

    plaintext = ""
    for c, k in zip(ciphertext, keyword):
        c_idx = ord(c) - ord('A')
        k_idx = ord(k) - ord('A')
        p_idx = c_idx ^ k_idx
        plaintext += chr(p_idx + ord('A'))

    return plaintext


if __name__ == "__main__":
    # Example usage:
    message = "CARLOS"
    key =     "XPTO12"  # key must match length

    cipher = vernam_encrypt(message, key)
    print("Cipher (raw chars):", cipher)

    plain = vernam_decrypt(cipher, key)
    print("Decrypted:", plain)