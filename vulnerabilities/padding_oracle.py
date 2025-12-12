#!/usr/bin/env python3
"""
Educational padding‑oracle attack demo.

- Encrypts a secret message with AES‑CBC + PKCS7.
- Exposes an oracle(ciphertext) -> True/False (padding valid?).
- Recovers the plaintext using only the oracle and the IV + ciphertext.

Run: python3 padding_oracle_demo.py
"""

import os
from typing import Callable, List

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


# =========================
# Crypto helper functions
# =========================

BLOCK_SIZE = 16  # AES block size in bytes


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    padder = padding.PKCS7(block_size * 8).padder()
    return padder.update(data) + padder.finalize()


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    unpadder = padding.PKCS7(block_size * 8).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()



def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# =========================
# Oracle implementation
# =========================

class PaddingOracle:
    """
    Simulates a vulnerable service:
    - Keeps the AES key secret.
    - Given IV || ciphertext, returns:
        True  if padding is valid
        False otherwise
    """

    def __init__(self, key: bytes):
        self.key = key

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = os.urandom(BLOCK_SIZE)
        padded = pkcs7_pad(plaintext)
        ct = aes_cbc_encrypt(self.key, iv, padded)
        return iv + ct

    def check_padding(self, data: bytes) -> bool:
        """
        Oracle: returns True if PKCS7 padding is valid, False otherwise.
        Assumes data = IV || ciphertext.
        """
        if len(data) < 2 * BLOCK_SIZE or len(data) % BLOCK_SIZE != 0:
            return False

        iv = data[:BLOCK_SIZE]
        ct = data[BLOCK_SIZE:]

        try:
            plaintext = aes_cbc_decrypt(self.key, iv, ct)
            pkcs7_unpad(plaintext)
            return True
        except Exception:
            # Any padding error (or other error) is mapped to False.
            return False


# =========================
# Attack implementation
# =========================

def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> List[bytes]:
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


def padding_oracle_decrypt(oracle: Callable[[bytes], bool], data: bytes) -> bytes:
    """
    Perform a padding‑oracle attack against an oracle(data) -> bool, where
    data = IV || ciphertext. Returns recovered plaintext (with padding removed).

    This follows the classic CBC padding‑oracle technique.[web:5]
    """
    if len(data) < 2 * BLOCK_SIZE or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be >= 2 blocks and multiple of block size")

    blocks = split_blocks(data)
    iv = blocks[0]
    ciphertext_blocks = blocks[1:]

    recovered_plaintext = b""

    # Process each ciphertext block independently
    for block_index, C_i in enumerate(ciphertext_blocks, start=1):
        # Previous block (C_{i-1}), starting with IV for the first
        C_prev = bytearray(blocks[block_index - 1])
        intermediate = bytearray(BLOCK_SIZE)  # D_K(C_i)
        recovered_block = bytearray(BLOCK_SIZE)

        # Recover bytes from last to first in the block
        for pad_len in range(1, BLOCK_SIZE + 1):
            pad_byte = pad_len
            byte_pos = BLOCK_SIZE - pad_len

            # Prepare a working copy of previous block for manipulation
            C_prev_modified = bytearray(C_prev)

            # Set already‑recovered bytes to enforce correct padding
            for j in range(BLOCK_SIZE - 1, byte_pos, -1):
                C_prev_modified[j] = intermediate[j] ^ pad_byte

            # Brute‑force the current byte
            found = False
            for guess in range(256):
                C_prev_modified[byte_pos] = guess
                forged = bytes(C_prev_modified) + C_i

                if oracle(forged):
                    # Valid padding -> derive intermediate and plaintext bytes
                    intermediate_byte = guess ^ pad_byte
                    intermediate[byte_pos] = intermediate_byte
                    recovered_block[byte_pos] = intermediate_byte ^ C_prev[byte_pos]
                    found = True
                    break

            if not found:
                # For robustness in a demo; in real attack, more heuristics may be needed
                raise RuntimeError(f"Failed to recover byte at position {byte_pos}")

        recovered_plaintext += bytes(recovered_block)

    # Remove PKCS7 padding from the combined plaintext
    return pkcs7_unpad(recovered_plaintext)


# =========================
# Demo
# =========================

def main():
    # Secret key known only to the oracle
    key = os.urandom(32)
    oracle = PaddingOracle(key)

    secret_message = b"Attack at dawn! This is a test of the padding oracle attack demo."
    print("[+] Original plaintext:", secret_message)

    data = oracle.encrypt(secret_message)
    print("[+] Ciphertext (hex):", data.hex())

    # Attacker only has 'data' and oracle.check_padding
    recovered = padding_oracle_decrypt(oracle.check_padding, data)
    print("[+] Recovered plaintext:", recovered)
    print("[+] Success:", recovered == secret_message)


if __name__ == "__main__":
    main()