from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def encrypt_file(data: bytes, key: bytes) -> bytes:
    """
    Encrypt file bytes using AES-256-CBC.
    Returns: IV (16 bytes) + encrypted data (concatenated)
    """
    # Generate a fresh random IV for every file — critical for security!
    iv = os.urandom(16)

    # Pad data to AES block size (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Create cipher and encrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    # Prepend IV so we can use it during decryption
    return iv + encrypted


def decrypt_file(encrypted_data: bytes, key: bytes) -> bytes:
    """
    Decrypt file bytes using AES-256-CBC.
    Expects: IV (first 16 bytes) + encrypted content
    """
    # Split IV from encrypted content
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()