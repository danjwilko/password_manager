import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


"""This module provides cryptographic utilities for the password manager application, including key derivation, encryption, and decryption functions. It uses Argon2id for key derivation and Fernet symmetric encryption for secure handling of credentials
    """


def gen_salt():
    """
    Generate a cryptographically secure random salt.

    Returns:
        bytes: 16 random bytes suitable for cryptographic use
    """
    return os.urandom(16)


def gen_dek():
    """
    Generate a random Data Encryption Key (DEK).

    Returns:
        bytes: 32 random bytes suitable for cryptographic use
    """
    return os.urandom(32)


# Setup zero knowledge encryption utilities for the password manager application


def derive_kek(password: str, salt: bytes) -> bytes:
    """
    Derive a Key Encryption Key (KEK) from the user's password and salt using Argon2id.

    Args:
        password (str): The user's plaintext password
        salt (bytes): User-specific salt value

    Returns:
        bytes: 32-byte KEK derived from the password and salt
    """
    kdf = Argon2id(
        salt=salt,
        length=32,  # 256-bit key
        iterations=3,  # Number of iterations
        lanes=4,  # Parallelism factor
        memory_cost=64 * 1024,  # 64MB memory usage
    )
    kek = kdf.derive(password.encode())
    return kek


def wrap_dek(dek: bytes, kek: bytes) -> bytes:
    """
    Wrap the Data Encryption Key (DEK) using the Key Encryption Key (KEK) with Fernet symmetric encryption.

    Args:
        dek (bytes): The DEK to be wrapped
        kek (bytes): The KEK used to wrap the DEK

    Returns:
        bytes: The wrapped DEK
    """
    fernet = Fernet(base64.urlsafe_b64encode(kek))
    wrapped_dek = fernet.encrypt(dek)
    return wrapped_dek


def unwrap_dek(wrapped_dek: bytes, kek: bytes) -> bytes:
    """
    Unwrap the Data Encryption Key (DEK) using the Key Encryption Key (KEK) with Fernet symmetric encryption.

    Args:
        wrapped_dek (bytes): The wrapped DEK to be unwrapped
        kek (bytes): The KEK used to unwrap the DEK

    Returns:
        bytes: The original DEK after unwrapping
    """
    fernet = Fernet(base64.urlsafe_b64encode(kek))
    dek = fernet.decrypt(wrapped_dek)
    return dek


def encrypt_password(plaintext: str, dek: bytes) -> str:
    """
    Encrypt the plaintext password using the Data Encryption Key (DEK) with Fernet symmetric encryption.

    Args:
        plaintext (str): The plaintext credentials to be encrypted
        dek (bytes): The DEK used for encryption

    Returns:
        str: The encrypted credentials as a base64-encoded string
    """
    fernet = Fernet(base64.urlsafe_b64encode(dek))
    return fernet.encrypt(plaintext.encode())


def decrypt_password(encrypted: str, dek: bytes) -> str:
    """
    Decrypt the encrypted credentials using the Data Encryption Key (DEK) with Fernet symmetric encryption.

    Args:
        encrypted (str): The encrypted credentials as a base64-encoded string
        dek (bytes): The DEK used for decryption

    Returns:
        str: The original plaintext credentials after decryption
    """
    fernet = Fernet(base64.urlsafe_b64encode(dek))
    decrypted = fernet.decrypt(encrypted.encode())
    return decrypted.decode()
