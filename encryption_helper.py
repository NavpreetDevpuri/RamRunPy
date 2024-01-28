# encryption_helper.py

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import base64
import os
import bcrypt

password_salt = b"$2b$12$Ph8lZ5HioRm2i9YW.5y3e."  # bcrypt.gensalt()
derive_key_salt_for_filename = b"\xd0\x1ai\x9f\xe9\x1b\r\x9d2Q\x87\xa4\x85Lk\xb1"


def hash_password(password: str) -> str:
    """Hash a password and return a URL-safe Base64 encoded string."""
    hashed = bcrypt.hashpw(password.encode(), password_salt)
    return base64.urlsafe_b64encode(hashed).decode("utf-8")


def check_password(password: str, hashed: bytes) -> bool:
    """Check a hashed password."""
    return bcrypt.checkpw(password.encode(), hashed)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a cryptographic key from a password."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    derive_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    print("derive_key", derive_key)
    return derive_key


def encrypt_bytes(content: bytes, password: str, salt: bytes = None) -> bytes:
    """Encrypt file content using a derived key from the password."""
    if salt is None:
        salt = os.urandom(16)  # Generate a new salt for each encryption
    key = derive_key(password, salt)
    cipher_suite = Fernet(key)
    encrypted_content = cipher_suite.encrypt(content)
    return salt + encrypted_content  # Prepend salt to encrypted content


def decrypt_bytes(encrypted_content: bytes, password: str) -> bytes:
    """Decrypt file content using a derived key from the password."""
    salt = encrypted_content[:16]  # Extract the salt from the content
    key = derive_key(password, salt)
    cipher_suite = Fernet(key)
    return cipher_suite.decrypt(encrypted_content[16:])  # Decrypt the actual content


def encrypt_filename(filename: str, password: str) -> str:
    # TODO: encrypted value is keep changing everytime, find some alternative
    """Encrypt a filename to base64."""
    # encrypted_filename = encrypt_string(
    #     filename, password, derive_key_salt_for_filename
    # )
    # return base64.urlsafe_b64encode(encrypted_filename.encode()).decode("utf-8")
    return filename


def decrypt_filename(encrypted_filename: str, password: str) -> str:
    """Decrypt a filename from base64."""
    # decoded_filename = base64.urlsafe_b64decode(encrypted_filename).decode("utf-8")
    # decrypted_filename = decrypt_string(decoded_filename, password)
    # return decrypted_filename
    return encrypted_filename


def encrypt_string(string: str, password: str, salt: bytes = None) -> str:
    encrypted_bytes = encrypt_bytes(string.encode(), password, salt)
    return base64.b64encode(encrypted_bytes).decode()


def decrypt_string(string: str, password: str) -> str:
    decoded_bytes = base64.b64decode(string.encode())
    dencrypted_bytes = decrypt_bytes(decoded_bytes, password)
    return dencrypted_bytes


def save_hashed_password(hashed_password: bytes, file_path: str):
    with open(file_path, "wb") as file:
        file.write(hashed_password)


def retrieve_hashed_password(file_path: str) -> bytes:
    with open(file_path, "rb") as file:
        return file.read()
