# src/server/core/auth.py
import os
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv, find_dotenv
import os

dotenv_path = find_dotenv()
if dotenv_path:
    load_dotenv(dotenv_path, override=False)
# Ключ для AES (128 или 256 бит) берётся из .env
AES_KEY = b64decode(os.getenv("ADMIN_AES_KEY_B64"))

def _get_cipher(iv: bytes):
    return Cipher(algorithms.AES(AES_KEY), modes.CBC(iv))

def encrypt_password(plain: str) -> str:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    data = padder.update(plain.encode()) + padder.finalize()
    cipher = _get_cipher(iv).encryptor()
    ct = cipher.update(data) + cipher.finalize()
    return b64encode(iv + ct).decode()

def decrypt_password(token_b64: str) -> str:
    raw = b64decode(token_b64)
    iv, ct = raw[:16], raw[16:]
    cipher = _get_cipher(iv).decryptor()
    data = cipher.update(ct) + cipher.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(data) + unpadder.finalize()).decode()

