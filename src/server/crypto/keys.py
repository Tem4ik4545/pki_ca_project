# src/server/crypto/keys.py

import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Пути к файлам ключей (можно вынести в настройки)
ROOT_KEY_PATH = Path(os.getenv("ROOT_KEY_PATH", "data/keys/root_key.pem"))
INT_KEY_DIR   = Path(os.getenv("INT_KEY_DIR", "data/keys/intermediate"))
INT_KEY_DIR.mkdir(parents=True, exist_ok=True)

# Параметры KDF
KDF_SALT      = b"pki-ca-salt"
KDF_ITER      = 100_000


def _derive_key(passphrase: bytes) -> bytes:
    """
    Из пароля-фразы генерирует ключ AES через PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=KDF_SALT,
        iterations=KDF_ITER,
        backend=default_backend()
    )
    return kdf.derive(passphrase)


def generate_rsa_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    """
    Генерирует новую RSA-пару.
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def generate_ec_key(curve: ec.EllipticCurve = ec.SECP384R1()) -> ec.EllipticCurvePrivateKey:
    """
    Генерирует новую EC-пару.
    """
    return ec.generate_private_key(curve, default_backend())


def save_private_key(
    key,
    path: Path,
    passphrase: str,
    overwrite: bool = False
) -> None:
    """
    Сохраняет приватный ключ в PEM, зашифровывая AES-256-GCM,
    ключ KDF-деривится из passphrase.
    """
    if path.exists() and not overwrite:
        raise FileExistsError(f"{path} already exists")

    # Деривация ключа и упаковка шифрования
    encryption_alg = serialization.BestAvailableEncryption(passphrase.encode())

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_alg
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pem)


def load_private_key(
    path: Path,
    passphrase: str
):
    """
    Загружает приватный ключ из PEM (расшифровывает AES по passphrase).
    """
    pem_data = path.read_bytes()
    return serialization.load_pem_private_key(
        pem_data,
        password=passphrase.encode(),
        backend=default_backend()
    )


def init_root_ca(passphrase: str, overwrite: bool = False):
    """
    Если файл ключа корня не существует или overwrite=True —
    генерирует новый ключ и сохраняет его.
    """
    if not ROOT_KEY_PATH.exists() or overwrite:
        key = generate_rsa_key()
        save_private_key(key, ROOT_KEY_PATH, passphrase, overwrite=overwrite)
    else:
        key = load_private_key(ROOT_KEY_PATH, passphrase)
    return key


def init_intermediate_ca(name: str, passphrase: str, overwrite: bool = False):
    """
    Генерирует или загружает ключ intermediate CA с указанным именем.
    """
    path = INT_KEY_DIR / f"{name}_key.pem"
    if not path.exists() or overwrite:
        key = generate_rsa_key()
        save_private_key(key, path, passphrase, overwrite=overwrite)
    else:
        key = load_private_key(path, passphrase)
    return key
