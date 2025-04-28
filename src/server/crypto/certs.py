# src/server/crypto/certs.py

import os
from pathlib import Path
from datetime import datetime, timedelta, timezone


from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization


# Директория хранения сертификатов
CERTS_DIR = Path(os.getenv("CERTS_DIR", "data/certs"))
CERTS_DIR.mkdir(parents=True, exist_ok=True)


def generate_root_certificate(
    root_key,
    subject_name: x509.Name,
    valid_days: int = 3650,
    overwrite: bool = False
) -> x509.Certificate:
    """
    Генерирует или загружает корневой сертификат (self-signed).
    """
    cert_path = CERTS_DIR / "root_ca_cert.pem"
    if cert_path.exists() and not overwrite:
        return x509.load_pem_x509_certificate(cert_path.read_bytes(), default_backend())

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False
        )
    )

    cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256(), backend=default_backend())
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def generate_intermediate_certificate(
    intermediate_key,
    root_cert: x509.Certificate,
    root_key,
    subject_name: x509.Name,
    valid_days: int = 1825,
    overwrite: bool = False
) -> x509.Certificate:
    """
    Генерирует или загружает сертификат промежуточного УЦ.
    """
    filename = subject_name.rfc4514_string().replace("=", "_").replace(",", "_")
    cert_path = CERTS_DIR / f"{filename}_cert.pem"
    if cert_path.exists() and not overwrite:
        return x509.load_pem_x509_certificate(cert_path.read_bytes(), default_backend())

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(root_cert.subject)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()),
            critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False
        )
    )

    cert = builder.sign(private_key=root_key, algorithm=hashes.SHA256(), backend=default_backend())
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def issue_certificate_from_csr(
    csr_pem: str,
    issuer_cert: x509.Certificate,
    issuer_key,
    valid_days: int = 365
) -> x509.Certificate:
    """
    Выпускает end-entity сертификат на основе CSR в формате PEM.
    """
    csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())
    if not csr.is_signature_valid:
        raise ValueError("Invalid CSR signature")

    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )


    for ext in csr.extensions:
        builder = builder.add_extension(ext.value, ext.critical)

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
        critical=False
    ).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
        critical=False
    )

    cert = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256(), backend=default_backend())
    return cert
