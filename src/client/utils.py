import os
import tempfile
import requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
API_PREFIX = os.getenv("API_PREFIX", "/api/v1")
BASE_URL   = f"http://localhost:8000{API_PREFIX}"

def generate_csr_and_issue(
    common_name: str,
    organization: str,
    organizational_unit: str,
    locality: str,
    state: str,
    country: str,
    email: str
) -> tuple[str, str]:
    # Генерация ключа
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Составление subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    # Отправка CSR в CA
    resp = requests.post(f"{BASE_URL}/csr", json={"csr_pem": csr_pem})
    resp.raise_for_status()
    cert_pem = resp.json()["certificate_pem"]


    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_file.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    key_file.close()


    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_file.write(cert_pem.encode())
    cert_file.close()

    return key_file.name, cert_file.name

def revoke_cert(serial: int, reason: str) -> dict:
    resp = requests.post(
        f"{BASE_URL}/revoke",
        json={"serial_number": int(serial), "reason": reason.strip()}
    )
    resp.raise_for_status()
    return resp.json()

def get_crl() -> str:
    resp = requests.get(f"{BASE_URL}/crl")
    resp.raise_for_status()
    return resp.json()

def build_ocsp_request(cert_pem: bytes, issuer_pem: bytes) -> bytes:
    """
    Собирает OCSPRequest в DER из двух PEM-сертификатов.
    """
    cert   = x509.load_pem_x509_certificate(cert_pem)
    issuer = x509.load_pem_x509_certificate(issuer_pem)

    builder = OCSPRequestBuilder().add_certificate(
        cert=cert,
        issuer=issuer,
        algorithm=hashes.SHA1()
    )
    return builder.build().public_bytes(serialization.Encoding.DER)

def check_ocsp_status(cert_pem: bytes, issuer_pem: bytes) -> dict:
    """
    Генерирует OCSPRequest, шлёт его на сервер,
    парсит OCSPResponse и возвращает:
      {
        "status": "GOOD"|"REVOKED"|"UNKNOWN",
        "this_update": "...",
        "next_update": "...",
        "revocation_time": "...",        # или ""
        "revocation_reason": "..."       # или ""
      }
    """
    der_req = build_ocsp_request(cert_pem, issuer_pem)

    resp = requests.post(
        f"{BASE_URL}/ocsp",
        data=der_req,
        headers={"Content-Type": "application/ocsp-request"}
    )
    resp.raise_for_status()

    ocsp_resp = load_der_ocsp_response(resp.content)
    single   = ocsp_resp.responses[0]

    return {
        "status": single.cert_status.name,
        "this_update": single.this_update.isoformat(),
        "next_update": single.next_update.isoformat(),
        "revocation_time": (
            single.revocation_time.isoformat()
            if single.revocation_time else ""
        ),
        "revocation_reason": (
            single.revocation_reason.name
            if single.revocation_reason else ""
        )
    }
