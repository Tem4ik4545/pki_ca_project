import os
import tempfile
import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
API_PREFIX = os.getenv("API_PREFIX", "/api/v1")
BASE_URL   = f"http://localhost:8000{API_PREFIX}"





def verify_admin(password: str):
    resp = requests.post(f"{BASE_URL}/admin/login", json={"password": password})
    return resp.status_code == 200
def do_revoke_ui(serial_str, reason_str):
    serial_str = serial_str.strip()
    if not serial_str.isdigit():
        return "❌ Формат серийного номера неверен: только цифры."
    serial = int(serial_str)
    try:
        r = revoke_cert(serial, reason_str)
        return (
            f"✔ Сертификат отозван:\n"
            f"- Серийный номер: {r['serial_number']}\n"
            f"- Дата отзыва: {r['revocation_date']}\n"
            f"- Причина: {r['reason']}"
        )
    except requests.HTTPError as he:
        try:
            detail = he.response.json().get("detail", he.response.text)
        except:
            detail = he.response.text
        return f"❌ Ошибка сервера: {detail}"
    except Exception as e:
        return f"❌ Непредвиденная ошибка: {e}"


def fetch_crl_ui() -> list[list[str]]:
    data = get_crl() or []
    return [
        [
            entry.get("serial_number", ""),
            entry.get("revocation_date", ""),
            entry.get("reason", ""),
        ]
        for entry in data
    ]

def generate_csr_and_issue(
    common_name: str,
    organization: str,
    organizational_unit: str,
    locality: str,
    state: str,
    country: str,
    email: str,
    ca_name: str | None = None
) -> tuple[str, str, str]:
    # 1) Генерация ключа
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 2) Составление CSR
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, email),
    ])
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256(), default_backend())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    payload = {"csr_pem": csr_pem}
    if ca_name and ca_name.strip():
        payload["ca_name"] = ca_name

    resp = requests.post(f"{BASE_URL}/issue", json=payload)
    resp.raise_for_status()
    data = resp.json()
    cert_pem = data["certificate_pem"]
    serial = str(data["serial_number"])

    # 4) Сохранение приватного ключа
    key_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    key_file.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
    key_file.close()

    # 5) Сохранение сертификата
    cert_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
    cert_file.write(cert_pem.encode())
    cert_file.close()

    return key_file.name, cert_file.name, serial
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

def check_ocsp_status(serial_number: str) -> dict:
    resp = requests.post(f"{BASE_URL}/ocsp", json={"serial_number": serial_number})
    resp.raise_for_status()
    return resp.json()

def get_issuer_pubkey(issuer_name: str) -> str:
    resp = requests.get(f"{BASE_URL}/ocsp/issuer-key/{issuer_name}")
    resp.raise_for_status()
    return resp.text

