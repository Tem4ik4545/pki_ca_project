# tests/test_api.py

import os
import tempfile
import pytest
from fastapi.testclient import TestClient
from pathlib import Path
import sys

# Добавляем src/ в PYTHONPATH для тестов
project_root = Path(__file__).parent.parent
src_path = project_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Конфигурация тестовой БД и PKI
os.environ.setdefault("MYSQL_URL", f"sqlite:///{tempfile.NamedTemporaryFile(suffix='.db').name}")
os.environ.setdefault("ROOT_CA_PASSPHRASE", "changeit")
os.environ.setdefault("INTERMEDIATE_CA_NAMES", "")

# Перезагружаем модули конфигурации
import importlib
import server.core.config, server.db.engine
importlib.reload(server.core.config)
importlib.reload(server.db.engine)

from server.main import app
from server.db.engine import engine
from server.db.models import Base

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

@pytest.fixture(scope="module")
def client():
    # Инициализация БД
    Base.metadata.create_all(bind=engine)
    with TestClient(app) as c:
        yield c

# 1. Health-check
def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}

# 2. Issue and Revoke
def test_issue_and_revoke_flow(client):
    # Генерируем ключ и CSR
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-user")])
    ).sign(key, hashes.SHA256())
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    # Issue
    resp = client.post("/api/v1/csr", json={"csr_pem": csr_pem})
    assert resp.status_code == 200, resp.text
    cert_pem = resp.json()["certificate_pem"]
    assert cert_pem.startswith("-----BEGIN CERTIFICATE-----")

    # Извлекаем serial из сертификата
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    serial = cert.serial_number

    # Revoke
    rev = client.post(
        "/api/v1/revoke",
        json={"serial_number": serial, "reason": "test compromise"}
    )
    assert rev.status_code == 200, rev.text
    data = rev.json()
    assert data["serial_number"] == serial
    assert data["reason"] == "test compromise"

# 3. Get CRL
def test_get_crl(client):
    r = client.get("/api/v1/crl")
    assert r.status_code == 200
    assert "BEGIN X509 CRL" in r.text

# 4. OCSP invalid request
def test_ocsp_invalid(client):
    r = client.post(
        "/api/v1/ocsp",
        content=b"notader",
        headers={"Content-Type": "application/ocsp-request"}
    )
    assert r.status_code == 400
