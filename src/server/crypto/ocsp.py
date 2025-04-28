from cryptography import x509
from cryptography.x509.ocsp import load_der_ocsp_request, OCSPResponseBuilder, OCSPCertStatus
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone

from server.db.engine import SessionLocal
from server.db.models import ActiveCertificate, RevokedCertificate
from server.crypto.keys import load_private_key
import os

CERTS_DIR = os.getenv("CERTS_DIR", "data/certs")
ROOT_CERT_PATH = os.path.join(CERTS_DIR, "root_ca_cert.pem")
ROOT_KEY_PATH = os.getenv("ROOT_KEY_PATH", "data/keys/root_key.pem")

def handle_ocsp_request(raw_request: bytes) -> bytes:
    """Обработка запроса OCSP."""

    # Парсим запрос
    ocsp_req = load_der_ocsp_request(raw_request)

    # Извлекаем serial_number
    serial_number = ocsp_req.serial_number

    db = SessionLocal()

    try:
        cert = db.query(ActiveCertificate).filter_by(serial_number=str(serial_number)).first()
        if cert:
            status = OCSPCertStatus.GOOD
            revocation_time = None
            revocation_reason = None
        else:
            revoked = db.query(RevokedCertificate).filter_by(serial_number=str(serial_number)).first()
            if revoked:
                status = OCSPCertStatus.REVOKED
                revocation_time = revoked.revocation_date.replace(tzinfo=timezone.utc)
                revocation_reason = x509.ReasonFlags.unspecified
            else:
                status = OCSPCertStatus.UNKNOWN
                revocation_time = None
                revocation_reason = None

        now = datetime.now(timezone.utc)

        issuer_cert = x509.load_pem_x509_certificate(
            open(ROOT_CERT_PATH, "rb").read(),
            default_backend()
        )
        issuer_key = load_private_key(ROOT_KEY_PATH, os.getenv("ROOT_CA_PASSPHRASE"))

        builder = OCSPResponseBuilder()

        builder = builder.add_response(
            cert=issuer_cert,
            issuer=issuer_cert,
            algorithm=hashes.SHA256(),
            cert_status=status,
            this_update=now,
            next_update=now + timedelta(days=7),
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
        )

        ocsp_response = builder.sign(
            private_key=issuer_key,
            algorithm=hashes.SHA256(),
        )

        return ocsp_response.public_bytes(serialization.Encoding.DER)

    finally:
        db.close()
