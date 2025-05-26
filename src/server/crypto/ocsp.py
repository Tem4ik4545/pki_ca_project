import os
import json
import base64
from datetime import timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate

from server.db.engine import SessionLocal
from server.db.models import ActiveCertificate, RevokedCertificate

CERTS_DIR = os.getenv("CERTS_DIR", "data/certs")
KEYS_DIR = os.getenv("KEYS_DIR", "data/keys")

ISSUER_CERTS = {
    "CN=Root CA": "data/certs/root_ca_cert.pem",
    "CN=Intermediate CA 1": "data/certs/CN_Intermediate CA 1_cert.pem",
    "CN=Intermediate CA 2": "data/certs/CN_Intermediate CA 2_cert.pem",
}
def load_cert_by_issuer(issuer: str):
    path = ISSUER_CERTS.get(issuer)
    if not path or not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        return load_pem_x509_certificate(f.read())



def load_key_by_issuer(issuer: str):
    if "Intermediate CA 1" in issuer:
        key_path = os.path.join(KEYS_DIR, "intermediate", "int1_key.pem")
        password = os.getenv("INT1_CA_PASSPHRASE", "").encode()
    elif "Intermediate CA 2" in issuer:
        key_path = os.path.join(KEYS_DIR, "intermediate", "int2_key.pem")
        password = os.getenv("INT2_CA_PASSPHRASE", "").encode()
    else:
        key_path = os.getenv("ROOT_KEY_PATH", "data/keys/root_key.pem")
        password = os.getenv("ROOT_CA_PASSPHRASE", "").encode()

    with open(key_path, "rb") as f:
        return load_pem_private_key(f.read(), password=password if password else None)




def check_certificate_status(serial_number: str):
    db = SessionLocal()
    result = {"serial_number": serial_number}
    status = "unknown"

    cert = db.query(ActiveCertificate).filter_by(serial_number=serial_number).first()
    if cert:
        status = "good"
        issuer_name = cert.issuer
        issuer_cert = load_cert_by_issuer(issuer_name)
        issuer_key = load_key_by_issuer(issuer_name)
        result.update({
            "status": "good",
            "issuer": issuer_name,
            "issuer_public_key": issuer_cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        })
    else:
        revoked = db.query(RevokedCertificate).filter_by(serial_number=serial_number).first()
        if revoked:
            status = "revoked"
            issuer_name = "Intermediate CA 1"
            issuer_key = load_key_by_issuer(issuer_name)
            result.update({
                "status": "revoked",
                "revoked_at": revoked.revocation_date.astimezone(timezone.utc).isoformat(),
                "revocation_reason": revoked.reason
            })
        else:
            return None  # не найден вообще

    # Подпись JSON-ответа
    message = json.dumps(result, sort_keys=True).encode()
    signature = issuer_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    result["signature"] = base64.b64encode(signature).decode()
    return result