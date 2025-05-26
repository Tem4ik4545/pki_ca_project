from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from server.crypto.ocsp import check_certificate_status

from fastapi.responses import PlainTextResponse
import urllib.parse
import os
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization

router = APIRouter()

class OCSPRequest(BaseModel):
    serial_number: str

@router.post("/", summary="Проверка статуса сертификата по серийному номеру")
async def check_ocsp_status(request: OCSPRequest):
    result = check_certificate_status(request.serial_number)
    if result is None:
        raise HTTPException(status_code=404, detail="Сертификат не найден")
    return result
@router.get("/issuer-key/{issuer_name}", response_class=PlainTextResponse)
def get_issuer_pubkey(issuer_name: str):
    CERTS = {
        "Root CA": "data/certs/root_ca_cert.pem",
        "Intermediate CA 1": "data/certs/CN_Intermediate CA 1_cert.pem",
        "Intermediate CA 2": "data/certs/CN_Intermediate CA 2_cert.pem"
    }

    decoded_name = urllib.parse.unquote_plus(issuer_name)
    path = CERTS.get(decoded_name)

    if not path or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="УЦ не найден")

    with open(path, "rb") as f:
        cert = load_pem_x509_certificate(f.read())
        return cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")