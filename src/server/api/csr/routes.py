# src/server/api/csr/routes.py

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from ...db.repository import CertificateRepository

router = APIRouter()

class CSRRequest(BaseModel):
    csr_pem: str

class CSRResponse(BaseModel):
    certificate_pem: str

@router.post(
    "/",
    response_model=CSRResponse,
    summary="Submit CSR and get issued certificate"
)
async def create_certificate(
    req: CSRRequest,
    db=Depends(CertificateRepository.get_db)
):
    """
    Принимаем CSR в PEM, подписываем и возвращаем PEM-сертификат.
    """
    try:
        cert = CertificateRepository.issue(req.csr_pem, db)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return CSRResponse(certificate_pem=cert.certificate_pem)
