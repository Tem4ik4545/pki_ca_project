# src/server/api/csr/routes.py

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

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
    ca_name: str | None = None,
    db: Session = Depends(CertificateRepository.get_db)
):
    """
    Принимаем CSR в PEM, опционально имя CA (query-параметр ca_name),
    выпускаем и возвращаем новый сертификат.
    """
    try:
        cert_obj = CertificateRepository.issue(
            csr_pem=req.csr_pem,
            ca_name=ca_name,
            db=db
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return CSRResponse(certificate_pem=cert_obj.certificate_pem)
