# src/server/api/issue/routes.py

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ...core.config import settings
from ...db.repository import CertificateRepository
from .schemas import IssueRequest,IssueResponse


router = APIRouter()


@router.post("/", response_model=IssueResponse, summary="Issue a new certificate")
async def issue_certificate(
    req: IssueRequest,
    db: Session = Depends(CertificateRepository.get_db)
):
    """
    Принимаем JSON с полем csr_pem и опциональным ca_name,
    выпускаем сертификат и возвращаем PEM и серийный номер.
    """
    try:
        cert_obj = CertificateRepository.issue(
            csr_pem=req.csr_pem,
            ca_name=req.ca_name,
            db=db
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    return IssueResponse(
        certificate_pem=cert_obj.certificate_pem,
        serial_number=cert_obj.serial_number
    )
