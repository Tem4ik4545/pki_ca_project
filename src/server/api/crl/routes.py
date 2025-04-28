# src/server/api/crl/routes.py
from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from server.db.repository import CertificateRepository
from server.db.models import RevokedCertificate
from .schemas import CRLEntry

router = APIRouter()

@router.get("/", response_model=List[CRLEntry], summary="Список отозванных сертификатов")
async def get_crl_list(db: Session = Depends(CertificateRepository.get_db)):
    """
    Возвращает JSON-массив всех отозванных сертификатов:
    - serial_number
    - revocation_date
    - reason
    """
    revoked = db.query(RevokedCertificate).all()
    return [
        CRLEntry(
            serial_number=entry.serial_number,
            revocation_date=entry.revocation_date,
            reason=entry.reason
        )
        for entry in revoked
    ]
