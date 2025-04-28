# src/server/api/issue/routes.py

from fastapi import APIRouter, Depends
from ...core.config import settings
from ...db.repository import CertificateRepository

router = APIRouter()

@router.post("/", summary="Issue a new certificate")
async def issue_certificate(
    csr_pem: str,
    db=Depends(CertificateRepository.get_db)
):
    """
    Принимаем CSR в PEM, подписываем intermediate/root CA
    и сохраняем новый cert в БД.
    """
    cert = await CertificateRepository.issue(csr_pem, db)
    return {"certificate": cert}
