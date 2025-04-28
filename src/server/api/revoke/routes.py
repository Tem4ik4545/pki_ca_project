# src/server/api/revoke/routes.py

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from datetime import datetime

from ...db.repository import CertificateRepository

router = APIRouter()

class RevokeRequest(BaseModel):
    serial_number: int
    reason: str

class RevokeResponse(BaseModel):
    serial_number: int
    revocation_date: datetime
    reason: str

@router.post("/", response_model=RevokeResponse)
async def revoke_certificate(
    req: RevokeRequest,
    db=Depends(CertificateRepository.get_db)
):
    try:
        revoked = CertificateRepository.revoke(req.serial_number, req.reason, db)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return RevokeResponse(
        serial_number=int(revoked.serial_number),
        revocation_date=revoked.revocation_date,
        reason=revoked.reason
    )
