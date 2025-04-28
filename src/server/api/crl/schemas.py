# src/server/api/crl/schemas.py
from datetime import datetime
from pydantic import BaseModel

class CRLEntry(BaseModel):
    serial_number: str
    revocation_date: datetime
    reason: str
