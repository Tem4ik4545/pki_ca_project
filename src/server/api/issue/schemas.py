

from pydantic import BaseModel

class IssueRequest(BaseModel):
    csr_pem: str
    ca_name: str | None = None

class IssueResponse(BaseModel):
    certificate_pem: str
    serial_number: str
