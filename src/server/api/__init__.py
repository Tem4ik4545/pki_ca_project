from fastapi import APIRouter


from .csr import router as csr_router
from .issue import router as issue_router
from .revoke import router as revoke_router
from .crl import router as crl_router
from .ocsp import router as ocsp_router
from .crt import router as crt_router
router = APIRouter()


router.include_router(csr_router,    prefix="/csr",    tags=["CSR"])
router.include_router(issue_router,  prefix="/issue",  tags=["Issue"])
router.include_router(revoke_router, prefix="/revoke", tags=["Revoke"])
router.include_router(crl_router,    prefix="/crl",    tags=["CRL"])
router.include_router(ocsp_router,   prefix="/ocsp",   tags=["OCSP"])
router.include_router(crt_router, prefix="/crt", tags=["CRT"])

