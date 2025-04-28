# src/server/main.py

from fastapi import FastAPI
from .api import router as api_router
from .core.config import settings
from .db.engine import engine
from .db.models import Base
from .core.security import init_security


Base.metadata.create_all(bind=engine)


init_security()

app = FastAPI(
    title="PKI CA Server",
    version="0.1.0",
    description="Удостоверяющий центр с уровнями Root/Intermediate CA"
)

app.include_router(api_router, prefix=settings.API_PREFIX)

@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "ok"}
