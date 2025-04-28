# src/server/api/crt/routes.py
from pathlib import Path

from fastapi import APIRouter, HTTPException, Response

# импорт вашего .env-конфига
from server.core.config import settings

router = APIRouter()

@router.get(
    "/ca/{name}",
    summary="Получить CA-сертификат по имени",
    responses={200: {"content": {"application/x-pem-file": {}}}}
)
async def get_ca_cert(name: str):
    """
    name — это:
      - "root"  (ROOT CA)
      - или одно из INTERMEDIATE_CA_NAMES (приводя имя к lowercase/без пробелов)
    """
    # собираем путь к PEM
    certs_dir = Path(settings.CERTS_DIR)
    filename = f"{name}_cert.pem"
    path = certs_dir / filename

    if not path.exists():
        raise HTTPException(status_code=404, detail=f"CA '{name}' не найден")
    pem = path.read_bytes()
    return Response(content=pem, media_type="application/x-pem-file")
