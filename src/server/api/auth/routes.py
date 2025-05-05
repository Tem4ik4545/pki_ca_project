# src/server/api/auth/routes.py
from fastapi import APIRouter, HTTPException
from server.core.config import settings
from server.core.auth import decrypt_password

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])

@router.post("/login")
def admin_login(payload: dict):
    """Проверка пароля для скрытых функций."""
    pwd = payload.get("password") or ""
    try:
        real = decrypt_password(settings.ADMIN_PASSWORD_ENC)
    except Exception:
        raise HTTPException(500, "Ошибка расшифровки пароля")
    if pwd != real:
        raise HTTPException(401, "Неверный пароль")
    return {"ok": True}
