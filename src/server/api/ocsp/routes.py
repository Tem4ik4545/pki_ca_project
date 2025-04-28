# src/server/api/ocsp/routes.py

from fastapi import APIRouter, Request, Response
from server.crypto.ocsp import handle_ocsp_request

router = APIRouter()

@router.post("/", summary="Обработка OCSP-запроса")
async def ocsp_responder(request: Request):
    raw_body = await request.body()
    ocsp_response = handle_ocsp_request(raw_body)
    return Response(
        content=ocsp_response,
        media_type="application/ocsp-response"
    )
