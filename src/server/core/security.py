# src/server/core/security.py

import os
import logging
from functools import lru_cache
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import Name, NameAttribute
from cryptography.x509.oid import NameOID



from server.core.config import settings
from server.crypto.keys import init_root_ca, init_intermediate_ca
from server.crypto.certs import generate_root_certificate, generate_intermediate_certificate

# Подгружаем .env из корня проекта


logger = logging.getLogger(__name__)

# Глобальные кеши для CA
_root_key = None
_root_cert = None
_intermediate_keys = {}
_intermediate_certs = {}

def init_security() -> None:
    """
    Инициализация PKI: ключей и сертификатов Root CA и Intermediate CA.
    """
    global _root_key, _root_cert, _intermediate_keys, _intermediate_certs

    # 1. Корневой УЦ
    root_pass = os.getenv("ROOT_CA_PASSPHRASE")
    if not root_pass:
        raise RuntimeError("Не задана переменная окружения ROOT_CA_PASSPHRASE")
    _root_key = init_root_ca(passphrase=root_pass, overwrite=False)

    root_cn = os.getenv("ROOT_CA_CN", "Root CA")
    root_subject = Name([NameAttribute(NameOID.COMMON_NAME, root_cn)])
    _root_cert = generate_root_certificate(
        root_key=_root_key,
        subject_name=root_subject,
        overwrite=False
    )
    logger.info("Root CA initialized: %s", root_cn)

    # 2. Промежуточные УЦ
    _intermediate_keys.clear()
    _intermediate_certs.clear()

    names = os.getenv("INTERMEDIATE_CA_NAMES", "")
    if not names:
        logger.warning(
            "INTERMEDIATE_CA_NAMES не задан, пропускаем генерацию intermediate CA"
        )
        return

    for name in [n.strip() for n in names.split(",") if n.strip()]:
        env_prefix = name.upper()

        int_pass = os.getenv(f"{env_prefix}_CA_PASSPHRASE")
        if not int_pass:
            raise RuntimeError(
                f"Не задана переменная окружения {env_prefix}_CA_PASSPHRASE"
            )
        ica_key = init_intermediate_ca(
            name=name,
            passphrase=int_pass,
            overwrite=False
        )

        ica_cn = os.getenv(f"{env_prefix}_CA_CN", f"{name} Intermediate CA")
        ica_subject = Name([NameAttribute(NameOID.COMMON_NAME, ica_cn)])
        ica_cert = generate_intermediate_certificate(
            intermediate_key=ica_key,
            root_cert=_root_cert,
            root_key=_root_key,
            subject_name=ica_subject,
            overwrite=False
        )

        _intermediate_keys[name] = ica_key
        _intermediate_certs[name] = ica_cert
        logger.info("Intermediate CA initialized: %s", ica_cn)


def get_issuer(ca_name: str | None = None) -> tuple[x509.Certificate, serialization.PrivateFormat]:
    """
    Возвращает (issuer_cert, issuer_key) для подписания end-entity CSR.
    Если передано ca_name:
        - "root" => Root CA
        - имя из INTERMEDIATE_CA_NAMES => соответствующий Intermediate CA
    Если не передано — используется Root CA.
    """
    if ca_name:
        name = ca_name.strip().lower()
        if name == "root":
            return _root_cert, _root_key
        for inter_name, inter_cert in _intermediate_certs.items():
            if inter_name.lower() == name:
                return inter_cert, _intermediate_keys[inter_name]
        raise RuntimeError(f"Unknown CA '{ca_name}'")

    # По умолчанию — Root CA
    return _root_cert, _root_key