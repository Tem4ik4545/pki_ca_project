# src/server/crypto/crl.py

import logging
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509 import (
    CertificateRevocationListBuilder,
    RevokedCertificateBuilder
)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from server.db.models import RevokedCertificate
from server.core.security import get_issuer

logger = logging.getLogger(__name__)

def build_crl(db_session) -> bytes:

    issuer_cert, issuer_key = get_issuer()

    now = datetime.now(timezone.utc)
    builder = (
        CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(now)
        .next_update(now + timedelta(days=7))
    )


    for entry in db_session.query(RevokedCertificate).all():
        try:
            serial_int = int(entry.serial_number)
        except Exception as e:
            logger.error("CRL: неверный serial %r: %s", entry.serial_number, e)
            continue

        revoked = (
            RevokedCertificateBuilder()
            .serial_number(serial_int)
            .revocation_date(entry.revocation_date)
            .build(default_backend())
        )
        builder = builder.add_revoked_certificate(revoked)

    crl = builder.sign(
        private_key=issuer_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )
    return crl.public_bytes(serialization.Encoding.PEM)
