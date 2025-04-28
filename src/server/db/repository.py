# src/server/db/repository.py

from typing import Generator, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from .engine import SessionLocal
from .models import ActiveCertificate, RevokedCertificate


from cryptography.hazmat.primitives import serialization

class CertificateRepository:
    @staticmethod
    def get_db() -> Generator[Session, None, None]:
        db = SessionLocal()
        try:
            yield db
        finally:
            db.close()

    @classmethod
    def issue(cls, csr_pem: str, db: Session) -> ActiveCertificate:
        """
        Принимаем CSR в PEM, подписываем, сохраняем в ActiveCertificate и возвращаем запись.
        """

        from server.core.security import get_issuer
        issuer_cert, issuer_key = get_issuer()


        from server.crypto.certs import issue_certificate_from_csr
        cert = issue_certificate_from_csr(csr_pem, issuer_cert, issuer_key)


        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        new_cert = ActiveCertificate(
            serial_number=str(cert.serial_number),
            subject=cert.subject.rfc4514_string(),
            issuer=cert.issuer.rfc4514_string(),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            certificate_pem=cert_pem,
            status="active"
        )
        db.add(new_cert)
        db.commit()
        db.refresh(new_cert)
        return new_cert

    @staticmethod
    def revoke(serial_number, reason: str, db: Session) -> RevokedCertificate:
        """
        Отзыв сертификата с заданным serial_number.
        Принимаем и int, и str — приводим к str, ищем в БД по строке.
        """
        # 1) Убедимся, что serial в виде строки точно совпадает с тем, что хранится
        serial_str = str(serial_number)

        # 2) Ищем в таблице active_certs
        cert = (
            db.query(ActiveCertificate)
              .filter(ActiveCertificate.serial_number == serial_str)
              .first()
        )
        if not cert:
            raise ValueError(f"Certificate with serial {serial_str} not found")


        revoked = RevokedCertificate(
            serial_number=serial_str,
            revocation_date=datetime.utcnow(),
            reason=reason
        )
        db.add(revoked)

        db.delete(cert)

        db.commit()

        return revoked

    @classmethod
    def list_revoked(cls, db: Session) -> List[RevokedCertificate]:
        """
        Возвращает все записи отзывов.
        """
        return db.query(RevokedCertificate).all()
