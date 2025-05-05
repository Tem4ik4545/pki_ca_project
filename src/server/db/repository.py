# src/server/db/repository.py

from typing import Generator, List
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from .engine import SessionLocal
from .models import ActiveCertificate, RevokedCertificate
from ..core.security import get_issuer
from ..crypto.certs import issue_certificate_from_csr

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
    def issue(
            cls,
            csr_pem: str,
            ca_name: str | None,
            db: Session
    ) -> ActiveCertificate:
        """
        Выпускает новый сертификат из CSR, подписывает выбранным CA (по имени ca_name или по умолчанию),
        сохраняет в БД и возвращает ORM-объект ActiveCertificate.
        """
        # выбираем нужный CA
        issuer_cert, issuer_key = get_issuer(ca_name)

        # генерируем сертификат
        cert = issue_certificate_from_csr(csr_pem=csr_pem, issuer_cert=issuer_cert, issuer_key=issuer_key)

        # сохраняем в базу
        db_obj = ActiveCertificate(
            serial_number=str(cert.serial_number),
            subject=cert.subject.rfc4514_string(),
            issuer=issuer_cert.subject.rfc4514_string(),
            not_before=cert.not_valid_before_utc,
            not_after=cert.not_valid_after_utc,
            public_key=cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            certificate_pem=cert.public_bytes(serialization.Encoding.PEM).decode(),
            status="active"
        )
        db.add(db_obj)
        db.commit()
        db.refresh(db_obj)
        return db_obj

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
