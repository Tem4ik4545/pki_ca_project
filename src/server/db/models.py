from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class ActiveCertificate(Base):
    __tablename__ = "active_certs"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    serial_number = Column(String(64), unique=True, nullable=False)
    subject       = Column(String(256), nullable=False)
    issuer        = Column(String(256), nullable=False)
    not_before    = Column(DateTime(timezone=True), nullable=False)
    not_after     = Column(DateTime(timezone=True), nullable=False)
    public_key    = Column(Text, nullable=True)
    certificate_pem = Column(Text, nullable=False)
    status        = Column(String(16), nullable=False)

class RevokedCertificate(Base):
    __tablename__ = "revoked_certs"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    serial_number = Column(String(64), unique=True, nullable=False)
    revocation_date = Column(DateTime(timezone=True), nullable=False)
    reason        = Column(String(128), nullable=False)
