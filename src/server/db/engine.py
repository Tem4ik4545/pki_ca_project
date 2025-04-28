# src/server/db/engine.py

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from server.core.config import settings


SQLALCHEMY_DATABASE_URL = settings.MYSQL_URL


engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
    echo=False
)


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)
