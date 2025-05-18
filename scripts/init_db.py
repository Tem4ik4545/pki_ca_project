# src/server/core/config.py

import os
from dotenv import load_dotenv, find_dotenv

# Load .env before reading env variables
dotenv_file = find_dotenv()
if dotenv_file:
    load_dotenv(dotenv_file, override=True)
from dotenv import load_dotenv, find_dotenv

# Автоматически ищем и загружаем .env из корня или выше
dotenv_file = find_dotenv()
if dotenv_file:
    load_dotenv(dotenv_file, override=True)

class Settings:
    """
    Конфигурация приложения, значения берутся из переменных окружения с дефолтами.
    """
    # API
    API_PREFIX = os.getenv("API_PREFIX", "/api/v1")

    # База данных
    MYSQL_URL = os.getenv(
        "MYSQL_URL",
        "mysql+mysqlconnector://ca_user:secret@localhost:3306/ca_db"
    )

    # Корневой УЦ
    ROOT_CA_PASSPHRASE = os.getenv("ROOT_CA_PASSPHRASE", "changeit")
    ROOT_CA_CN = os.getenv("ROOT_CA_CN", "Root CA")

    # Промежуточные УЦ
    INTERMEDIATE_CA_NAMES = os.getenv("INTERMEDIATE_CA_NAMES", "int1,int2")

    # Пути к директориям и файлам
    CERTS_DIR = os.getenv("CERTS_DIR", "data/certs")
    ROOT_KEY_PATH = os.getenv("ROOT_KEY_PATH", "data/keys/root_key.pem")
    INT_KEY_DIR = os.getenv("INT_KEY_DIR", "data/keys/intermediate")

# Экземпляр настроек
settings = Settings()
