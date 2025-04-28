import os
from pathlib import Path
from dotenv import load_dotenv, find_dotenv
from pydantic_settings import BaseSettings

from dotenv import load_dotenv, find_dotenv

dotenv_path = find_dotenv()
if dotenv_path:
    load_dotenv(dotenv_path)


class Settings(BaseSettings):
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent

    CERTS_DIR: Path = Path(os.getenv("CERTS_DIR", BASE_DIR / "data/certs"))
    ROOT_KEY_PATH: Path = Path(os.getenv("ROOT_KEY_PATH", BASE_DIR / "data/keys/root_key.pem"))
    INT_KEY_DIR: Path = Path(os.getenv("INT_KEY_DIR", BASE_DIR / "data/keys/intermediate"))

    ROOT_CA_PASSPHRASE: str = os.getenv("ROOT_CA_PASSPHRASE", "changeit")
    ROOT_CA_CN: str = os.getenv("ROOT_CA_CN", "Root CA")

    INTERMEDIATE_CA_NAMES: str = os.getenv("INTERMEDIATE_CA_NAMES", "")
    INT1_CA_PASSPHRASE: str = os.getenv("INT1_CA_PASSPHRASE", "changeit")
    INT1_CA_CN: str = os.getenv("INT1_CA_CN", "Intermediate CA 1")
    INT2_CA_PASSPHRASE: str = os.getenv("INT2_CA_PASSPHRASE", "changeit")
    INT2_CA_CN: str = os.getenv("INT2_CA_CN", "Intermediate CA 2")
    API_PREFIX: str = "/api/v1"
    MYSQL_URL: str = os.getenv("MYSQL_URL")


settings = Settings()
