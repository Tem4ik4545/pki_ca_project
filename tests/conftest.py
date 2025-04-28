import sys
import os
from pathlib import Path

# Добавляем src/ в PYTHONPATH для pytest
project_root = Path(__file__).parent.parent
src_path = project_root / "src"
if str(src_path) not in sys.path:
    sys.path.insert(0, str(src_path))

# Настройка переменных окружения для тестов (PKI)
os.environ.setdefault("ROOT_CA_PASSPHRASE", "changeit")
os.environ.setdefault("INTERMEDIATE_CA_NAMES", "")
