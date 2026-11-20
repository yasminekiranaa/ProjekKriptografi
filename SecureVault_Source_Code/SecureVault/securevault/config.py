from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "securevault.db"
BIOMETRIC_DIR = DATA_DIR / "biometrics"
DATA_DIR.mkdir(exist_ok=True)
BIOMETRIC_DIR.mkdir(exist_ok=True)
