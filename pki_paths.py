from pathlib import Path

APP_ROOT = Path(__file__).parent.resolve()
DATA_DIR = APP_ROOT / "data"
CA_ROOT = DATA_DIR / "ca"
ISSUED_ROOT = DATA_DIR / "issued"
