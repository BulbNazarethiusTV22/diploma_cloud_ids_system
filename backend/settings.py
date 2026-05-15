import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SETTINGS_PATH = DATA_DIR / "settings.json"

DEFAULT_SETTINGS = {
    "medium_risk_threshold": 0.45,
    "high_risk_threshold": 0.70
}


def load_settings() -> dict:
    DATA_DIR.mkdir(exist_ok=True)

    if not SETTINGS_PATH.exists():
        save_settings(DEFAULT_SETTINGS)

    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as file:
            return json.load(file)

    except Exception:
        save_settings(DEFAULT_SETTINGS)
        return DEFAULT_SETTINGS.copy()


def save_settings(settings: dict) -> None:
    DATA_DIR.mkdir(exist_ok=True)

    with open(SETTINGS_PATH, "w", encoding="utf-8") as file:
        json.dump(settings, file, indent=4)
