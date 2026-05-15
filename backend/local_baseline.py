from pathlib import Path

import pandas as pd

from feature_extractor import (
    FINAL_FEATURES,
    extract_features_for_session,
)


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

BASELINE_SESSIONS_PATH = DATA_DIR / "benign_baseline_sessions.txt"


def add_session_to_baseline(session_id: str) -> None:
    DATA_DIR.mkdir(exist_ok=True)

    existing = set(get_baseline_session_ids())

    if session_id not in existing:
        with open(BASELINE_SESSIONS_PATH, "a", encoding="utf-8") as file:
            file.write(session_id + "\n")


def get_baseline_session_ids() -> list[str]:
    if not BASELINE_SESSIONS_PATH.exists():
        return []

    with open(BASELINE_SESSIONS_PATH, "r", encoding="utf-8") as file:
        session_ids = [
            line.strip()
            for line in file
            if line.strip()
        ]

    return list(dict.fromkeys(session_ids))


def build_local_baseline() -> dict:
    session_ids = get_baseline_session_ids()

    if len(session_ids) < 2:
        raise ValueError("At least 2 benign baseline sessions are required")

    rows = []
    valid_session_ids = []

    for session_id in session_ids:
        try:
            features = extract_features_for_session(session_id)
            rows.append(features)
            valid_session_ids.append(session_id)

        except Exception as e:
            print(f"Failed to extract baseline features for {session_id}: {e}")
            continue

    if len(rows) < 2:
        raise ValueError("Not enough valid baseline sessions")

    df = pd.DataFrame(rows)

    median = df[FINAL_FEATURES].median()

    iqr = (
        df[FINAL_FEATURES].quantile(0.75)
        - df[FINAL_FEATURES].quantile(0.25)
    )

    iqr = iqr.replace(0, 1e-6)

    return {
        "median": median,
        "iqr": iqr,
        "sessions_count": len(rows),
        "valid_session_ids": valid_session_ids,
    }
