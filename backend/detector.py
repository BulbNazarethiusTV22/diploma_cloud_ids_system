from pathlib import Path

import joblib

from feature_extractor import (
    extract_features_for_session,
    build_deviation_dataframe,
)

from local_baseline import build_local_baseline


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
MODELS_DIR = PROJECT_DIR / "models"

MODEL_PATH = MODELS_DIR / "rf_deviation_model.pkl"

if not MODEL_PATH.exists():
    raise RuntimeError(f"Model file not found: {MODEL_PATH}")

model = joblib.load(MODEL_PATH)


def detect_session(session_id: str) -> dict:
    features = extract_features_for_session(session_id)

    local_baseline = build_local_baseline()

    deviation_df = build_deviation_dataframe(
        features=features,
        baseline_median=local_baseline["median"],
        baseline_iqr=local_baseline["iqr"],
    )

    prediction = model.predict(deviation_df)[0]
    probabilities = model.predict_proba(deviation_df)[0]

    class_probabilities = {
        label: float(prob)
        for label, prob in zip(model.classes_, probabilities)
    }

    anomaly_score = (
        class_probabilities.get("Attack", 0)
        + class_probabilities.get("Suspicious", 0)
    )

    return {
        "session_id": session_id,
        "prediction": prediction,
        "probability": float(probabilities.max()),
        "class_probabilities": class_probabilities,
        "features": features,
        "deviation_features": deviation_df.iloc[0].to_dict(),
        "baseline_sessions_count": local_baseline["sessions_count"],
        "ml_anomaly_score": anomaly_score,
    }
