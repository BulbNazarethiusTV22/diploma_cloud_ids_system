import random
import uuid
from pathlib import Path

import joblib
import pandas as pd

from feature_extractor import DEVIATION_FEATURES
from settings import load_settings


BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
MODELS_DIR = PROJECT_DIR / "models"

MODEL_PATH = MODELS_DIR / "rf_deviation_model.pkl"

if not MODEL_PATH.exists():
    raise RuntimeError(f"Model file not found: {MODEL_PATH}")

model = joblib.load(MODEL_PATH)


def get_risk_level(anomaly_score: float) -> str:
    settings = load_settings()

    medium_threshold = settings.get("medium_risk_threshold", 0.45)
    high_threshold = settings.get("high_risk_threshold", 0.70)

    if anomaly_score >= high_threshold:
        return "HIGH"

    if anomaly_score >= medium_threshold:
        return "MEDIUM"

    return "LOW"


def simulate_feature_attack_search(attempts: int = 100) -> dict:
    if attempts <= 0:
        raise ValueError("attempts must be greater than 0")

    best_result = None
    best_attack_prob = -1

    for attempt in range(attempts):
        row = {
            "log_duration_dev": random.uniform(1.0, 5.0),
            "log_bytes_rate_dev": random.uniform(0.5, 4.0),
            "payload_bytes_mean_dev": random.uniform(0.0, 0.8),
            "payload_bytes_std_dev": random.uniform(0.0, 1.2),
            "payload_bytes_skewness_dev": random.uniform(0.0, 4.0),
            "log_down_up_rate_dev": random.uniform(0.2, 4.0),
        }

        dev_values = list(row.values())

        row["mean_deviation"] = sum(dev_values) / len(dev_values)
        row["max_deviation"] = max(dev_values)
        row["std_deviation"] = (
            sum((x - row["mean_deviation"]) ** 2 for x in dev_values)
            / len(dev_values)
        ) ** 0.5
        row["sum_deviation"] = sum(dev_values)

        X = pd.DataFrame([row], columns=DEVIATION_FEATURES)

        prediction = model.predict(X)[0]
        probabilities = model.predict_proba(X)[0]

        class_probabilities = {
            label: float(prob)
            for label, prob in zip(model.classes_, probabilities)
        }

        attack_prob = class_probabilities.get("Attack", 0)
        suspicious_prob = class_probabilities.get("Suspicious", 0)
        anomaly_score = attack_prob + suspicious_prob

        result = {
            "simulation_id": f"feature-attack-{uuid.uuid4()}",
            "scenario": "synthetic_feature_attack_search",
            "attempt": attempt,
            "prediction": prediction,
            "probability": float(probabilities.max()),
            "attack_probability": attack_prob,
            "suspicious_probability": suspicious_prob,
            "anomaly_score": anomaly_score,
            "risk_level": get_risk_level(anomaly_score),
            "class_probabilities": class_probabilities,
            "deviation_features": row,
        }

        if attack_prob > best_attack_prob:
            best_attack_prob = attack_prob
            best_result = result

        if prediction == "Attack":
            return {
                **result,
                "found_attack": True,
            }

    if best_result is None:
        raise RuntimeError("Simulation failed: no candidates generated")

    return {
        **best_result,
        "found_attack": False,
        "note": "No direct Attack prediction found; returned highest Attack probability candidate.",
    }
