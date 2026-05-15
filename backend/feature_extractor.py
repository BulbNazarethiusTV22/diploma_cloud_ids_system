from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import skew


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

ACCESS_LOG_PATH = DATA_DIR / "access_logs.csv"


FINAL_FEATURES = [
    "log_duration",
    "log_bytes_rate",
    "payload_bytes_mean",
    "payload_bytes_std",
    "payload_bytes_skewness",
    "log_down_up_rate",
]


def extract_features_for_session(session_id: str) -> dict:
    if not ACCESS_LOG_PATH.exists():
        raise FileNotFoundError("access_logs.csv not found")

    df = pd.read_csv(
        ACCESS_LOG_PATH,
        on_bad_lines="skip",
        engine="python",
    )

    session_df = df[df["session_id"] == session_id].copy()

    if session_df.empty:
        raise ValueError(f"No logs found for session_id={session_id}")

    session_df["timestamp"] = pd.to_datetime(session_df["timestamp"], errors="coerce")
    session_df = session_df.dropna(subset=["timestamp"])

    session_df["request_bytes"] = pd.to_numeric(
        session_df["request_bytes"],
        errors="coerce"
    ).fillna(0)

    session_df["response_bytes"] = pd.to_numeric(
        session_df["response_bytes"],
        errors="coerce"
    ).fillna(0)

    session_df["payload_bytes"] = (
        session_df["request_bytes"] + session_df["response_bytes"]
    )

    start_time = session_df["timestamp"].min()
    end_time = session_df["timestamp"].max()

    duration = (end_time - start_time).total_seconds()

    if duration <= 0:
        duration = 1

    total_bytes = session_df["payload_bytes"].sum()

    bytes_rate = total_bytes / duration

    payload_values = session_df["payload_bytes"].values

    payload_mean = float(np.mean(payload_values))
    payload_std = float(np.std(payload_values))

    if len(payload_values) > 2 and payload_std > 0:
        payload_skewness = float(skew(payload_values))
    else:
        payload_skewness = 0.0

    upload_bytes = session_df["request_bytes"].sum()
    download_bytes = session_df["response_bytes"].sum()

    if upload_bytes <= 0:
        down_up_rate = download_bytes / 1
    else:
        down_up_rate = download_bytes / upload_bytes

    features = {
        "log_duration": float(np.log1p(duration)),
        "log_bytes_rate": float(np.log1p(bytes_rate)),
        "payload_bytes_mean": payload_mean,
        "payload_bytes_std": payload_std,
        "payload_bytes_skewness": payload_skewness,
        "log_down_up_rate": float(np.log1p(down_up_rate)),
    }

    return features


def extract_features_dataframe_for_session(session_id: str) -> pd.DataFrame:
    features = extract_features_for_session(session_id)
    return pd.DataFrame([features], columns=FINAL_FEATURES)


DEVIATION_FEATURES = [
    "log_duration_dev",
    "log_bytes_rate_dev",
    "payload_bytes_mean_dev",
    "payload_bytes_std_dev",
    "payload_bytes_skewness_dev",
    "log_down_up_rate_dev",
    "mean_deviation",
    "max_deviation",
    "std_deviation",
    "sum_deviation",
]


def build_deviation_features(
    features: dict,
    baseline_median: pd.Series,
    baseline_iqr: pd.Series,
) -> dict:
    deviation = {}

    for feature in FINAL_FEATURES:
        iqr = baseline_iqr[feature]

        if iqr == 0:
            iqr = 1e-6

        deviation[f"{feature}_dev"] = abs(
            features[feature] - baseline_median[feature]
        ) / iqr

    values = list(deviation.values())

    deviation["mean_deviation"] = float(np.mean(values))
    deviation["max_deviation"] = float(np.max(values))
    deviation["std_deviation"] = float(np.std(values))
    deviation["sum_deviation"] = float(np.sum(values))

    return deviation


def build_deviation_dataframe(
    features: dict,
    baseline_median: pd.Series,
    baseline_iqr: pd.Series,
) -> pd.DataFrame:
    deviation = build_deviation_features(
        features,
        baseline_median,
        baseline_iqr,
    )

    return pd.DataFrame([deviation], columns=DEVIATION_FEATURES)
