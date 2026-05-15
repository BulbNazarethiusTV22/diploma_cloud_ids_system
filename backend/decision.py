import csv
from datetime import datetime
from pathlib import Path

from detector import detect_session
from settings import load_settings


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"

ALERTS_PATH = DATA_DIR / "alerts.csv"
BLACKLIST_PATH = DATA_DIR / "blacklist.txt"


ALERT_COLUMNS = [
    "timestamp",
    "session_id",
    "ip",
    "prediction",
    "probability",
    "risk_level",
    "action_taken",
]


def init_alerts_file() -> None:
    DATA_DIR.mkdir(exist_ok=True)

    if not ALERTS_PATH.exists():
        with open(ALERTS_PATH, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=ALERT_COLUMNS)
            writer.writeheader()


def get_session_ip(session_id: str) -> str:
    access_log_path = DATA_DIR / "access_logs.csv"

    if not access_log_path.exists():
        return "unknown"

    with open(access_log_path, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        rows = [
            row
            for row in reader
            if row.get("session_id") == session_id
        ]

    if not rows:
        return "unknown"

    return rows[-1].get("ip", "unknown")


def add_ip_to_blacklist(ip: str) -> None:
    if ip == "unknown":
        return

    DATA_DIR.mkdir(exist_ok=True)

    existing_ips = set()

    if BLACKLIST_PATH.exists():
        with open(BLACKLIST_PATH, mode="r", encoding="utf-8") as file:
            existing_ips = {
                line.strip()
                for line in file
                if line.strip()
            }

    if ip not in existing_ips:
        with open(BLACKLIST_PATH, mode="a", encoding="utf-8") as file:
            file.write(ip + "\n")


def save_alert(
    session_id: str,
    ip: str,
    prediction: str,
    probability: float,
    risk_level: str,
    action_taken: str,
) -> None:
    init_alerts_file()

    row = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "session_id": session_id,
        "ip": ip,
        "prediction": prediction,
        "probability": probability,
        "risk_level": risk_level,
        "action_taken": action_taken,
    }

    with open(ALERTS_PATH, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=ALERT_COLUMNS)
        writer.writerow(row)


def analyze_security_rules(session_id: str) -> dict:
    access_log_path = DATA_DIR / "access_logs.csv"

    if not access_log_path.exists():
        return {"matched": False}

    with open(access_log_path, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        rows = [
            row
            for row in reader
            if row.get("session_id") == session_id
        ]

    if not rows:
        return {"matched": False}

    downloads = [
        row
        for row in rows
        if row.get("action") == "download"
    ]

    unauthorized = [
        row
        for row in rows
        if row.get("action") == "unauthorized_access"
    ]

    list_files = [
        row
        for row in rows
        if row.get("action") == "list_files"
    ]

    total_download_bytes = sum(
        int(float(row.get("response_bytes", 0) or 0))
        for row in downloads
    )

    if len(unauthorized) >= 10:
        return {
            "matched": True,
            "risk_level": "HIGH",
            "action_taken": "blacklist_ip",
            "reason": "Multiple unauthorized access attempts",
        }

    if len(downloads) >= 50 or total_download_bytes >= 100_000_000:
        return {
            "matched": True,
            "risk_level": "HIGH",
            "action_taken": "blacklist_ip",
            "reason": "Mass download / possible data exfiltration",
        }

    if len(list_files) >= 100:
        return {
            "matched": True,
            "risk_level": "MEDIUM",
            "action_taken": "alert_operator",
            "reason": "Suspicious directory enumeration",
        }

    return {"matched": False}


def make_decision(session_id: str) -> dict:
    detection_result = detect_session(session_id)

    prediction = detection_result["prediction"]
    probability = detection_result["probability"]
    class_probabilities = detection_result["class_probabilities"]

    ip = get_session_ip(session_id)

    attack_probability = class_probabilities.get("Attack", 0)
    suspicious_probability = class_probabilities.get("Suspicious", 0)

    anomaly_score = attack_probability + suspicious_probability

    settings = load_settings()

    medium_threshold = settings.get("medium_risk_threshold", 0.45)
    high_threshold = settings.get("high_risk_threshold", 0.70)

    risk_level = "LOW"
    action_taken = "monitor_session"
    rule_reason = ""

    rule_result = analyze_security_rules(session_id)

    if rule_result["matched"]:
        risk_level = rule_result["risk_level"]
        action_taken = rule_result["action_taken"]
        rule_reason = rule_result["reason"]

        if action_taken == "blacklist_ip":
            add_ip_to_blacklist(ip)

    else:
        if anomaly_score >= high_threshold:
            risk_level = "HIGH"
            action_taken = "blacklist_ip"
            add_ip_to_blacklist(ip)

        elif anomaly_score >= medium_threshold:
            risk_level = "MEDIUM"
            action_taken = "ml_anomaly_alert"

        else:
            risk_level = "LOW"
            action_taken = "monitor_session"

    save_alert(
        session_id=session_id,
        ip=ip,
        prediction=prediction,
        probability=probability,
        risk_level=risk_level,
        action_taken=action_taken,
    )

    result = {
        "session_id": session_id,
        "ip": ip,
        "prediction": prediction,
        "probability": probability,
        "risk_level": risk_level,
        "action_taken": action_taken,
        "class_probabilities": class_probabilities,
        "attack_probability": attack_probability,
        "suspicious_probability": suspicious_probability,
        "ml_anomaly_score": anomaly_score,
    }

    if rule_reason:
        result["rule_reason"] = rule_reason

    return result
