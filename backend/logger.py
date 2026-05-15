import csv
from datetime import datetime
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

ACCESS_LOG_PATH = DATA_DIR / "access_logs.csv"


LOG_COLUMNS = [
    "timestamp",
    "session_id",
    "ip",
    "action",
    "filename",
    "request_bytes",
    "response_bytes",
    "status_code",
    "success",
]


def init_access_log() -> None:
    if not ACCESS_LOG_PATH.exists():
        with open(ACCESS_LOG_PATH, mode="w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=LOG_COLUMNS)
            writer.writeheader()


def log_action(
    session_id: str,
    ip: str,
    action: str,
    filename: str = "",
    request_bytes: int = 0,
    response_bytes: int = 0,
    status_code: int = 200,
    success: bool = True,
    timestamp: str | None = None,
) -> None:
    init_access_log()

    row = {
        "timestamp": timestamp or datetime.now().isoformat(timespec="seconds"),
        "session_id": session_id,
        "ip": ip,
        "action": action,
        "filename": filename,
        "request_bytes": int(request_bytes),
        "response_bytes": int(response_bytes),
        "status_code": status_code,
        "success": success,
    }

    with open(ACCESS_LOG_PATH, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=LOG_COLUMNS)
        writer.writerow(row)
