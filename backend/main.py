import os
import uuid
import shutil
from pathlib import Path
import csv
from collections import defaultdict

from fastapi import FastAPI, UploadFile, File, HTTPException, Request, Form, Response
from fastapi.responses import FileResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from auth import (
    authenticate_user,
    create_session,
    get_current_user,
    require_admin,
    logout_user,
    register_user,
)

from logger import log_action
from minio_client import (
    ensure_bucket_exists,
    upload_file,
    list_files,
    download_file,
    delete_file,
    create_folder,
    delete_folder,
)

from feature_extractor import extract_features_for_session
from detector import detect_session
from decision import make_decision, save_alert
from simulator import simulate_feature_attack_search
from local_baseline import add_session_to_baseline, get_baseline_session_ids
from pydantic import BaseModel
from settings import load_settings, save_settings
from decision import add_ip_to_blacklist

BASE_DIR = Path(__file__).resolve().parent
TEMP_DIR = BASE_DIR / "temp"
TEMP_DIR.mkdir(exist_ok=True)

app = FastAPI(title="Cloud IDS Storage Gateway")

STATIC_DIR = BASE_DIR / "static"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

class RiskSettings(BaseModel):
    medium_risk_threshold: float
    high_risk_threshold: float


class BlacklistRequest(BaseModel):
    ip: str


def get_session_id(request: Request) -> str:
    return request.headers.get("X-Session-ID", "default-session")


def get_client_ip(request: Request) -> str:
    try:
        user = get_current_user(request)
        if user.get("demo_ip"):
            return user["demo_ip"]
    except Exception:
        pass

    return request.client.host if request.client else "unknown"

def is_ip_blacklisted(ip: str) -> bool:
    blacklist_path = BASE_DIR / "data" / "blacklist.txt"

    if not blacklist_path.exists():
        return False

    with open(blacklist_path, mode="r", encoding="utf-8") as file:
        blacklisted_ips = {line.strip() for line in file if line.strip()}

    return ip in blacklisted_ips


def block_if_blacklisted(request: Request) -> None:
    ip = get_client_ip(request)

    if is_ip_blacklisted(ip):
        raise HTTPException(
            status_code=403,
            detail=f"Access denied. IP {ip} is blacklisted."
        )

@app.on_event("startup")
def startup_event():
    ensure_bucket_exists()


@app.get("/")
def root(request: Request):
    try:
        get_current_user(request)
        return FileResponse(STATIC_DIR / "index.html")
    except HTTPException:
        return RedirectResponse(url="/login", status_code=302)


@app.post("/upload")
async def upload(request: Request, file: UploadFile = File(...)):
    get_current_user(request)
    block_if_blacklisted(request)
    
    safe_temp_name = file.filename.replace("/", "_").replace("\\", "_")
    temp_path = TEMP_DIR / safe_temp_name
    object_name = file.filename
    
    session_id = get_session_id(request)
    ip = get_client_ip(request)

    try:
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        file_size = temp_path.stat().st_size

        upload_file(
            object_name=object_name,
            file_path=str(temp_path),
            content_type=file.content_type or "application/octet-stream",
        )

        log_action(
            session_id=session_id,
            ip=ip,
            action="upload",
            filename=object_name,
            request_bytes=file_size,
            response_bytes=0,
            status_code=200,
            success=True,
        )

        return {
            "status": "success",
            "message": "File uploaded successfully",
            "filename": file.filename,
        }

    except Exception as e:
        log_action(
            session_id=session_id,
            ip=ip,
            action="upload",
            filename=file.filename,
            request_bytes=0,
            response_bytes=0,
            status_code=500,
            success=False,
        )
        raise HTTPException(status_code=500, detail=str(e))

    finally:
        if temp_path.exists():
            os.remove(temp_path)


@app.get("/files")
def get_files(request: Request):
    get_current_user(request)
    block_if_blacklisted(request)
    
    session_id = get_session_id(request)
    ip = get_client_ip(request)

    try:
        files = list_files()

        log_action(
            session_id=session_id,
            ip=ip,
            action="list_files",
            filename="",
            request_bytes=0,
            response_bytes=len(str(files).encode("utf-8")),
            status_code=200,
            success=True,
        )

        return {"files": files}

    except Exception as e:
        log_action(
            session_id=session_id,
            ip=ip,
            action="list_files",
            filename="",
            request_bytes=0,
            response_bytes=0,
            status_code=500,
            success=False,
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/download/{filename:path}")
def download(request: Request, filename: str):
    get_current_user(request)
    block_if_blacklisted(request)
    safe_temp_name = filename.replace("/", "_").replace("\\", "_")
    temp_path = TEMP_DIR / safe_temp_name
    session_id = get_session_id(request)
    ip = get_client_ip(request)

    try:
        download_file(filename, str(temp_path))
        file_size = temp_path.stat().st_size

        log_action(
            session_id=session_id,
            ip=ip,
            action="download",
            filename=filename,
            request_bytes=0,
            response_bytes=file_size,
            status_code=200,
            success=True,
        )

        return FileResponse(
            path=temp_path,
            filename=filename,
            media_type="application/octet-stream",
        )

    except Exception as e:
        log_action(
            session_id=session_id,
            ip=ip,
            action="download",
            filename=filename,
            request_bytes=0,
            response_bytes=0,
            status_code=404,
            success=False,
        )
        raise HTTPException(status_code=404, detail=str(e))


@app.delete("/delete/{filename:path}")
def delete(request: Request, filename: str):
    get_current_user(request)
    block_if_blacklisted(request)
    session_id = get_session_id(request)
    ip = get_client_ip(request)

    try:
        delete_file(filename)

        log_action(
            session_id=session_id,
            ip=ip,
            action="delete",
            filename=filename,
            request_bytes=0,
            response_bytes=0,
            status_code=200,
            success=True,
        )

        return {
            "status": "success",
            "message": "File deleted successfully",
            "filename": filename,
        }

    except Exception as e:
        log_action(
            session_id=session_id,
            ip=ip,
            action="delete",
            filename=filename,
            request_bytes=0,
            response_bytes=0,
            status_code=404,
            success=False,
        )
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/sessions/{session_id}/detect")
def detect_session_endpoint(request: Request, session_id: str):
    require_admin(request)
    try:
        result = detect_session(session_id)
        return result

    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.get("/sessions/{session_id}/decision")
def decision_endpoint(request: Request, session_id: str):
    require_admin(request)
    try:
        result = make_decision(session_id)
        return result

    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))

@app.post("/folders")
def create_folder_endpoint(request: Request, folder_path: str):
    get_current_user(request)
    block_if_blacklisted(request)

    session_id = get_session_id(request)
    ip = get_client_ip(request)

    try:
        create_folder(folder_path)

        log_action(
            session_id=session_id,
            ip=ip,
            action="create_folder",
            filename=folder_path,
            request_bytes=len(folder_path.encode("utf-8")),
            response_bytes=0,
            status_code=200,
            success=True,
        )

        return {
            "status": "success",
            "message": "Folder created successfully",
            "folder_path": folder_path,
        }

    except Exception as e:
        log_action(
            session_id=session_id,
            ip=ip,
            action="create_folder",
            filename=folder_path,
            request_bytes=len(folder_path.encode("utf-8")),
            response_bytes=0,
            status_code=500,
            success=False,
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/folders/{folder_path:path}")
def delete_folder_endpoint(request: Request, folder_path: str):
    get_current_user(request)
    block_if_blacklisted(request)

    session_id = get_session_id(request)
    ip = get_client_ip(request)

    try:
        result = delete_folder(folder_path)

        log_action(
            session_id=session_id,
            ip=ip,
            action="delete_folder",
            filename=folder_path,
            request_bytes=len(folder_path.encode("utf-8")),
            response_bytes=result["deleted_bytes"],
            status_code=200,
            success=True,
        )

        return {
            "status": "success",
            "message": "Folder deleted successfully",
            **result,
        }

    except Exception as e:
        log_action(
            session_id=session_id,
            ip=ip,
            action="delete_folder",
            filename=folder_path,
            request_bytes=len(folder_path.encode("utf-8")),
            response_bytes=0,
            status_code=500,
            success=False,
        )

        raise HTTPException(status_code=500, detail=str(e))

@app.get("/login")
def login_page():
    return FileResponse(STATIC_DIR / "login.html")


@app.post("/login")
def login(
    response: Response,
    username: str = Form(...),
    password: str = Form(...)
):
    user = authenticate_user(username, password)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    token = create_session(user)

    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        samesite="lax",
        path="/"
    )

    return {
        "status": "success",
        "username": user["username"],
        "role": user["role"]
    }


@app.post("/logout")
def logout(request: Request):
    response = JSONResponse({
        "status": "success",
        "message": "Logged out"
    })

    logout_user(request, response)

    return response


@app.get("/me")
def me(request: Request):
    user = get_current_user(request)

    return user

@app.get("/admin")
def admin_page(request: Request):
    try:
        require_admin(request)
        return FileResponse(STATIC_DIR / "admin.html")
    except HTTPException:
        return RedirectResponse(url="/login", status_code=302)

@app.post("/register")
def register(
    username: str = Form(...),
    password: str = Form(...)
):
    user = register_user(username, password)

    return {
        "status": "success",
        "message": "User registered successfully",
        "username": user["username"],
        "role": user["role"]
    }

def read_csv_file(path: Path) -> list[dict]:
    if not path.exists():
        return []

    with open(path, mode="r", encoding="utf-8") as file:
        return list(csv.DictReader(file))


def read_blacklist() -> list[str]:
    blacklist_path = BASE_DIR / "data" / "blacklist.txt"

    if not blacklist_path.exists():
        return []

    with open(blacklist_path, mode="r", encoding="utf-8") as file:
        return [line.strip() for line in file if line.strip()]


@app.get("/admin/api/logs")
def admin_logs(
    request: Request,
    page: int = 1,
    page_size: int = 20,
):
    require_admin(request)

    logs_path = BASE_DIR / "data" / "access_logs.csv"
    logs = read_csv_file(logs_path)

    logs = list(reversed(logs))

    total_count = len(logs)

    page = max(page, 1)
    page_size = max(min(page_size, 100), 1)

    total_pages = max((total_count + page_size - 1) // page_size, 1)

    if page > total_pages:
        page = total_pages

    start = (page - 1) * page_size
    end = start + page_size

    return {
        "count": total_count,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "logs": logs[start:end],
    }


@app.get("/admin/api/alerts")
def admin_alerts(request: Request):
    require_admin(request)

    alerts_path = BASE_DIR / "data" / "alerts.csv"
    alerts = read_csv_file(alerts_path)

    return {
        "count": len(alerts),
        "alerts": alerts[-200:]
    }


@app.get("/admin/api/blacklist")
def admin_blacklist(request: Request):
    require_admin(request)

    blacklist = read_blacklist()

    return {
        "count": len(blacklist),
        "blacklist": blacklist
    }


@app.get("/admin/api/sessions")
def admin_sessions(request: Request):
    require_admin(request)

    logs_path = BASE_DIR / "data" / "access_logs.csv"
    logs = read_csv_file(logs_path)

    sessions = defaultdict(lambda: {
        "session_id": "",
        "ip": "",
        "actions_count": 0,
        "first_activity": "",
        "last_activity": "",
        "last_action": "",
    })

    for row in logs:
        session_id = row.get("session_id", "unknown")

        session = sessions[session_id]

        session["session_id"] = session_id
        session["ip"] = row.get("ip", "unknown")
        session["actions_count"] += 1

        timestamp = row.get("timestamp", "")

        if not session["first_activity"]:
            session["first_activity"] = timestamp

        session["last_activity"] = timestamp
        session["last_action"] = row.get("action", "")

    result = list(sessions.values())

    return {
        "count": len(result),
        "sessions": result
    }


@app.get("/admin/api/summary")
def admin_summary(request: Request):
    require_admin(request)

    logs = read_csv_file(BASE_DIR / "data" / "access_logs.csv")
    alerts = read_csv_file(BASE_DIR / "data" / "alerts.csv")
    blacklist = read_blacklist()

    session_ids = {
        row.get("session_id")
        for row in logs
        if row.get("session_id")
    }

    high_risk_alerts = [
        alert for alert in alerts
        if alert.get("risk_level") == "HIGH"
    ]

    medium_risk_alerts = [
        alert for alert in alerts
        if alert.get("risk_level") == "MEDIUM"
    ]

    return {
        "logs_count": len(logs),
        "sessions_count": len(session_ids),
        "alerts_count": len(alerts),
        "high_risk_alerts": len(high_risk_alerts),
        "medium_risk_alerts": len(medium_risk_alerts),
        "blacklist_count": len(blacklist),
    }

@app.post("/admin/api/baseline/{session_id}")
def add_baseline_session_endpoint(request: Request, session_id: str):
    require_admin(request)

    add_session_to_baseline(session_id)

    return {
        "status": "success",
        "message": "Session added to benign baseline",
        "session_id": session_id,
    }


@app.get("/admin/api/baseline")
def get_baseline_sessions_endpoint(request: Request):
    require_admin(request)

    sessions = get_baseline_session_ids()

    return {
        "count": len(sessions),
        "sessions": sessions,
    }

@app.post("/simulate/feature-attack")
def simulate_feature_attack_endpoint(request: Request):
    require_admin(request)

    result = simulate_feature_attack_search(attempts=100)

    session_id = f"feature-sim-{uuid.uuid4()}"
    ip = get_client_ip(request)

    log_action(
        session_id=session_id,
        ip=ip,
        action="feature_level_attack_simulation",
        filename="synthetic_deviation_features",
        request_bytes=0,
        response_bytes=0,
        status_code=200,
        success=True,
    )

    settings = load_settings()

    medium_threshold = settings.get("medium_risk_threshold", 0.45)
    high_threshold = settings.get("high_risk_threshold", 0.70)

    anomaly_score = result["anomaly_score"]

    if anomaly_score >= high_threshold:
        risk_level = "HIGH"
        action_taken = "ml_high_risk_alert"

    elif anomaly_score >= medium_threshold:
        risk_level = "MEDIUM"
        action_taken = "ml_anomaly_alert"

    else:
        risk_level = "LOW"
        action_taken = "monitor_session"

    save_alert(
        session_id=session_id,
        ip=ip,
        prediction=result["prediction"],
        probability=result["probability"],
        risk_level=risk_level,
        action_taken=action_taken,
    )

    return {
        **result,
        "session_id": session_id,
        "logged_to_sessions": True,
        "alert_created": True,
        "risk_level": risk_level,
        "action_taken": action_taken,
    }

@app.get("/admin/api/settings")
def get_settings_endpoint(request: Request):
    require_admin(request)
    return load_settings()


@app.post("/admin/api/settings")
def update_settings_endpoint(request: Request, settings: RiskSettings):
    require_admin(request)

    save_settings(settings.model_dump())

    return {
        "status": "success",
        "settings": settings.model_dump()
    }


@app.post("/admin/api/blacklist")
def add_blacklist_endpoint(request: Request, item: BlacklistRequest):
    require_admin(request)

    add_ip_to_blacklist(item.ip)

    return {
        "status": "success",
        "message": "IP added to blacklist",
        "ip": item.ip
    }


@app.delete("/admin/api/blacklist/{ip}")
def remove_blacklist_endpoint(request: Request, ip: str):
    require_admin(request)

    blacklist_path = BASE_DIR / "data" / "blacklist.txt"

    if blacklist_path.exists():
        with open(blacklist_path, "r", encoding="utf-8") as file:
            ips = [line.strip() for line in file if line.strip()]

        ips = [item for item in ips if item != ip]

        with open(blacklist_path, "w", encoding="utf-8") as file:
            for item in ips:
                file.write(item + "\n")

    return {
        "status": "success",
        "message": "IP removed from blacklist",
        "ip": ip
    }
