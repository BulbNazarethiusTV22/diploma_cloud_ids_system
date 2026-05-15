import json
import uuid
import random
from pathlib import Path

from fastapi import Request, HTTPException, Response


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
USERS_PATH = DATA_DIR / "users.json"

active_sessions = {}


def generate_demo_ip(users: list | None = None) -> str:
    used_ips = set()

    if users:
        used_ips = {
            user.get("demo_ip")
            for user in users
            if user.get("demo_ip")
        }

    while True:
        ip = f"192.168.1.{random.randint(10, 250)}"

        if ip not in used_ips:
            return ip


def init_users_file():
    DATA_DIR.mkdir(exist_ok=True)

    if not USERS_PATH.exists():
        users = [
            {
                "username": "admin",
                "password": "admin123",
                "role": "admin",
                "demo_ip": "192.168.1.2"
            },
            {
                "username": "nazar",
                "password": "1234",
                "role": "user",
                "demo_ip": "192.168.1.10"
            }
        ]

        with open(USERS_PATH, "w", encoding="utf-8") as file:
            json.dump(users, file, indent=4)


def load_users():
    init_users_file()

    with open(USERS_PATH, "r", encoding="utf-8") as file:
        users = json.load(file)

    changed = False

    for user in users:
        if "demo_ip" not in user:
            user["demo_ip"] = generate_demo_ip(users)
            changed = True

    if changed:
        save_users(users)

    return users


def save_users(users: list):
    DATA_DIR.mkdir(exist_ok=True)

    with open(USERS_PATH, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)


def authenticate_user(username: str, password: str) -> dict | None:
    users = load_users()

    for user in users:
        if user["username"] == username and user["password"] == password:
            return user

    return None


def create_session(user: dict) -> str:
    token = str(uuid.uuid4())

    active_sessions[token] = {
        "username": user["username"],
        "role": user["role"],
        "demo_ip": user.get("demo_ip")
    }

    return token


def get_current_user(request: Request):
    token = request.cookies.get("session_token")

    if not token or token not in active_sessions:
        raise HTTPException(status_code=401, detail="Unauthorized")

    return active_sessions[token]


def require_admin(request: Request):
    user = get_current_user(request)

    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    return user


def logout_user(request: Request, response: Response):
    token = request.cookies.get("session_token")

    if token in active_sessions:
        del active_sessions[token]

    response.delete_cookie(
        key="session_token",
        path="/"
    )


def register_user(username: str, password: str):
    users = load_users()

    for user in users:
        if user["username"] == username:
            raise HTTPException(
                status_code=400,
                detail="Username already exists"
            )

    new_user = {
        "username": username,
        "password": password,
        "role": "user",
        "demo_ip": generate_demo_ip(users)
    }

    users.append(new_user)
    save_users(users)

    return new_user
