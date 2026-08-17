import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

APP_NAME = "ParkAccess"
SECRET_KEY = os.getenv("SECRET_KEY", "").strip() or secrets.token_hex(32)

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

DEBUG = os.getenv("FLASK_ENV", "development").strip().lower() == "development"
HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "5000"))

MYSQL_HOST = os.getenv("MYSQL_HOST", "127.0.0.1").strip()
MYSQL_PORT = int(os.getenv("MYSQL_PORT", "3306"))
MYSQL_USER = os.getenv("MYSQL_USER", "").strip()
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "parkaccess").strip() or "parkaccess"

TTLOCK_CLIENT_ID = os.getenv("TTLOCK_CLIENT_ID", "").strip().strip('"').strip("'")
TTLOCK_CLIENT_SECRET = os.getenv("TTLOCK_CLIENT_SECRET", "").strip().strip('"').strip("'")
TTLOCK_BASE_URL = os.getenv("TTLOCK_BASE_URL", "https://euapi.ttlock.com").rstrip("/")
TTLOCK_MOCK = False

UNLOCK_MAX_ATTEMPTS = 8
UNLOCK_WINDOW_SECONDS = 300

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    ).split(",")
    if origin.strip()
]

FRONTEND_DIST = BASE_DIR.parent / "frontend" / "dist"
