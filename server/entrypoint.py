from __future__ import annotations

import os
import secrets
import sys


def enabled(value: str | None) -> bool:
    return str(value or "").lower() in {"1", "true", "yes", "on"}


if enabled(os.environ.get("TRAINER_PASSWORD_RANDOM_EACH_START", "1")):
    password = secrets.token_urlsafe(18)
    os.environ["TRAINER_PASSWORD"] = password
    os.environ["RESET_ADMIN_PASSWORD_ON_START"] = "1"

    print("", flush=True)
    print("========================================", flush=True)
    print(" Clicker Trainer admin login", flush=True)
    print(f" Username: {os.environ.get('TRAINER_USERNAME', 'trainer')}", flush=True)
    print(f" Password: {password}", flush=True)
    public_url = os.environ.get("TRAINER_PUBLIC_URL", "http://localhost:8000").rstrip("/")
    print(f" URL:      {public_url}/admin", flush=True)
    print("========================================", flush=True)
    print("", flush=True)

os.execvp(
    sys.executable,
    [sys.executable, "-m", "uvicorn", "server.app.main:app", "--host", "0.0.0.0", "--port", "8000"],
)
