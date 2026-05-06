from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import random
import secrets
import sqlite3
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from common.protocol import PROTOCOL_VERSION, compatible


APP_NAME = "Clicker Trainer"
ROOT = Path(__file__).resolve().parents[2]
DB_PATH = Path(os.environ.get("TRAINER_DB_PATH", ROOT / "server" / "trainer.sqlite3"))
AUDIO_DIR = Path(os.environ.get("TRAINER_AUDIO_DIR", ROOT / "server" / "audio"))
RECORDING_DIR = Path(os.environ.get("TRAINER_RECORDING_DIR", ROOT / "server" / "recordings"))
CLICK_MIN_SECONDS = 1
CLICK_MAX_SECONDS = 6000
BARK_MAX_SECONDS = 6000
TRAINER_USERNAME = os.environ.get("TRAINER_USERNAME", "trainer")
TRAINER_PASSWORD = os.environ.get("TRAINER_PASSWORD", "trainer")
SESSION_SECRET = os.environ.get("SESSION_SECRET", TRAINER_PASSWORD)
RESET_ADMIN_PASSWORD_ON_START = os.environ.get("RESET_ADMIN_PASSWORD_ON_START") == "1"
TRAINER_COOKIE = "trainer_session"
PET_COOKIE = "pet_session"
SESSION_TTL_SECONDS = 60 * 60 * 12


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 150_000)
    return f"pbkdf2${salt}${base64.b64encode(digest).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt, digest_text = stored.split("$", 2)
    except ValueError:
        return False
    if scheme != "pbkdf2":
        return False
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 150_000)
    return hmac.compare_digest(base64.b64encode(digest).decode(), digest_text)


def sign(value: str) -> str:
    signature = hmac.new(SESSION_SECRET.encode(), value.encode(), "sha256").hexdigest()
    return f"{value}.{signature}"


def unsign(cookie: str | None) -> str | None:
    if not cookie or "." not in cookie:
        return None
    value, signature = cookie.rsplit(".", 1)
    expected = sign(value).rsplit(".", 1)[1]
    if not hmac.compare_digest(signature, expected):
        return None
    parts = value.split("|")
    try:
        issued = int(parts[-1])
    except (ValueError, IndexError):
        return None
    if time.time() - issued > SESSION_TTL_SECONDS:
        return None
    return value


async def read_json(request: Request) -> dict[str, Any]:
    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Expected JSON body") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Expected JSON object")
    return payload


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = asyncio.Lock()

    async def setup(self) -> None:
        async with self.lock:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS trainers (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('admin', 'trainer')),
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    code TEXT NOT NULL UNIQUE,
                    active INTEGER NOT NULL DEFAULT 1,
                    stay_enabled INTEGER NOT NULL DEFAULT 0,
                    stay_until REAL,
                    random_enabled INTEGER NOT NULL DEFAULT 0,
                    click_min_seconds INTEGER NOT NULL DEFAULT 30,
                    click_max_seconds INTEGER NOT NULL DEFAULT 300,
                    kneel_enabled INTEGER NOT NULL DEFAULT 0,
                    break_enabled INTEGER NOT NULL DEFAULT 0,
                    break_interval_seconds INTEGER NOT NULL DEFAULT 1800,
                    break_duration_seconds INTEGER NOT NULL DEFAULT 300,
                    bark_enabled INTEGER NOT NULL DEFAULT 0,
                    bark_min_seconds INTEGER NOT NULL DEFAULT 30,
                    bark_max_seconds INTEGER NOT NULL DEFAULT 300,
                    bark_response_seconds INTEGER NOT NULL DEFAULT 5,
                    bark_record_seconds INTEGER NOT NULL DEFAULT 10,
                    bark_record_enabled INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    pet_id INTEGER,
                    event TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS bark_recordings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pet_id INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    content_type TEXT NOT NULL,
                    duration_seconds INTEGER NOT NULL,
                    size_bytes INTEGER NOT NULL
                );
                """
            )
            pet_columns = {
                row["name"]
                for row in self.connection.execute("PRAGMA table_info(pets)").fetchall()
            }
            pet_defaults = {
                "kneel_enabled": "INTEGER NOT NULL DEFAULT 0",
                "break_enabled": "INTEGER NOT NULL DEFAULT 0",
                "break_interval_seconds": "INTEGER NOT NULL DEFAULT 1800",
                "break_duration_seconds": "INTEGER NOT NULL DEFAULT 300",
                "bark_enabled": "INTEGER NOT NULL DEFAULT 0",
                "bark_min_seconds": "INTEGER NOT NULL DEFAULT 30",
                "bark_max_seconds": "INTEGER NOT NULL DEFAULT 300",
                "bark_response_seconds": "INTEGER NOT NULL DEFAULT 5",
                "bark_record_seconds": "INTEGER NOT NULL DEFAULT 10",
                "bark_record_enabled": "INTEGER NOT NULL DEFAULT 0",
            }
            for column, definition in pet_defaults.items():
                if column not in pet_columns:
                    self.connection.execute(f"ALTER TABLE pets ADD COLUMN {column} {definition}")
            log_columns = {
                row["name"]
                for row in self.connection.execute("PRAGMA table_info(logs)").fetchall()
            }
            if "pet_id" not in log_columns:
                self.connection.execute("ALTER TABLE logs ADD COLUMN pet_id INTEGER")
            if RESET_ADMIN_PASSWORD_ON_START:
                self.connection.execute(
                    "INSERT INTO trainers(username, password_hash, role, created_at) VALUES(?, ?, 'admin', ?) "
                    "ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash, role = 'admin'",
                    (TRAINER_USERNAME, hash_password(TRAINER_PASSWORD), now_iso()),
                )
            trainer_count = self.connection.execute("SELECT COUNT(*) AS count FROM trainers").fetchone()["count"]
            if trainer_count == 0:
                self.connection.execute(
                    "INSERT INTO trainers(username, password_hash, role, created_at) VALUES(?, ?, 'admin', ?)",
                    (TRAINER_USERNAME, hash_password(TRAINER_PASSWORD), now_iso()),
                )
            self.connection.commit()

    async def authenticate_trainer(self, username: str, password: str) -> dict[str, Any] | None:
        async with self.lock:
            row = self.connection.execute("SELECT * FROM trainers WHERE username = ?", (username,)).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            return None
        return {"username": row["username"], "role": row["role"]}

    async def list_trainers(self) -> list[dict[str, Any]]:
        async with self.lock:
            rows = self.connection.execute(
                "SELECT username, role, created_at FROM trainers ORDER BY username"
            ).fetchall()
        return [dict(row) for row in rows]

    async def add_trainer(self, username: str, password: str, role: str) -> None:
        username = username.strip()
        if not username or not all(char.isalnum() or char in "._-" for char in username):
            raise HTTPException(status_code=400, detail="Use only letters, numbers, dots, dashes, and underscores in usernames")
        if len(password) < 4:
            raise HTTPException(status_code=400, detail="Password must be at least 4 characters")
        role = role if role in {"admin", "trainer"} else "trainer"
        async with self.lock:
            self.connection.execute(
                "INSERT INTO trainers(username, password_hash, role, created_at) VALUES(?, ?, ?, ?) "
                "ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash, role = excluded.role",
                (username, hash_password(password), role, now_iso()),
            )
            self.connection.commit()

    async def delete_trainer(self, username: str) -> None:
        async with self.lock:
            count = self.connection.execute("SELECT COUNT(*) AS count FROM trainers").fetchone()["count"]
            if count <= 1:
                raise HTTPException(status_code=400, detail="Keep at least one trainer")
            self.connection.execute("DELETE FROM trainers WHERE username = ?", (username,))
            self.connection.commit()

    async def list_pets(self) -> list[dict[str, Any]]:
        async with self.lock:
            rows = self.connection.execute("SELECT * FROM pets WHERE active = 1 ORDER BY id").fetchall()
        return [self._pet_row(row) for row in rows]

    async def get_pet(self, pet_id: int) -> dict[str, Any] | None:
        async with self.lock:
            row = self.connection.execute("SELECT * FROM pets WHERE id = ? AND active = 1", (pet_id,)).fetchone()
        return self._pet_row(row) if row else None

    async def get_pet_by_code(self, code: str) -> dict[str, Any] | None:
        async with self.lock:
            row = self.connection.execute("SELECT * FROM pets WHERE code = ? AND active = 1", (code.strip(),)).fetchone()
        return self._pet_row(row) if row else None

    async def add_pet(self, name: str, code: str) -> dict[str, Any]:
        name = name.strip() or "Pet"
        code = code.strip()
        if len(code) < 3:
            raise HTTPException(status_code=400, detail="Code must be at least 3 characters")
        async with self.lock:
            try:
                cursor = self.connection.execute(
                    "INSERT INTO pets(name, code, created_at) VALUES(?, ?, ?)",
                    (name, code, now_iso()),
                )
            except sqlite3.IntegrityError as exc:
                raise HTTPException(status_code=400, detail="That code is already in use") from exc
            self.connection.commit()
            pet_id = int(cursor.lastrowid)
        pet = await self.get_pet(pet_id)
        assert pet is not None
        return pet

    async def update_pet_code(self, pet_id: int, code: str) -> None:
        code = code.strip()
        if len(code) < 3:
            raise HTTPException(status_code=400, detail="Code must be at least 3 characters")
        async with self.lock:
            try:
                self.connection.execute("UPDATE pets SET code = ? WHERE id = ?", (code, pet_id))
            except sqlite3.IntegrityError as exc:
                raise HTTPException(status_code=400, detail="That code is already in use") from exc
            self.connection.commit()

    async def delete_pet(self, pet_id: int) -> None:
        async with self.lock:
            self.connection.execute("UPDATE pets SET active = 0 WHERE id = ?", (pet_id,))
            self.connection.commit()

    async def set_stay(self, pet_id: int, enabled: bool, duration_seconds: int | None) -> None:
        stay_until = None
        if enabled and duration_seconds:
            stay_until = time.time() + max(1, duration_seconds)
        async with self.lock:
            self.connection.execute(
                "UPDATE pets SET stay_enabled = ?, stay_until = ? WHERE id = ?",
                (1 if enabled else 0, stay_until, pet_id),
            )
            self.connection.commit()

    async def expire_stay(self, pet_id: int) -> None:
        async with self.lock:
            self.connection.execute("UPDATE pets SET stay_enabled = 0, stay_until = NULL WHERE id = ?", (pet_id,))
            self.connection.commit()

    async def set_random_click(self, pet_id: int, enabled: bool, min_seconds: int, max_seconds: int) -> None:
        async with self.lock:
            self.connection.execute(
                "UPDATE pets SET random_enabled = ?, click_min_seconds = ?, click_max_seconds = ? WHERE id = ?",
                (1 if enabled else 0, min_seconds, max_seconds, pet_id),
            )
            self.connection.commit()

    async def set_kneel(self, pet_id: int, enabled: bool) -> None:
        async with self.lock:
            self.connection.execute(
                "UPDATE pets SET kneel_enabled = ? WHERE id = ?",
                (1 if enabled else 0, pet_id),
            )
            self.connection.commit()

    async def set_breaks(self, pet_id: int, enabled: bool, interval_seconds: int, duration_seconds: int) -> None:
        async with self.lock:
            self.connection.execute(
                "UPDATE pets SET break_enabled = ?, break_interval_seconds = ?, break_duration_seconds = ? WHERE id = ?",
                (1 if enabled else 0, interval_seconds, duration_seconds, pet_id),
            )
            self.connection.commit()

    async def set_bark(self, pet_id: int, enabled: bool, min_seconds: int, max_seconds: int, response_seconds: int, record_seconds: int, record_enabled: bool) -> None:
        async with self.lock:
            self.connection.execute(
                """
                UPDATE pets
                SET bark_enabled = ?, bark_min_seconds = ?, bark_max_seconds = ?,
                    bark_response_seconds = ?, bark_record_seconds = ?, bark_record_enabled = ?
                WHERE id = ?
                """,
                (1 if enabled else 0, min_seconds, max_seconds, response_seconds, record_seconds, 1 if record_enabled else 0, pet_id),
            )
            self.connection.commit()

    async def add_recording(self, pet_id: int, filename: str, content_type: str, duration_seconds: int, size_bytes: int) -> int:
        async with self.lock:
            cursor = self.connection.execute(
                "INSERT INTO bark_recordings(pet_id, created_at, filename, content_type, duration_seconds, size_bytes) VALUES(?, ?, ?, ?, ?, ?)",
                (pet_id, now_iso(), filename, content_type, duration_seconds, size_bytes),
            )
            self.connection.commit()
            return int(cursor.lastrowid)

    async def list_recordings(self, limit: int = 80) -> list[dict[str, Any]]:
        async with self.lock:
            rows = self.connection.execute(
                """
                SELECT bark_recordings.*, pets.name AS pet_name
                FROM bark_recordings
                LEFT JOIN pets ON pets.id = bark_recordings.pet_id
                ORDER BY bark_recordings.id DESC
                LIMIT ?
                """,
                (min(max(limit, 1), 300),),
            ).fetchall()
        return [dict(row) for row in rows]

    async def get_recording(self, recording_id: int) -> dict[str, Any] | None:
        async with self.lock:
            row = self.connection.execute("SELECT * FROM bark_recordings WHERE id = ?", (recording_id,)).fetchone()
        return dict(row) if row else None

    async def delete_recording(self, recording_id: int) -> dict[str, Any] | None:
        recording = await self.get_recording(recording_id)
        if not recording:
            return None
        async with self.lock:
            self.connection.execute("DELETE FROM bark_recordings WHERE id = ?", (recording_id,))
            self.connection.commit()
        return recording

    async def clear_logs(self) -> None:
        async with self.lock:
            self.connection.execute("DELETE FROM logs")
            self.connection.commit()

    async def log(self, event: str, pet_id: int | None = None, detail: dict[str, Any] | None = None) -> None:
        async with self.lock:
            self.connection.execute(
                "INSERT INTO logs(created_at, pet_id, event, detail) VALUES(?, ?, ?, ?)",
                (now_iso(), pet_id, event, json.dumps(detail or {})),
            )
            self.connection.commit()

    async def recent_logs(self, limit: int = 120) -> list[dict[str, Any]]:
        async with self.lock:
            rows = self.connection.execute(
                """
                SELECT logs.id, logs.created_at, logs.pet_id, logs.event, logs.detail, pets.name AS pet_name
                FROM logs
                LEFT JOIN pets ON pets.id = logs.pet_id
                ORDER BY logs.id DESC
                LIMIT ?
                """,
                (min(max(limit, 1), 500),),
            ).fetchall()
        logs: list[dict[str, Any]] = []
        for row in reversed(rows):
            try:
                detail = json.loads(row["detail"])
            except json.JSONDecodeError:
                detail = {}
            logs.append(
                {
                    "id": row["id"],
                    "created_at": row["created_at"],
                    "pet_id": row["pet_id"],
                    "pet_name": row["pet_name"],
                    "event": row["event"],
                    "detail": detail,
                }
            )
        return logs

    def _pet_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "name": row["name"],
            "code": row["code"],
            "stay_enabled": bool(row["stay_enabled"]),
            "stay_until": row["stay_until"],
            "random_enabled": bool(row["random_enabled"]),
            "click_min_seconds": row["click_min_seconds"],
            "click_max_seconds": row["click_max_seconds"],
            "kneel_enabled": bool(row["kneel_enabled"]),
            "break_enabled": bool(row["break_enabled"]),
            "break_interval_seconds": row["break_interval_seconds"],
            "break_duration_seconds": row["break_duration_seconds"],
            "bark_enabled": bool(row["bark_enabled"]),
            "bark_min_seconds": row["bark_min_seconds"],
            "bark_max_seconds": row["bark_max_seconds"],
            "bark_response_seconds": row["bark_response_seconds"],
            "bark_record_seconds": row["bark_record_seconds"],
            "bark_record_enabled": bool(row["bark_record_enabled"]),
            "created_at": row["created_at"],
        }


class Hub:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.clients: dict[int, set[WebSocket]] = {}
        self.client_pet: dict[WebSocket, int] = {}
        self.trainers: set[WebSocket] = set()
        self.presence: dict[int, bool | None] = {}
        self.kneeling: dict[int, bool | None] = {}
        self.parts: dict[int, list[str]] = {}
        self.connected_at: dict[int, str] = {}
        self.live_allowed: dict[int, bool] = {}
        self.live_enabled: dict[int, bool] = {}
        self.next_click_at: dict[int, float] = {}
        self.break_due_at: dict[int, float] = {}
        self.break_started_at: dict[int, float] = {}
        self.break_until: dict[int, float] = {}
        self.break_overdue: dict[int, bool] = {}
        self.next_bark_at: dict[int, float] = {}
        self.bark_pending_until: dict[int, float] = {}
        self.lock = asyncio.Lock()
        self._random_task: asyncio.Task[None] | None = None
        self._timer_task: asyncio.Task[None] | None = None

    async def start(self) -> None:
        self._random_task = asyncio.create_task(self._random_loop())
        self._timer_task = asyncio.create_task(self._timer_loop())

    async def stop(self) -> None:
        for task in (self._random_task, self._timer_task):
            if task:
                task.cancel()

    async def register_client(self, websocket: WebSocket, pet_id: int) -> None:
        async with self.lock:
            self.clients.setdefault(pet_id, set()).add(websocket)
            self.client_pet[websocket] = pet_id
            self.connected_at[pet_id] = now_iso()
            self.presence.setdefault(pet_id, None)
            self.kneeling.setdefault(pet_id, None)
            self.parts.setdefault(pet_id, [])
            pet = await self.store.get_pet(pet_id)
            if pet and pet["break_enabled"]:
                self.break_due_at.setdefault(pet_id, time.time() + pet["break_interval_seconds"])
        await self.store.log("pet_connected", pet_id, {"clients": len(self.clients.get(pet_id, []))})
        await websocket.send_json({"type": "hello", "protocol_version": PROTOCOL_VERSION})
        await self.send_pet_settings(websocket, pet_id)
        await self.broadcast_trainers()

    async def unregister_client(self, websocket: WebSocket) -> None:
        pet_id = self.client_pet.pop(websocket, None)
        if pet_id is None:
            return
        async with self.lock:
            self.clients.get(pet_id, set()).discard(websocket)
            if not self.clients.get(pet_id):
                self.clients.pop(pet_id, None)
                self.presence[pet_id] = None
                self.kneeling[pet_id] = None
                self.parts[pet_id] = []
                self.connected_at.pop(pet_id, None)
                self.live_enabled[pet_id] = False
                self.break_due_at.pop(pet_id, None)
                self.break_started_at.pop(pet_id, None)
                self.break_until.pop(pet_id, None)
                self.break_overdue.pop(pet_id, None)
                self.next_bark_at.pop(pet_id, None)
                self.bark_pending_until.pop(pet_id, None)
        await self.store.log("pet_disconnected", pet_id, {})
        await self.broadcast_trainers()

    async def register_trainer(self, websocket: WebSocket) -> None:
        self.trainers.add(websocket)
        await self.send_to_trainer(websocket)

    async def unregister_trainer(self, websocket: WebSocket) -> None:
        self.trainers.discard(websocket)

    async def set_stay(self, pet_id: int, enabled: bool, duration_seconds: int | None) -> None:
        await self.store.set_stay(pet_id, enabled, duration_seconds)
        await self.store.log("stay_in_frame_updated", pet_id, {"enabled": enabled, "duration_seconds": duration_seconds})
        await self.broadcast_pet_settings(pet_id)
        await self.broadcast_trainers()

    async def set_random_click(self, pet_id: int, enabled: bool, min_seconds: int, max_seconds: int) -> None:
        min_seconds = min(CLICK_MAX_SECONDS, max(CLICK_MIN_SECONDS, min_seconds))
        max_seconds = min(CLICK_MAX_SECONDS, max(CLICK_MIN_SECONDS, max_seconds))
        if min_seconds > max_seconds:
            max_seconds = min_seconds
        await self.store.set_random_click(pet_id, enabled, min_seconds, max_seconds)
        self.next_click_at.pop(pet_id, None)
        await self.store.log("random_click_updated", pet_id, {"enabled": enabled, "min_seconds": min_seconds, "max_seconds": max_seconds})
        await self.broadcast_trainers()

    async def set_kneel(self, pet_id: int, enabled: bool) -> None:
        await self.store.set_kneel(pet_id, enabled)
        await self.store.log("kneel_check_updated", pet_id, {"enabled": enabled})
        await self.broadcast_pet_settings(pet_id)
        await self.broadcast_trainers()

    async def set_breaks(self, pet_id: int, enabled: bool, interval_seconds: int, duration_seconds: int) -> None:
        interval_seconds = min(24 * 60 * 60, max(60, interval_seconds))
        duration_seconds = min(60 * 60, max(30, duration_seconds))
        await self.store.set_breaks(pet_id, enabled, interval_seconds, duration_seconds)
        now = time.time()
        if enabled:
            self.break_due_at[pet_id] = now + interval_seconds
        else:
            self.break_due_at.pop(pet_id, None)
            self.break_started_at.pop(pet_id, None)
            self.break_until.pop(pet_id, None)
            self.break_overdue.pop(pet_id, None)
        await self.store.log("breaks_updated", pet_id, {"enabled": enabled, "interval_seconds": interval_seconds, "duration_seconds": duration_seconds})
        await self.broadcast_pet_settings(pet_id)
        await self.broadcast_trainers()

    async def set_bark(self, pet_id: int, enabled: bool, min_seconds: int, max_seconds: int, response_seconds: int, record_seconds: int, record_enabled: bool) -> None:
        min_seconds = min(BARK_MAX_SECONDS, max(1, min_seconds))
        max_seconds = min(BARK_MAX_SECONDS, max(1, max_seconds))
        if min_seconds > max_seconds:
            max_seconds = min_seconds
        response_seconds = min(60, max(1, response_seconds))
        record_seconds = min(60, max(1, record_seconds))
        await self.store.set_bark(pet_id, enabled, min_seconds, max_seconds, response_seconds, record_seconds, record_enabled)
        self.next_bark_at.pop(pet_id, None)
        self.bark_pending_until.pop(pet_id, None)
        await self.store.log("bark_check_updated", pet_id, {
            "enabled": enabled,
            "min_seconds": min_seconds,
            "max_seconds": max_seconds,
            "response_seconds": response_seconds,
            "record_seconds": record_seconds,
            "record_enabled": record_enabled,
        })
        await self.broadcast_pet_settings(pet_id)
        await self.broadcast_trainers()

    async def manual_click(self, pet_id: int) -> None:
        await self.store.log("manual_click", pet_id, {})
        await self.broadcast_clients(pet_id, {"type": "play_click", "source": "manual"})
        await self.broadcast_trainers()

    async def trigger_speak(self, pet_id: int, source: str = "manual") -> None:
        pet = await self.store.get_pet(pet_id)
        if not pet:
            return
        self.bark_pending_until[pet_id] = time.time() + pet["bark_response_seconds"]
        await self.store.log("speak_prompt", pet_id, {"source": source, "response_seconds": pet["bark_response_seconds"]})
        await self.broadcast_clients(pet_id, {
            "type": "speak",
            "response_seconds": pet["bark_response_seconds"],
            "record_seconds": pet["bark_record_seconds"],
            "record_enabled": pet["bark_record_enabled"],
        })
        await self.broadcast_trainers()

    async def update_presence(self, pet_id: int, present: bool, confidence: float | None, parts: list[str], kneeling: bool | None = None) -> None:
        previous = self.presence.get(pet_id)
        self.presence[pet_id] = present
        self.parts[pet_id] = parts
        if previous != present:
            event = "pet_returned" if present else "pet_left_frame"
            await self.store.log(event, pet_id, {"confidence": confidence, "parts": parts})
        previous_kneeling = self.kneeling.get(pet_id)
        if kneeling is not None:
            self.kneeling[pet_id] = kneeling
            if previous_kneeling != kneeling:
                await self.store.log("pet_knelt" if kneeling else "pet_not_kneeling", pet_id, {"confidence": confidence})
        await self.broadcast_trainers()

    async def set_break_state(self, pet_id: int, active: bool) -> None:
        pet = await self.store.get_pet(pet_id)
        if not pet or not pet["break_enabled"]:
            return
        now = time.time()
        if active:
            self.break_started_at[pet_id] = now
            self.break_until[pet_id] = now + pet["break_duration_seconds"]
            self.break_overdue[pet_id] = False
            await self.store.log("break_started", pet_id, {"duration_seconds": pet["break_duration_seconds"]})
        else:
            self.break_started_at.pop(pet_id, None)
            self.break_until.pop(pet_id, None)
            self.break_overdue.pop(pet_id, None)
            self.break_due_at[pet_id] = now + pet["break_interval_seconds"]
            await self.store.log("break_ended", pet_id, {})
        await self.broadcast_pet_settings(pet_id)
        await self.broadcast_trainers()

    async def handle_bark_noise(self, pet_id: int, level: float) -> None:
        pending_until = self.bark_pending_until.get(pet_id)
        if not pending_until or time.time() > pending_until:
            return
        self.bark_pending_until.pop(pet_id, None)
        await self.store.log("bark_detected", pet_id, {"level": level})
        await self.broadcast_trainers()

    async def save_bark_recording(self, pet_id: int, data_url: str, duration_seconds: int) -> None:
        if "," not in data_url:
            return
        header, encoded = data_url.split(",", 1)
        content_type = "audio/webm"
        if header.startswith("data:") and ";" in header:
            content_type = header[5:].split(";", 1)[0] or content_type
        try:
            blob = base64.b64decode(encoded, validate=True)
        except Exception:
            return
        if not blob or len(blob) > 5_000_000:
            return
        RECORDING_DIR.mkdir(parents=True, exist_ok=True)
        filename = f"bark-{pet_id}-{int(time.time())}-{secrets.token_hex(4)}.webm"
        path = RECORDING_DIR / filename
        path.write_bytes(blob)
        recording_id = await self.store.add_recording(pet_id, filename, content_type, duration_seconds, len(blob))
        await self.store.log("bark_recording_saved", pet_id, {"recording_id": recording_id, "size_bytes": len(blob)})
        await self.broadcast_trainers()

    async def set_live_allowed(self, pet_id: int, allowed: bool) -> None:
        self.live_allowed[pet_id] = allowed
        if not allowed:
            self.live_enabled[pet_id] = False
            await self.broadcast_clients(pet_id, {"type": "live_request", "enabled": False})
        await self.store.log("live_feed_permission_updated", pet_id, {"allowed": allowed})
        await self.broadcast_trainers()

    async def set_live_enabled(self, pet_id: int, enabled: bool) -> None:
        enabled = bool(enabled and self.live_allowed.get(pet_id, False))
        self.live_enabled[pet_id] = enabled
        await self.store.log("live_feed_updated", pet_id, {"enabled": enabled})
        await self.broadcast_clients(pet_id, {"type": "live_request", "enabled": enabled})
        await self.broadcast_trainers()

    async def forward_live_frame(self, pet_id: int, frame: str) -> None:
        if not self.live_allowed.get(pet_id) or not self.live_enabled.get(pet_id):
            return
        await self.broadcast_trainers({"type": "live_frame", "pet_id": pet_id, "frame": frame})

    async def send_pet_settings(self, websocket: WebSocket, pet_id: int) -> None:
        pet = await self.store.get_pet(pet_id)
        if pet:
            await websocket.send_json({"type": "settings", "settings": self._client_settings(pet)})

    async def broadcast_pet_settings(self, pet_id: int) -> None:
        pet = await self.store.get_pet(pet_id)
        if pet:
            await self.broadcast_clients(pet_id, {"type": "settings", "settings": self._client_settings(pet)})

    async def state(self, me: dict[str, str] | None = None) -> dict[str, Any]:
        role = me.get("role") if me else None
        pets: list[dict[str, Any]] = []
        trainers: list[dict[str, Any]] = []
        recordings: list[dict[str, Any]] = []
        if role == "trainer":
            pets = await self.store.list_pets()
            await self._expire_stay_if_needed(pets)
            pets = await self.store.list_pets()
            recordings = await self.store.list_recordings()
        elif role == "admin":
            trainers = await self.store.list_trainers()
        return {
            "protocol_version": PROTOCOL_VERSION,
            "me": me,
            "pets": [self._public_pet(pet) for pet in pets],
            "trainers": trainers,
            "recordings": recordings,
            "audio": {
                "beep_exists": (AUDIO_DIR / "beep.mp3").exists(),
                "click_exists": (AUDIO_DIR / "click.mp3").exists(),
            },
            "pet_link": "/pet",
        }

    async def broadcast_trainers(self, payload: dict[str, Any] | None = None) -> None:
        stale: list[WebSocket] = []
        for trainer in list(self.trainers):
            try:
                if payload is None:
                    await self.send_to_trainer(trainer)
                elif payload.get("type") == "live_frame" and trainer_from_cookie(trainer.cookies.get(TRAINER_COOKIE), role="trainer"):
                    await trainer.send_json(payload)
                elif payload.get("type") != "live_frame":
                    await trainer.send_json(payload)
            except Exception:
                stale.append(trainer)
        for trainer in stale:
            self.trainers.discard(trainer)

    async def send_to_trainer(self, websocket: WebSocket) -> None:
        me = trainer_from_cookie(websocket.cookies.get(TRAINER_COOKIE))
        logs = [] if me and me.get("role") == "admin" else await self.store.recent_logs(120)
        await websocket.send_json(
            {"type": "state", "state": await self.state(me), "logs": logs}
        )

    async def broadcast_clients(self, pet_id: int, payload: dict[str, Any]) -> None:
        stale: list[WebSocket] = []
        for client in list(self.clients.get(pet_id, set())):
            try:
                await client.send_json(payload)
            except Exception:
                stale.append(client)
        for client in stale:
            await self.unregister_client(client)

    def _client_settings(self, pet: dict[str, Any]) -> dict[str, Any]:
        break_until = self.break_until.get(pet["id"])
        return {
            "stay_in_frame_enabled": self._stay_active(pet),
            "kneel_enabled": pet["kneel_enabled"],
            "break_enabled": pet["break_enabled"],
            "break_due_at": self.break_due_at.get(pet["id"]),
            "break_until": break_until,
            "break_overdue": self.break_overdue.get(pet["id"], False),
            "bark_enabled": pet["bark_enabled"],
            "bark_response_seconds": pet["bark_response_seconds"],
            "bark_record_seconds": pet["bark_record_seconds"],
            "bark_record_enabled": pet["bark_record_enabled"],
        }

    def _public_pet(self, pet: dict[str, Any]) -> dict[str, Any]:
        stay_remaining = None
        if pet["stay_until"] is not None:
            stay_remaining = max(0, int(pet["stay_until"] - time.time()))
        return {
            **pet,
            "stay_active": self._stay_active(pet),
            "stay_seconds_remaining": stay_remaining,
            "connected": bool(self.clients.get(pet["id"])),
            "clients": len(self.clients.get(pet["id"], set())),
            "presence": self.presence.get(pet["id"]),
            "kneeling": self.kneeling.get(pet["id"]),
            "parts": self.parts.get(pet["id"], []),
            "connected_at": self.connected_at.get(pet["id"]),
            "live_allowed": self.live_allowed.get(pet["id"], False),
            "live_enabled": self.live_enabled.get(pet["id"], False),
            "break_due_at": self.break_due_at.get(pet["id"]),
            "break_until": self.break_until.get(pet["id"]),
            "break_overdue": self.break_overdue.get(pet["id"], False),
            "bark_pending_until": self.bark_pending_until.get(pet["id"]),
        }

    def _stay_active(self, pet: dict[str, Any]) -> bool:
        if not pet["stay_enabled"]:
            return False
        return pet["stay_until"] is None or pet["stay_until"] > time.time()

    async def _expire_stay_if_needed(self, pets: list[dict[str, Any]] | None = None) -> None:
        for pet in pets or await self.store.list_pets():
            if pet["stay_enabled"] and pet["stay_until"] is not None and pet["stay_until"] <= time.time():
                await self.store.expire_stay(pet["id"])
                await self.store.log("stay_in_frame_expired", pet["id"], {})
                await self.broadcast_pet_settings(pet["id"])

    async def _timer_loop(self) -> None:
        while True:
            await asyncio.sleep(1)
            await self._expire_stay_if_needed()
            now = time.time()
            for pet in await self.store.list_pets():
                pet_id = pet["id"]
                if pet["break_enabled"] and self.break_until.get(pet_id) and now > self.break_until[pet_id]:
                    if not self.break_overdue.get(pet_id):
                        self.break_overdue[pet_id] = True
                        await self.store.log("break_overdue", pet_id, {})
                        await self.broadcast_pet_settings(pet_id)
                pending_until = self.bark_pending_until.get(pet_id)
                if pending_until and now > pending_until:
                    self.bark_pending_until.pop(pet_id, None)
                    await self.store.log("bark_missed", pet_id, {})
            await self.broadcast_trainers()

    async def _random_loop(self) -> None:
        while True:
            await asyncio.sleep(0.5)
            now = time.time()
            for pet in await self.store.list_pets():
                pet_id = pet["id"]
                connected = bool(self.clients.get(pet_id))
                if not pet["random_enabled"] or not connected:
                    self.next_click_at.pop(pet_id, None)
                else:
                    due = self.next_click_at.get(pet_id)
                    if due is None:
                        self.next_click_at[pet_id] = now + random.randint(pet["click_min_seconds"], pet["click_max_seconds"])
                    elif now >= due:
                        await self.store.log("random_click", pet_id, {})
                        await self.broadcast_clients(pet_id, {"type": "play_click", "source": "random"})
                        self.next_click_at[pet_id] = now + random.randint(pet["click_min_seconds"], pet["click_max_seconds"])
                        await self.broadcast_trainers()
                if pet["bark_enabled"] and connected:
                    bark_due = self.next_bark_at.get(pet_id)
                    if bark_due is None:
                        self.next_bark_at[pet_id] = now + random.randint(pet["bark_min_seconds"], pet["bark_max_seconds"])
                    elif now >= bark_due:
                        await self.trigger_speak(pet_id, "random")
                        self.next_bark_at[pet_id] = now + random.randint(pet["bark_min_seconds"], pet["bark_max_seconds"])
                else:
                    self.next_bark_at.pop(pet_id, None)


store = Store(DB_PATH)
hub = Hub(store)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await store.setup()
    await hub.start()
    try:
        yield
    finally:
        await hub.stop()


app = FastAPI(title=APP_NAME, lifespan=lifespan)
AUDIO_DIR.mkdir(parents=True, exist_ok=True)
RECORDING_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/audio", StaticFiles(directory=AUDIO_DIR), name="audio")


@app.get("/api/audio/debug")
async def audio_debug() -> dict[str, Any]:
    files: dict[str, dict[str, Any]] = {}
    for filename in ("beep.mp3", "click.mp3"):
        path = AUDIO_DIR / filename
        files[filename] = {
            "path": str(path),
            "exists": path.exists(),
            "size": path.stat().st_size if path.exists() else 0,
            "url": f"/audio/{filename}",
        }
    return {"audio_dir": str(AUDIO_DIR), "files": files}


def trainer_from_cookie(cookie: str | None, role: str | None = None) -> dict[str, str] | None:
    value = unsign(cookie)
    if not value:
        return None
    parts = value.split("|")
    if len(parts) != 4 or parts[0] != "trainer":
        return None
    me = {"username": parts[1], "role": parts[2]}
    if role is not None and me["role"] != role:
        return None
    return me


def pet_id_from_cookie(cookie: str | None) -> int | None:
    value = unsign(cookie)
    if not value:
        return None
    parts = value.split("|")
    if len(parts) != 3 or parts[0] != "pet":
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def require_trainer(request: Request) -> dict[str, str]:
    me = trainer_from_cookie(request.cookies.get(TRAINER_COOKIE), role="trainer")
    if not me:
        raise HTTPException(status_code=403, detail="Trainer account required")
    return me


def require_admin(request: Request) -> dict[str, str]:
    me = trainer_from_cookie(request.cookies.get(TRAINER_COOKIE), role="admin")
    if not me:
        raise HTTPException(status_code=403, detail="Admin only")
    return me


def render_page(title: str, body: str) -> HTMLResponse:
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
:root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif; --bg: #f5f6f8; --text: #17191c; --panel: #ffffff; --border: #dde2ea; --soft-border: #e4e8ef; --input: #ffffff; --muted: #687282; --primary: #1f6feb; --secondary-bg: #e7eaee; --secondary-text: #20242a; --ok-bg: #dff6e8; --ok-text: #136c36; --bad-bg: #ffe1e1; --bad-text: #9b1c20; --camera-bg: #12161c; }}
:root.dark {{ color-scheme: dark; --bg: #111418; --text: #f2f5f8; --panel: #1a1f26; --border: #303844; --soft-border: #313945; --input: #111820; --muted: #a1abb8; --primary: #4c8dff; --secondary-bg: #2a323d; --secondary-text: #f2f5f8; --ok-bg: #153c25; --ok-text: #8ee0aa; --bad-bg: #4a1d22; --bad-text: #ff9aa2; --camera-bg: #080a0d; }}
body {{ margin: 0; background: var(--bg); color: var(--text); }}
button, input, select {{ font: inherit; }}
button {{ border: 0; border-radius: 6px; padding: 10px 13px; background: var(--primary); color: white; cursor: pointer; transition: transform .08s ease, opacity .12s ease; }}
button:active {{ transform: translateY(1px); }}
button.secondary {{ background: var(--secondary-bg); color: var(--secondary-text); }}
button.danger {{ background: #bc2f32; }}
button.busy {{ opacity: .7; }}
button:disabled {{ opacity: .45; cursor: not-allowed; }}
input, select {{ border: 1px solid var(--border); border-radius: 6px; padding: 9px 10px; background: var(--input); color: var(--text); }}
h1, h2, h3 {{ margin: 0; }}
.shell {{ max-width: 1280px; margin: 0 auto; padding: 24px; }}
.top {{ display: flex; align-items: center; justify-content: space-between; gap: 16px; margin-bottom: 18px; }}
.grid {{ display: grid; grid-template-columns: 300px 1fr; gap: 16px; align-items: start; }}
.panel {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
.stack {{ display: grid; gap: 12px; }}
.row {{ display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
.field {{ display: grid; gap: 6px; }}
.field label {{ color: var(--muted); font-size: 13px; }}
.badge {{ display: inline-flex; align-items: center; border-radius: 999px; padding: 4px 9px; background: var(--secondary-bg); color: var(--secondary-text); font-size: 13px; }}
.badge.ok {{ background: var(--ok-bg); color: var(--ok-text); }}
.badge.bad {{ background: var(--bad-bg); color: var(--bad-text); }}
.list {{ display: grid; gap: 8px; }}
.item {{ border: 1px solid var(--soft-border); border-radius: 8px; padding: 10px; display: grid; gap: 6px; }}
.item.active {{ border-color: var(--primary); box-shadow: inset 3px 0 0 var(--primary); }}
.toolbar {{ display: flex; gap: 8px; flex-wrap: wrap; }}
.logs {{ height: 360px; overflow: auto; display: grid; align-content: start; gap: 8px; }}
.log {{ display: grid; grid-template-columns: 170px 120px 1fr; gap: 10px; border-bottom: 1px solid var(--soft-border); padding-bottom: 8px; }}
.time, .quiet {{ color: var(--muted); }}
[hidden] {{ display: none !important; }}
.login, .pet {{ min-height: 100vh; display: grid; place-items: center; padding: 24px; }}
.login form {{ width: min(460px, 100%); }}
.pet main {{ width: min(900px, 100%); }}
.camera {{ width: 100%; aspect-ratio: 16 / 9; background: var(--camera-bg); border-radius: 8px; object-fit: cover; transform: scaleX(-1); }}
.live {{ width: 100%; max-width: 980px; aspect-ratio: 16 / 9; object-fit: cover; background: var(--camera-bg); border-radius: 8px; }}
.live[hidden] {{ display: none; }}
.stay-warning {{ color: var(--bad-text); font-size: 20px; font-weight: 800; text-transform: uppercase; }}
.theme-toggle {{ position: fixed; right: 16px; bottom: 16px; z-index: 10; box-shadow: 0 8px 24px rgb(0 0 0 / .18); }}
#toast {{ min-height: 22px; color: var(--ok-text); }}
@media (max-width: 880px) {{ .grid {{ grid-template-columns: 1fr; }} .log {{ grid-template-columns: 1fr; }} }}
</style>
<script>
(() => {{
  const mode = localStorage.getItem('theme') || 'light';
  document.documentElement.classList.toggle('dark', mode === 'dark');
}})();
</script>
</head>
<body>{body}
<button id="themeToggle" class="secondary theme-toggle" type="button">Dark</button>
<script>
(() => {{
  const button = document.getElementById('themeToggle');
  const sync = () => {{
    const dark = document.documentElement.classList.contains('dark');
    button.textContent = dark ? 'Light' : 'Dark';
  }};
  button.addEventListener('click', () => {{
    const dark = !document.documentElement.classList.contains('dark');
    document.documentElement.classList.toggle('dark', dark);
    localStorage.setItem('theme', dark ? 'dark' : 'light');
    sync();
  }});
  sync();
}})();
</script>
</body>
</html>"""
    return HTMLResponse(
        html,
        headers={
            "Cache-Control": "no-store, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


@app.get("/")
async def index(request: Request) -> HTMLResponse:
    me = trainer_from_cookie(request.cookies.get(TRAINER_COOKIE))
    if not me:
        return render_page("Trainer Login", LOGIN_HTML)
    if me["role"] != "trainer":
        return render_page("Trainer Panel", WRONG_ROLE_HTML.replace("__TARGET__", "/admin").replace("__LABEL__", "Admin dashboard"))
    return render_page("Trainer Panel", TRAINER_HTML.replace("__PROTOCOL__", PROTOCOL_VERSION))


@app.get("/admin")
async def admin_page(request: Request) -> HTMLResponse:
    me = trainer_from_cookie(request.cookies.get(TRAINER_COOKIE))
    if not me:
        return render_page("Admin Login", LOGIN_HTML)
    if me["role"] != "admin":
        return render_page("Admin Dashboard", WRONG_ROLE_HTML.replace("__TARGET__", "/").replace("__LABEL__", "Trainer panel"))
    return render_page("Admin Dashboard", ADMIN_HTML.replace("__PROTOCOL__", PROTOCOL_VERSION))


@app.get("/pet")
async def pet_page() -> HTMLResponse:
    return render_page("Pet Client", PET_HTML.replace("__PROTOCOL__", PROTOCOL_VERSION))


@app.post("/api/login")
async def login(request: Request) -> Response:
    payload = await read_json(request)
    trainer = await store.authenticate_trainer(str(payload.get("username", "")), str(payload.get("password", "")))
    if not trainer:
        raise HTTPException(status_code=401, detail="Bad login")
    response = JSONResponse({"ok": True, "role": trainer["role"]})
    response.set_cookie(
        TRAINER_COOKIE,
        sign(f"trainer|{trainer['username']}|{trainer['role']}|{int(time.time())}"),
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL_SECONDS,
    )
    return response


@app.post("/api/logout")
async def logout() -> Response:
    response = JSONResponse({"ok": True})
    response.delete_cookie(TRAINER_COOKIE)
    return response


@app.post("/api/pet/login")
async def pet_login(request: Request) -> Response:
    payload = await read_json(request)
    pet = await store.get_pet_by_code(str(payload.get("code", "")))
    if not pet:
        raise HTTPException(status_code=401, detail="Bad code")
    response = JSONResponse({"ok": True, "pet": {"id": pet["id"], "name": pet["name"]}})
    response.set_cookie(
        PET_COOKIE,
        sign(f"pet|{pet['id']}|{int(time.time())}"),
        httponly=True,
        samesite="lax",
        max_age=SESSION_TTL_SECONDS,
    )
    return response


@app.get("/api/pet/me")
async def pet_me(request: Request) -> dict[str, Any]:
    pet_id = pet_id_from_cookie(request.cookies.get(PET_COOKIE))
    if pet_id is None:
        raise HTTPException(status_code=401, detail="Not in a pet session")
    pet = await store.get_pet(pet_id)
    if not pet:
        raise HTTPException(status_code=401, detail="Pet session expired")
    return {"ok": True, "pet": {"id": pet["id"], "name": pet["name"]}}


@app.post("/api/pet/logout")
async def pet_logout() -> Response:
    response = JSONResponse({"ok": True})
    response.delete_cookie(PET_COOKIE)
    return response


@app.get("/api/state")
async def api_state(request: Request) -> dict[str, Any]:
    return await hub.state(require_trainer(request))


@app.post("/api/pets")
async def api_add_pet(request: Request) -> dict[str, Any]:
    require_trainer(request)
    payload = await read_json(request)
    pet = await store.add_pet(str(payload.get("name", "")), str(payload.get("code", "")))
    await store.log("pet_added", pet["id"], {"name": pet["name"]})
    await hub.broadcast_trainers()
    return {"ok": True, "pet": pet}


@app.delete("/api/pets/{pet_id}")
async def api_delete_pet(pet_id: int, request: Request) -> dict[str, Any]:
    require_trainer(request)
    await store.delete_pet(pet_id)
    await store.log("pet_removed", pet_id, {})
    await hub.broadcast_trainers()
    return {"ok": True}


@app.post("/api/pets/{pet_id}/code")
async def api_pet_code(pet_id: int, request: Request) -> dict[str, Any]:
    require_trainer(request)
    payload = await read_json(request)
    await store.update_pet_code(pet_id, str(payload.get("code", "")))
    await store.log("pet_code_updated", pet_id, {})
    await hub.broadcast_trainers()
    return {"ok": True}


@app.post("/api/pets/{pet_id}/stay")
async def api_stay(pet_id: int, request: Request) -> dict[str, Any]:
    require_trainer(request)
    payload = await read_json(request)
    duration = payload.get("duration_seconds")
    await hub.set_stay(pet_id, bool(payload.get("enabled")), int(duration) if duration else None)
    return {"ok": True}


@app.post("/api/pets/{pet_id}/random-click")
async def api_random_click(pet_id: int, request: Request) -> dict[str, Any]:
    require_trainer(request)
    payload = await read_json(request)
    await hub.set_random_click(
        pet_id,
        bool(payload.get("enabled")),
        int(payload.get("min_seconds", 30)),
        int(payload.get("max_seconds", 300)),
    )
    return {"ok": True}


@app.post("/api/pets/{pet_id}/click")
async def api_click(pet_id: int, request: Request) -> dict[str, Any]:
    require_trainer(request)
    await hub.manual_click(pet_id)
    return {"ok": True}


@app.post("/api/pets/{pet_id}/kneel")
async def api_kneel(pet_id: int, request: Request) -> dict[str, Any]:
    require_trainer(request)
    payload = await read_json(request)
    await hub.set_kneel(pet_id, bool(payload.get("enabled")))
    return {"ok": True}


@app.post("/api/pets/{pet_id}/breaks")
async def api_breaks(pet_id: int, request: Request) -> dict[str, Any]:
    require_trainer(request)
    payload = await read_json(request)
    await hub.set_breaks(
        pet_id,
        bool(payload.get("enabled")),
        int(payload.get("interval_seconds", 1800)),
        int(payload.get("duration_seconds", 300)),
    )
    return {"ok": True}


@app.post("/api/pets/{pet_id}/bark")
async def api_bark(pet_id: int, request: Request) -> dict[str, Any]:
    require_trainer(request)
    payload = await read_json(request)
    await hub.set_bark(
        pet_id,
        bool(payload.get("enabled")),
        int(payload.get("min_seconds", 30)),
        int(payload.get("max_seconds", 300)),
        int(payload.get("response_seconds", 5)),
        int(payload.get("record_seconds", 10)),
        bool(payload.get("record_enabled")),
    )
    return {"ok": True}


@app.post("/api/pets/{pet_id}/speak")
async def api_speak(pet_id: int, request: Request) -> dict[str, Any]:
    require_trainer(request)
    await hub.trigger_speak(pet_id, "manual")
    return {"ok": True}


@app.post("/api/pets/{pet_id}/live")
async def api_live(pet_id: int, request: Request) -> dict[str, Any]:
    require_trainer(request)
    payload = await read_json(request)
    await hub.set_live_enabled(pet_id, bool(payload.get("enabled")))
    return {"ok": True}


@app.post("/api/trainers")
async def api_add_trainer(request: Request) -> dict[str, Any]:
    require_admin(request)
    payload = await read_json(request)
    await store.add_trainer(str(payload.get("username", "")), str(payload.get("password", "")), str(payload.get("role", "trainer")))
    await store.log("trainer_updated", None, {"username": payload.get("username"), "role": payload.get("role", "trainer")})
    await hub.broadcast_trainers()
    return {"ok": True}


@app.delete("/api/trainers/{username}")
async def api_delete_trainer(username: str, request: Request) -> dict[str, Any]:
    require_admin(request)
    await store.delete_trainer(username)
    await store.log("trainer_removed", None, {"username": username})
    await hub.broadcast_trainers()
    return {"ok": True}


@app.post("/api/logs/clear")
async def api_clear_logs(request: Request) -> dict[str, Any]:
    require_trainer(request)
    await store.clear_logs()
    await hub.broadcast_trainers()
    return {"ok": True}


@app.get("/api/recordings/{recording_id}")
async def api_get_recording(recording_id: int, request: Request) -> FileResponse:
    require_trainer(request)
    recording = await store.get_recording(recording_id)
    if not recording:
        raise HTTPException(status_code=404, detail="Recording not found")
    path = RECORDING_DIR / recording["filename"]
    if not path.exists():
        raise HTTPException(status_code=404, detail="Recording file missing")
    return FileResponse(path, media_type=recording["content_type"], filename=recording["filename"], content_disposition_type="inline")


@app.delete("/api/recordings/{recording_id}")
async def api_delete_recording(recording_id: int, request: Request) -> dict[str, Any]:
    require_trainer(request)
    recording = await store.delete_recording(recording_id)
    if not recording:
        raise HTTPException(status_code=404, detail="Recording not found")
    path = RECORDING_DIR / recording["filename"]
    if path.exists():
        path.unlink()
    await hub.broadcast_trainers()
    return {"ok": True}


@app.get("/healthz")
async def healthz() -> PlainTextResponse:
    return PlainTextResponse("ok")


@app.websocket("/ws/trainer")
async def trainer_ws(websocket: WebSocket) -> None:
    if not trainer_from_cookie(websocket.cookies.get(TRAINER_COOKIE), role="trainer"):
        await websocket.close(code=4403)
        return
    await websocket.accept()
    await hub.register_trainer(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await hub.unregister_trainer(websocket)


@app.websocket("/ws/admin")
async def admin_ws(websocket: WebSocket) -> None:
    if not trainer_from_cookie(websocket.cookies.get(TRAINER_COOKIE), role="admin"):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    await hub.register_trainer(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await hub.unregister_trainer(websocket)


@app.websocket("/ws/pet")
async def pet_ws(websocket: WebSocket) -> None:
    version = websocket.query_params.get("version", "")
    pet_id = pet_id_from_cookie(websocket.cookies.get(PET_COOKIE))
    if pet_id is None:
        await websocket.close(code=4401)
        return
    if not compatible(version):
        await websocket.accept()
        await websocket.send_json({"type": "error", "message": f"Protocol mismatch. Server {PROTOCOL_VERSION}, client {version}."})
        await websocket.close(code=4400)
        return
    pet = await store.get_pet(pet_id)
    if not pet:
        await websocket.close(code=4403)
        return
    await websocket.accept()
    await hub.register_client(websocket, pet_id)
    try:
        while True:
            payload = await websocket.receive_json()
            if payload.get("type") == "presence":
                await hub.update_presence(
                    pet_id,
                    bool(payload.get("present")),
                    payload.get("confidence"),
                    [str(part) for part in payload.get("parts", [])],
                    payload.get("kneeling"),
                )
            elif payload.get("type") == "live_allowed":
                await hub.set_live_allowed(pet_id, bool(payload.get("allowed")))
            elif payload.get("type") == "live_frame":
                await hub.forward_live_frame(pet_id, str(payload.get("frame", "")))
            elif payload.get("type") == "break":
                await hub.set_break_state(pet_id, str(payload.get("state")) == "start")
            elif payload.get("type") == "bark_noise":
                await hub.handle_bark_noise(pet_id, float(payload.get("level", 0)))
            elif payload.get("type") == "bark_recording":
                await hub.save_bark_recording(pet_id, str(payload.get("data_url", "")), int(payload.get("duration_seconds", 0)))
    except WebSocketDisconnect:
        await hub.unregister_client(websocket)


LOGIN_HTML = """
<div class="login">
<form class="panel stack" id="login">
  <h1>Clicker Trainer</h1>
  <div class="field"><label>Username</label><input id="username" autocomplete="username" value="trainer"></div>
  <div class="field"><label>Password</label><input id="password" type="password" autocomplete="current-password" autofocus></div>
  <button>Log in</button>
  <p class="quiet" id="error"></p>
</form>
</div>
<script>
login.addEventListener('submit', async (event) => {
  event.preventDefault();
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({username: username.value, password: password.value})
  });
  if (res.ok) {
    const payload = await res.json();
    location.href = payload.role === 'admin' ? '/admin' : '/';
  }
  else error.textContent = 'Login failed';
});
</script>
"""


WRONG_ROLE_HTML = """
<div class="login">
<main class="panel stack" style="width:min(460px,100%)">
  <h1>Wrong account type</h1>
  <p class="quiet">This account cannot access this page.</p>
  <div class="row">
    <a href="__TARGET__">__LABEL__</a>
    <button id="logout">Log Out</button>
  </div>
</main>
</div>
<script>
logout.onclick = async () => { await fetch('/api/logout', {method: 'POST'}); location.href = '/'; };
</script>
"""


ADMIN_HTML = """
<div class="shell">
  <div class="top">
    <div>
      <h1>Admin Dashboard</h1>
      <div class="quiet">Protocol __PROTOCOL__</div>
    </div>
    <div class="row"><div id="toast"></div><button class="secondary" id="logout">Log Out</button></div>
  </div>
  <main class="panel stack">
    <h2>Trainers</h2>
    <div class="row">
      <input id="trainerName" placeholder="username">
      <input id="trainerPassword" placeholder="password" type="password">
      <select id="trainerRole"><option value="trainer">trainer</option><option value="admin">admin</option></select>
      <button id="addTrainer">Add / Update Trainer</button>
    </div>
    <div id="trainerList" class="list"></div>
  </main>
</div>
<script>
const $ = (id) => document.getElementById(id);
let state = null;
function showToast(text) {
  $('toast').textContent = text;
  clearTimeout(showToast.t);
  showToast.t = setTimeout(() => $('toast').textContent = '', 1600);
}
function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
}
async function post(url, body, button) {
  const old = button ? button.textContent : '';
  if (button) { button.disabled = true; button.classList.add('busy'); button.textContent = 'Saving...'; }
  const res = await fetch(url, {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body || {})});
  if (button) { button.disabled = false; button.classList.remove('busy'); button.textContent = old; }
  if (!res.ok) { alert(await res.text()); return null; }
  showToast('Saved');
  return res.json();
}
async function del(url, button) {
  const old = button ? button.textContent : '';
  if (button) { button.disabled = true; button.textContent = 'Removing...'; }
  const res = await fetch(url, {method: 'DELETE'});
  if (button) { button.disabled = false; button.textContent = old; }
  if (!res.ok) alert(await res.text()); else showToast('Removed');
}
function render(payload) {
  if (payload?.state) state = payload.state;
  $('trainerList').innerHTML = (state?.trainers || []).map((trainer) => `
    <div class="item">
      <strong>${esc(trainer.username)}</strong>
      <span class="quiet">${esc(trainer.role)}</span>
      <button class="danger" onclick="removeTrainer('${esc(trainer.username)}', this)">Remove</button>
    </div>`).join('');
}
window.removeTrainer = (username, button) => del(`/api/trainers/${username}`, button);
$('addTrainer').onclick = (e) => post('/api/trainers', {username: $('trainerName').value, password: $('trainerPassword').value, role: $('trainerRole').value}, e.target);
$('logout').onclick = async () => { await fetch('/api/logout', {method: 'POST'}); location.href = '/'; };
function connectAdminWs() {
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/admin`);
  ws.onmessage = (event) => render(JSON.parse(event.data));
  ws.onclose = () => setTimeout(connectAdminWs, 1500);
}
connectAdminWs();
</script>
"""


TRAINER_HTML = """
<div class="shell">
  <div class="top">
    <div>
      <h1>Clicker Trainer</h1>
      <div class="quiet">Protocol __PROTOCOL__</div>
    </div>
    <div class="row"><div id="toast"></div><button class="secondary" id="logout">Log Out</button></div>
  </div>
  <div class="grid">
    <aside class="panel stack">
      <h2>Pets</h2>
      <div id="petList" class="list"></div>
      <div class="field"><label>Name</label><input id="newPetName" placeholder="Riley"></div>
      <div class="field"><label>Code</label><input id="newPetCode" placeholder="secret-code"></div>
      <button id="addPet">Add Pet</button>
      <div class="field"><label>Pet login link</label><input id="petLink" readonly></div>
      <button class="secondary" id="copyLink">Copy Link</button>
    </aside>
    <main class="stack">
      <section class="panel stack">
        <h2 id="selectedTitle">Select a pet</h2>
        <div class="row">
          <span id="petStatus" class="badge">offline</span>
          <span id="presence" class="badge">unknown</span>
          <span id="kneeling" class="badge">kneel unknown</span>
          <span id="parts" class="quiet"></span>
        </div>
        <div class="toolbar">
          <button id="manualClick">Manual Click</button>
          <button class="secondary" id="liveOn">Live Feed On</button>
          <button class="secondary" id="liveOff">Live Feed Off</button>
        </div>
        <canvas id="liveCanvas" class="live" hidden></canvas>
        <div id="liveState" class="quiet"></div>
      </section>
      <section class="panel stack">
        <h2>Stay In Frame</h2>
        <div class="toolbar">
          <button id="stayOn">Turn On</button>
          <button class="secondary" id="stayOff">Turn Off</button>
        </div>
        <div class="row">
          <div class="field"><label>Auto-off seconds</label><input id="stayDuration" type="number" min="0" step="1" value="600"></div>
          <span class="quiet">0 means no timer.</span>
        </div>
        <div id="stayState" class="quiet"></div>
      </section>
      <section class="panel stack">
        <h2>Kneel Check</h2>
        <div class="toolbar">
          <button id="kneelOn">Turn On</button>
          <button class="secondary" id="kneelOff">Turn Off</button>
        </div>
        <div id="kneelState" class="quiet"></div>
      </section>
      <section class="panel stack">
        <h2>Breaks</h2>
        <div class="toolbar">
          <button id="breakOn">Enable</button>
          <button class="secondary" id="breakOff">Disable</button>
        </div>
        <div class="row">
          <div class="field"><label>Every seconds</label><input id="breakInterval" type="number" min="60" step="1" value="1800"></div>
          <div class="field"><label>Break seconds</label><input id="breakDuration" type="number" min="30" step="1" value="300"></div>
        </div>
        <div id="breakState" class="quiet"></div>
      </section>
      <section class="panel stack">
        <h2>Random Clicks</h2>
        <div class="toolbar">
          <button id="randomOn">Enable</button>
          <button class="secondary" id="randomOff">Disable</button>
        </div>
        <div class="row">
          <div class="field"><label>Min seconds</label><input id="clickMin" type="number" min="1" max="6000" step="1" value="30"></div>
          <div class="field"><label>Max seconds</label><input id="clickMax" type="number" min="1" max="6000" step="1" value="300"></div>
        </div>
        <div id="randomState" class="quiet"></div>
      </section>
      <section class="panel stack">
        <h2>Bark Check</h2>
        <div class="toolbar">
          <button id="manualSpeak">Manual Speak</button>
          <button id="barkOn">Enable</button>
          <button class="secondary" id="barkOff">Disable</button>
        </div>
        <div class="row">
          <div class="field"><label>Min seconds</label><input id="barkMin" type="number" min="1" max="6000" step="1" value="30"></div>
          <div class="field"><label>Max seconds</label><input id="barkMax" type="number" min="1" max="6000" step="1" value="300"></div>
          <div class="field"><label>Response seconds</label><input id="barkResponse" type="number" min="1" max="60" step="1" value="5"></div>
          <div class="field"><label>Record seconds</label><input id="barkRecordSeconds" type="number" min="1" max="60" step="1" value="10"></div>
        </div>
        <label class="row"><input id="barkRecordEnabled" type="checkbox"> Save bark recordings</label>
        <div id="barkState" class="quiet"></div>
      </section>
      <section class="panel stack">
        <h2>Bark Recordings</h2>
        <div id="recordings" class="list"></div>
      </section>
      <section class="panel stack">
        <div class="row" style="justify-content:space-between">
          <h2>Event Log</h2>
          <button class="danger" id="clearLogs">Clear Logs</button>
        </div>
        <div class="logs" id="logs"></div>
      </section>
    </main>
  </div>
</div>
<script>
const $ = (id) => document.getElementById(id);
const CLICK_MIN_SECONDS = 1;
const CLICK_MAX_SECONDS = 6000;
let state = null;
let logs = [];
let recordings = [];
let selectedPetId = null;
let liveFramePetId = null;
let clickRangeDirty = false;
let clickRangePetId = null;

function showToast(text) {
  $('toast').textContent = text;
  clearTimeout(showToast.t);
  showToast.t = setTimeout(() => $('toast').textContent = '', 1600);
}

async function post(url, body, button) {
  const old = button ? button.textContent : '';
  if (button) { button.disabled = true; button.classList.add('busy'); button.textContent = 'Saving...'; }
  const res = await fetch(url, {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body || {})});
  if (button) { button.disabled = false; button.classList.remove('busy'); button.textContent = old; }
  if (!res.ok) { alert(await res.text()); return null; }
  showToast('Saved');
  return res.json();
}

async function del(url, button) {
  const old = button ? button.textContent : '';
  if (button) { button.disabled = true; button.textContent = 'Removing...'; }
  const res = await fetch(url, {method: 'DELETE'});
  if (button) { button.disabled = false; button.textContent = old; }
  if (!res.ok) alert(await res.text()); else showToast('Removed');
}

async function deleteRecording(id, button) {
  await del(`/api/recordings/${id}`, button);
}

function badge(text, cls='') { return `<span class="badge ${cls}">${text}</span>`; }
function setBadge(id, text, cls='') {
  const el = $(id);
  el.className = `badge ${cls}`;
  el.textContent = text;
}
function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
}
function selectedPet() { return state?.pets.find((pet) => pet.id === selectedPetId) || state?.pets[0]; }

function clampClickSeconds(value, fallback) {
  const parsed = Number(value);
  const seconds = Number.isFinite(parsed) ? parsed : fallback;
  return Math.min(CLICK_MAX_SECONDS, Math.max(CLICK_MIN_SECONDS, Math.round(seconds)));
}

function normalizeClickInputs(changed = 'min') {
  const pet = selectedPet();
  let minSeconds = clampClickSeconds($('clickMin').value, pet?.click_min_seconds ?? 30);
  let maxSeconds = clampClickSeconds($('clickMax').value, pet?.click_max_seconds ?? 300);
  if (changed === 'max' && maxSeconds < minSeconds) minSeconds = maxSeconds;
  else if (minSeconds > maxSeconds) maxSeconds = minSeconds;
  $('clickMin').value = minSeconds;
  $('clickMax').value = maxSeconds;
  return {min_seconds: minSeconds, max_seconds: maxSeconds};
}

function currentClickRange() {
  return normalizeClickInputs(document.activeElement === $('clickMax') ? 'max' : 'min');
}

function clampSeconds(value, fallback, min, max) {
  const parsed = Number(value);
  const seconds = Number.isFinite(parsed) ? parsed : fallback;
  return Math.min(max, Math.max(min, Math.round(seconds)));
}

function markClickRangeDirty(changed) {
  clickRangeDirty = true;
  clickRangePetId = selectedPet()?.id ?? null;
  normalizeClickInputs(changed);
}

function syncClickRangeInputs(pet) {
  if (clickRangePetId !== pet.id) {
    clickRangeDirty = false;
    clickRangePetId = pet.id;
  }
  if (clickRangeDirty) return;
  $('clickMin').value = pet.click_min_seconds;
  $('clickMax').value = pet.click_max_seconds;
}

async function saveRandomClick(enabled, button) {
  const pet = selectedPet();
  const range = currentClickRange();
  const result = await post(`/api/pets/${pet.id}/random-click`, {enabled, ...range}, button);
  if (result) {
    clickRangeDirty = false;
    clickRangePetId = pet.id;
  }
}

function clearLiveCanvas() {
  const liveCanvas = $('liveCanvas');
  const liveContext = liveCanvas.getContext('2d');
  liveContext.clearRect(0, 0, liveCanvas.width, liveCanvas.height);
  liveCanvas.hidden = true;
  liveFramePetId = null;
}

function renderPets() {
  const pets = state.pets;
  if (!selectedPetId && pets.length) selectedPetId = pets[0].id;
  if (!pets.some((pet) => pet.id === selectedPetId)) {
    selectedPetId = pets[0]?.id || null;
    clearLiveCanvas();
  }
  $('petList').innerHTML = pets.map((pet) => `
    <div class="item ${pet.id === selectedPetId ? 'active' : ''}">
      <strong>${esc(pet.name)}</strong>
      <span class="quiet">code: ${esc(pet.code)}</span>
      <span>${pet.connected ? badge(`${pet.clients} online`, 'ok') : badge('offline', 'bad')}</span>
      <div class="row">
        <button class="secondary" onclick="selectPet(${pet.id})">Select</button>
        <button class="secondary" onclick="changeCode(${pet.id})">Change Code</button>
        <button class="danger" onclick="removePet(${pet.id}, this)">Remove</button>
      </div>
    </div>`).join('');
  $('petLink').value = new URL(state.pet_link, location.href).href;
}

function renderSelected() {
  const pet = selectedPet();
  const disabled = !pet;
  for (const id of ['manualClick','liveOn','liveOff','stayOn','stayOff','kneelOn','kneelOff','breakOn','breakOff','randomOn','randomOff','manualSpeak','barkOn','barkOff']) $(id).disabled = disabled;
  if (!pet) return;
  $('selectedTitle').textContent = pet.name;
  if (pet.connected) setBadge('petStatus', `${pet.clients} connected`, 'ok'); else setBadge('petStatus', 'offline', 'bad');
  if (pet.presence === true) setBadge('presence', 'in frame', 'ok');
  else if (pet.presence === false) setBadge('presence', 'out of frame', 'bad');
  else setBadge('presence', 'unknown');
  if (pet.kneeling === true) setBadge('kneeling', 'kneeling', 'ok');
  else if (pet.kneeling === false) setBadge('kneeling', 'not kneeling', pet.kneel_enabled ? 'bad' : '');
  else setBadge('kneeling', 'kneel unknown');
  $('parts').textContent = pet.parts?.length ? `Detected: ${pet.parts.join(', ')}` : 'No parts detected yet';
  $('stayState').textContent = pet.stay_enabled
    ? `On${pet.stay_seconds_remaining === null ? '' : `, ${pet.stay_seconds_remaining}s remaining`}`
    : 'Off';
  $('randomState').textContent = pet.random_enabled ? `Enabled, ${pet.click_min_seconds}-${pet.click_max_seconds}s` : 'Disabled';
  syncClickRangeInputs(pet);
  $('kneelState').textContent = pet.kneel_enabled ? 'On' : 'Off';
  $('breakInterval').value = pet.break_interval_seconds;
  $('breakDuration').value = pet.break_duration_seconds;
  if (pet.break_overdue) $('breakState').textContent = 'Break overdue';
  else if (pet.break_until) $('breakState').textContent = `On break until ${new Date(pet.break_until * 1000).toLocaleTimeString()}`;
  else if (pet.break_due_at) $('breakState').textContent = `Next break around ${new Date(pet.break_due_at * 1000).toLocaleTimeString()}`;
  else $('breakState').textContent = pet.break_enabled ? 'Enabled' : 'Disabled';
  $('barkMin').value = pet.bark_min_seconds;
  $('barkMax').value = pet.bark_max_seconds;
  $('barkResponse').value = pet.bark_response_seconds;
  $('barkRecordSeconds').value = pet.bark_record_seconds;
  $('barkRecordEnabled').checked = pet.bark_record_enabled;
  $('barkState').textContent = pet.bark_enabled
    ? `Enabled, ${pet.bark_min_seconds}-${pet.bark_max_seconds}s, ${pet.bark_response_seconds}s response`
    : 'Disabled';
  $('liveState').textContent = pet.live_allowed
    ? (pet.live_enabled ? 'Client allowed live feed; trainer view is on.' : 'Client allowed live feed; trainer view is off.')
    : 'Client has not allowed live feed.';
  if (!pet.live_allowed || !pet.live_enabled || liveFramePetId !== pet.id) clearLiveCanvas();
}

function renderRecordings() {
  $('recordings').innerHTML = recordings.map((recording) => `
    <div class="item">
      <strong>${esc(recording.pet_name || 'Pet')}</strong>
      <span class="quiet">${esc(recording.created_at)} - ${Math.round((recording.size_bytes || 0) / 1024)} KB</span>
      <audio controls src="/api/recordings/${recording.id}"></audio>
      <div class="row">
        <a href="/api/recordings/${recording.id}" download>Download</a>
        <button class="danger" onclick="deleteRecording(${recording.id}, this)">Delete</button>
      </div>
    </div>`).join('') || '<div class="quiet">No bark recordings yet.</div>';
}

function renderLogs() {
  const logBox = $('logs');
  const wasNearBottom = logBox.scrollTop + logBox.clientHeight >= logBox.scrollHeight - 24;
  $('logs').innerHTML = logs.map((log) => `
    <div class="log">
      <span class="time">${log.created_at}</span>
      <span>${esc(log.pet_name || '')}</span>
      <strong>${esc(log.event.replaceAll('_', ' '))}</strong>
    </div>`).join('');
  if (wasNearBottom) logBox.scrollTop = logBox.scrollHeight;
}

function render(payload) {
  if (payload?.state) state = payload.state;
  if (payload?.logs) logs = payload.logs;
  if (payload?.state?.recordings) recordings = payload.state.recordings;
  renderPets();
  renderSelected();
  renderRecordings();
  renderLogs();
}

async function copyTextFromInput(input) {
  const text = input.value;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (error) {
    console.warn('Clipboard API failed, trying fallback', error);
  }
  input.focus();
  input.select();
  input.setSelectionRange(0, text.length);
  try {
    const copied = document.execCommand('copy');
    input.blur();
    return copied;
  } catch (error) {
    console.warn('Fallback copy failed', error);
    input.blur();
    return false;
  }
}

window.selectPet = (id) => { selectedPetId = id; clickRangeDirty = false; clickRangePetId = id; clearLiveCanvas(); render({state, logs}); };
window.changeCode = async (id) => {
  const code = prompt('New code');
  if (code) await post(`/api/pets/${id}/code`, {code});
};
window.removePet = (id, button) => del(`/api/pets/${id}`, button);
window.deleteRecording = deleteRecording;

$('addPet').onclick = (e) => post('/api/pets', {name: $('newPetName').value, code: $('newPetCode').value}, e.target);
$('manualClick').onclick = (e) => post(`/api/pets/${selectedPet().id}/click`, {}, e.target);
$('liveOn').onclick = (e) => { clearLiveCanvas(); post(`/api/pets/${selectedPet().id}/live`, {enabled: true}, e.target); };
$('liveOff').onclick = (e) => { clearLiveCanvas(); post(`/api/pets/${selectedPet().id}/live`, {enabled: false}, e.target); };
$('stayOn').onclick = (e) => post(`/api/pets/${selectedPet().id}/stay`, {enabled: true, duration_seconds: Number($('stayDuration').value || 0) || null}, e.target);
$('stayOff').onclick = (e) => post(`/api/pets/${selectedPet().id}/stay`, {enabled: false}, e.target);
$('kneelOn').onclick = (e) => post(`/api/pets/${selectedPet().id}/kneel`, {enabled: true}, e.target);
$('kneelOff').onclick = (e) => post(`/api/pets/${selectedPet().id}/kneel`, {enabled: false}, e.target);
$('breakOn').onclick = (e) => post(`/api/pets/${selectedPet().id}/breaks`, {
  enabled: true,
  interval_seconds: clampSeconds($('breakInterval').value, 1800, 60, 86400),
  duration_seconds: clampSeconds($('breakDuration').value, 300, 30, 3600)
}, e.target);
$('breakOff').onclick = (e) => post(`/api/pets/${selectedPet().id}/breaks`, {
  enabled: false,
  interval_seconds: clampSeconds($('breakInterval').value, 1800, 60, 86400),
  duration_seconds: clampSeconds($('breakDuration').value, 300, 30, 3600)
}, e.target);
$('clickMin').oninput = () => markClickRangeDirty('min');
$('clickMax').oninput = () => markClickRangeDirty('max');
$('clickMin').onchange = () => markClickRangeDirty('min');
$('clickMax').onchange = () => markClickRangeDirty('max');
$('randomOn').onclick = (e) => saveRandomClick(true, e.target);
$('randomOff').onclick = (e) => saveRandomClick(false, e.target);
$('manualSpeak').onclick = (e) => post(`/api/pets/${selectedPet().id}/speak`, {}, e.target);
$('barkOn').onclick = (e) => post(`/api/pets/${selectedPet().id}/bark`, {
  enabled: true,
  min_seconds: clampSeconds($('barkMin').value, 30, 1, 6000),
  max_seconds: clampSeconds($('barkMax').value, 300, 1, 6000),
  response_seconds: clampSeconds($('barkResponse').value, 5, 1, 60),
  record_seconds: clampSeconds($('barkRecordSeconds').value, 10, 1, 60),
  record_enabled: $('barkRecordEnabled').checked
}, e.target);
$('barkOff').onclick = (e) => post(`/api/pets/${selectedPet().id}/bark`, {
  enabled: false,
  min_seconds: clampSeconds($('barkMin').value, 30, 1, 6000),
  max_seconds: clampSeconds($('barkMax').value, 300, 1, 6000),
  response_seconds: clampSeconds($('barkResponse').value, 5, 1, 60),
  record_seconds: clampSeconds($('barkRecordSeconds').value, 10, 1, 60),
  record_enabled: $('barkRecordEnabled').checked
}, e.target);
$('copyLink').onclick = async () => { showToast(await copyTextFromInput($('petLink')) ? 'Copied' : 'Copy failed'); };
$('logout').onclick = async () => { await fetch('/api/logout', {method: 'POST'}); location.href = '/'; };
$('clearLogs').onclick = (e) => { if (confirm('Clear all event logs?')) post('/api/logs/clear', {}, e.target); };

function connectTrainerWs() {
  const liveCanvas = $('liveCanvas');
  const liveContext = liveCanvas.getContext('2d');
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/trainer`);
  ws.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    if (payload.type === 'live_frame' && selectedPetId === payload.pet_id) {
      const image = new Image();
      image.onload = () => {
        liveCanvas.width = image.naturalWidth;
        liveCanvas.height = image.naturalHeight;
        liveContext.drawImage(image, 0, 0);
        liveFramePetId = payload.pet_id;
        liveCanvas.hidden = false;
      };
      image.src = payload.frame;
    }
    else render(payload);
  };
  ws.onclose = () => setTimeout(connectTrainerWs, 1500);
}
connectTrainerWs();
</script>
"""


PET_HTML = """
<div class="pet">
<main class="panel stack">
  <section id="codePanel" class="stack">
    <h1>Training Client</h1>
    <p class="quiet">Enter the code your trainer gave you.</p>
    <div class="field"><label>Code</label><input id="petCode" autocomplete="one-time-code" autofocus></div>
    <button id="loginPet">Continue</button>
    <p class="quiet" id="loginError"></p>
  </section>
  <section id="clientPanel" class="stack" hidden>
    <div class="row" style="justify-content:space-between">
      <h1 id="petName">Training Client</h1>
      <button id="leavePet" class="secondary" type="button">Leave Session</button>
    </div>
    <video id="video" class="camera" playsinline muted></video>
    <div class="row">
      <span id="status" class="badge">Starting</span>
      <span id="stayWarning" class="stay-warning" hidden>Stay in frame</span>
      <span id="kneelWarning" class="stay-warning" hidden>Kneel</span>
    </div>
    <ol id="loadSteps" class="quiet" style="margin:0;padding-left:22px" hidden>
      <li id="stepCamera">Camera permission</li>
      <li id="stepJs">MediaPipe JS</li>
      <li id="stepWasm">MediaPipe WASM</li>
      <li id="stepModel">Pose model</li>
      <li id="stepDetect">Detection loop</li>
    </ol>
    <p id="clientMessage" class="quiet" hidden></p>
    <div class="row">
      <label class="row"><input id="allowLive" type="checkbox"> Allow trainer live feed</label>
      <label class="row"><input id="censorFaces" type="checkbox" checked> Censor faces</label>
      <button id="breakButton" class="secondary" type="button" hidden>Start Break</button>
      <span id="breakStatus" class="quiet"></span>
    </div>
  </section>
  <canvas id="canvas" hidden></canvas>
</main>
</div>
<script>
const PROTOCOL_VERSION = "__PROTOCOL__";
const codePanel = document.getElementById('codePanel');
const clientPanel = document.getElementById('clientPanel');
const petCode = document.getElementById('petCode');
const loginPet = document.getElementById('loginPet');
const loginError = document.getElementById('loginError');
const petName = document.getElementById('petName');
const leavePet = document.getElementById('leavePet');
const video = document.getElementById('video');
const status = document.getElementById('status');
const stayWarning = document.getElementById('stayWarning');
const kneelWarning = document.getElementById('kneelWarning');
const clientMessage = document.getElementById('clientMessage');
const allowLive = document.getElementById('allowLive');
const censorFaces = document.getElementById('censorFaces');
const breakButton = document.getElementById('breakButton');
const breakStatus = document.getElementById('breakStatus');
const canvas = document.getElementById('canvas');
const loadSteps = document.getElementById('loadSteps');
const loadStepIds = ['stepCamera', 'stepJs', 'stepWasm', 'stepModel', 'stepDetect'];
let ws = null;
let poseLandmarker = null;
let faceDetector = null;
let stayEnabled = false;
let kneelEnabled = false;
let lastKneeling = null;
let breakEnabled = false;
let breakActive = false;
let breakOverdue = false;
let breakUntil = null;
let barkPendingUntil = 0;
let barkRecordSeconds = 10;
let barkRecordEnabled = false;
let audioAnalyser = null;
let audioData = null;
let audioNoiseBaseline = 0.02;
let mediaRecorder = null;
let lastPresent = null;
let lastParts = '';
let lastSent = 0;
let running = false;
let liveRequested = false;
let lastLiveAt = 0;
let liveTimer = null;
let cameraStream = null;
let intentionalDisconnect = false;
let audioContext = null;
let audioStartPromise = null;
let audioReady = false;
let audioRetryArmed = false;
let beepBuffer = null;
let clickBuffer = null;
let beepSource = null;

function setStatus(text, cls = '') {
  status.className = `badge ${cls}`;
  status.textContent = text;
}

function setMessage(text = '') {
  clientMessage.textContent = text;
  clientMessage.hidden = !text;
}

function logAudio(message, extra = undefined) {
  if (extra === undefined) console.info(`[audio] ${message}`);
  else console.info(`[audio] ${message}`, extra);
}

function armAudioRetry() {
  if (audioRetryArmed) return;
  audioRetryArmed = true;
  const retry = () => {
    document.removeEventListener('pointerdown', retry);
    document.removeEventListener('keydown', retry);
    audioRetryArmed = false;
    ensureAudioStarted().then(() => updateBeep());
  };
  document.addEventListener('pointerdown', retry, {once: true});
  document.addEventListener('keydown', retry, {once: true});
}

async function fetchAudioBuffer(name) {
  const url = `/audio/${name}.mp3`;
  logAudio(`fetching ${url}`);
  const response = await fetch(url, {cache: 'reload'});
  if (!response.ok) throw new Error(`${url} returned HTTP ${response.status}`);
  const buffer = await response.arrayBuffer();
  if (!buffer.byteLength) throw new Error(`${url} was empty`);
  return await audioContext.decodeAudioData(buffer);
}

async function ensureAudioStarted() {
  if (audioReady) return true;
  if (audioStartPromise) return audioStartPromise;
  audioStartPromise = (async () => {
    const AudioContextClass = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextClass) throw new Error('Web Audio is not supported in this browser');
    audioContext = audioContext || new AudioContextClass();
    await audioContext.resume();
    logAudio(`context state after resume: ${audioContext.state}`);
    const debugPromise = fetch('/api/audio/debug')
      .then((response) => response.ok ? response.json() : {ok: false, status: response.status})
      .catch((error) => ({error: String(error)}));
    const [debug, decodedBeep, decodedClick] = await Promise.all([
      debugPromise,
      fetchAudioBuffer('beep'),
      fetchAudioBuffer('click'),
    ]);
    logAudio('server debug', debug);
    beepBuffer = decodedBeep;
    clickBuffer = decodedClick;
    audioReady = true;
    return true;
  })().catch((error) => {
    audioStartPromise = null;
    audioReady = false;
    console.error('[audio] startup failed', error);
    setMessage(`Audio failed: ${error?.message || error}`);
    armAudioRetry();
    return false;
  });
  return audioStartPromise;
}

async function playClick() {
  if (!await ensureAudioStarted()) return;
  if (audioContext.state !== 'running') await audioContext.resume();
  if (audioContext.state !== 'running') {
    setMessage('Audio is blocked until this page is clicked or tapped once.');
    armAudioRetry();
    return;
  }
  const source = audioContext.createBufferSource();
  source.buffer = clickBuffer;
  source.connect(audioContext.destination);
  source.start();
}

async function startBeep() {
  if (beepSource) return;
  if (!await ensureAudioStarted()) return;
  if (audioContext.state !== 'running') await audioContext.resume();
  if (audioContext.state !== 'running') {
    setMessage('Audio is blocked until this page is clicked or tapped once.');
    armAudioRetry();
    return;
  }
  beepSource = audioContext.createBufferSource();
  beepSource.buffer = beepBuffer;
  beepSource.loop = true;
  beepSource.connect(audioContext.destination);
  beepSource.onended = () => {
    beepSource = null;
  };
  beepSource.start();
}

function stopBeep() {
  if (!beepSource) return;
  const source = beepSource;
  beepSource = null;
  try {
    source.stop();
  } catch (_) {}
  source.disconnect();
}

function speakText(text) {
  if (!('speechSynthesis' in window)) return;
  const utterance = new SpeechSynthesisUtterance(text);
  utterance.rate = 1;
  utterance.pitch = 1;
  speechSynthesis.speak(utterance);
}

function initNoiseDetection(stream) {
  if (!audioContext) return;
  const audioTracks = stream.getAudioTracks();
  if (!audioTracks.length) return;
  const source = audioContext.createMediaStreamSource(new MediaStream(audioTracks));
  audioAnalyser = audioContext.createAnalyser();
  audioAnalyser.fftSize = 1024;
  audioData = new Uint8Array(audioAnalyser.fftSize);
  source.connect(audioAnalyser);
}

function currentNoiseLevel() {
  if (!audioAnalyser || !audioData) return 0;
  audioAnalyser.getByteTimeDomainData(audioData);
  let sum = 0;
  for (const value of audioData) {
    const centered = (value - 128) / 128;
    sum += centered * centered;
  }
  return Math.sqrt(sum / audioData.length);
}

function watchForBark(until) {
  const tick = () => {
    if (performance.now() > until || !ws || ws.readyState !== WebSocket.OPEN) return;
    const level = currentNoiseLevel();
    audioNoiseBaseline = audioNoiseBaseline * 0.97 + level * 0.03;
    if (level > Math.max(0.08, audioNoiseBaseline * 3.5)) {
      ws.send(JSON.stringify({type: 'bark_noise', level}));
      return;
    }
    requestAnimationFrame(tick);
  };
  tick();
}

function startBarkRecording(seconds) {
  if (!cameraStream || !cameraStream.getAudioTracks().length || !window.MediaRecorder) return;
  const stream = new MediaStream(cameraStream.getAudioTracks());
  const chunks = [];
  mediaRecorder = new MediaRecorder(stream);
  mediaRecorder.ondataavailable = (event) => {
    if (event.data.size) chunks.push(event.data);
  };
  mediaRecorder.onstop = () => {
    const blob = new Blob(chunks, {type: mediaRecorder.mimeType || 'audio/webm'});
    const reader = new FileReader();
    reader.onload = () => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({type: 'bark_recording', data_url: reader.result, duration_seconds: seconds}));
      }
    };
    reader.readAsDataURL(blob);
  };
  mediaRecorder.start();
  setTimeout(() => {
    if (mediaRecorder?.state === 'recording') mediaRecorder.stop();
  }, seconds * 1000);
}

async function handleSpeak(message) {
  speakText('Speak!');
  barkPendingUntil = performance.now() + Number(message.response_seconds || 5) * 1000;
  barkRecordSeconds = Number(message.record_seconds || 10);
  barkRecordEnabled = Boolean(message.record_enabled);
  if (barkRecordEnabled) startBarkRecording(barkRecordSeconds);
  watchForBark(barkPendingUntil);
}

function setStep(id, state) {
  const item = document.getElementById(id);
  if (!item) return;
  const prefix = state === 'done' ? '[done] ' : state === 'active' ? '[...] ' : state === 'error' ? '[error] ' : '';
  item.dataset.state = state;
  item.textContent = prefix + item.textContent.replace(/^\\[(done|\\.\\.\\.|error)\\] /, '');
  item.style.color = state === 'done' ? 'var(--ok-text)' : state === 'error' ? 'var(--bad-text)' : '';
}

function resetSteps() {
  loadSteps.hidden = false;
  for (const id of loadStepIds) setStep(id, 'idle');
}

async function beginPetSession(pet, audioStart = null) {
  intentionalDisconnect = false;
  petName.textContent = pet.name;
  codePanel.hidden = true;
  clientPanel.hidden = false;
  resetSteps();
  await startClient(audioStart);
}

async function submitPetCode() {
  const audioStart = ensureAudioStarted();
  loginPet.disabled = true;
  loginPet.textContent = 'Checking...';
  loginError.textContent = '';
  const res = await fetch('/api/pet/login', {
    method: 'POST',
    headers: {'content-type': 'application/json'},
    body: JSON.stringify({code: petCode.value})
  });
  loginPet.disabled = false;
  loginPet.textContent = 'Continue';
  if (!res.ok) {
    loginError.textContent = 'Bad code';
    return;
  }
  const payload = await res.json();
  beginPetSession(payload.pet, audioStart).catch((error) => {
    console.error(error);
    for (const id of loadStepIds) {
      const item = document.getElementById(id);
      if (item?.dataset.state === 'active') setStep(id, 'error');
    }
    setStatus('Camera/model failed', 'bad');
    setMessage(error?.message || 'Startup failed');
    running = false;
  });
}

loginPet.onclick = () => submitPetCode();
petCode.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') submitPetCode();
});

leavePet.onclick = async () => {
  intentionalDisconnect = true;
  await fetch('/api/pet/logout', {method: 'POST'});
  if (ws) ws.close();
  if (liveTimer) clearInterval(liveTimer);
  if (cameraStream) cameraStream.getTracks().forEach((track) => track.stop());
  ws = null;
  liveTimer = null;
  cameraStream = null;
  poseLandmarker = null;
  faceDetector = null;
  running = false;
  lastPresent = null;
  lastParts = '';
  stayEnabled = false;
  kneelEnabled = false;
  lastKneeling = null;
  breakEnabled = false;
  breakActive = false;
  breakOverdue = false;
  if (mediaRecorder?.state === 'recording') mediaRecorder.stop();
  stopBeep();
  stayWarning.hidden = true;
  kneelWarning.hidden = true;
  breakButton.hidden = true;
  breakStatus.textContent = '';
  clientPanel.hidden = true;
  codePanel.hidden = false;
  petCode.value = '';
  loginPet.disabled = false;
  loginPet.textContent = 'Continue';
  petCode.focus();
};

allowLive.onchange = () => {
  if (allowLive.checked && !confirm('Allow your trainer to request a live camera feed?')) {
    allowLive.checked = false;
  }
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({type: 'live_allowed', allowed: allowLive.checked}));
  }
};

breakButton.onclick = () => {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  ws.send(JSON.stringify({type: 'break', state: breakActive ? 'stop' : 'start'}));
};

function connectWs() {
  ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/pet?version=${encodeURIComponent(PROTOCOL_VERSION)}`);
  ws.onopen = () => {
    ws.send(JSON.stringify({type: 'live_allowed', allowed: allowLive.checked}));
  };
  ws.onclose = () => {
    setStatus('Reconnecting');
    if (!intentionalDisconnect) setTimeout(connectWs, 1500);
  };
  ws.onmessage = async (event) => {
    const message = JSON.parse(event.data);
    if (message.type === 'settings') {
      stayEnabled = Boolean(message.settings.stay_in_frame_enabled);
      kneelEnabled = Boolean(message.settings.kneel_enabled);
      breakEnabled = Boolean(message.settings.break_enabled);
      breakUntil = message.settings.break_until || null;
      breakActive = Boolean(breakUntil);
      breakOverdue = Boolean(message.settings.break_overdue);
      stayWarning.hidden = !stayEnabled;
      kneelWarning.hidden = !kneelEnabled;
      breakButton.hidden = !breakEnabled;
      breakButton.textContent = breakActive ? 'End Break' : 'Start Break';
      breakStatus.textContent = breakOverdue ? 'Break overdue' : breakActive ? 'On break' : '';
      await updateBeep();
    }
    if (message.type === 'play_click') {
      await playClick();
    }
    if (message.type === 'speak') {
      await handleSpeak(message);
    }
    if (message.type === 'live_request') {
      liveRequested = Boolean(message.enabled);
    }
    if (message.type === 'error') setStatus(message.message, 'bad');
  };
}

async function updateBeep(present) {
  const shouldBeep = (stayEnabled && lastPresent === false) || (kneelEnabled && lastPresent === true && lastKneeling === false) || breakOverdue;
  if (shouldBeep) {
    await startBeep();
  } else {
    stopBeep();
  }
}

function classifyParts(landmarks) {
  const visible = (indexes) => indexes.some((i) => landmarks[i] && (landmarks[i].visibility ?? 1) > 0.35);
  const visibleCount = landmarks.filter((point) => (point.visibility ?? 1) > 0.35).length;
  const parts = [];
  if (visible([0, 1, 2, 3, 4, 5, 6, 7, 8])) parts.push('head/profile');
  if (visible([11, 12])) parts.push('shoulders');
  if (visible([11, 12, 23, 24])) parts.push('torso');
  if (visible([13, 14, 15, 16])) parts.push('arms/hands');
  if (visible([23, 24])) parts.push('hips');
  if (visible([25, 26, 27, 28, 29, 30, 31, 32])) parts.push('legs/feet');
  if (!parts.length && visibleCount > 0) parts.push('body part');
  return parts;
}

function landmarkVisible(point) {
  return point && (point.visibility ?? 1) > 0.35;
}

function angleDegrees(a, b, c) {
  const ab = {x: a.x - b.x, y: a.y - b.y};
  const cb = {x: c.x - b.x, y: c.y - b.y};
  const dot = ab.x * cb.x + ab.y * cb.y;
  const mag = Math.hypot(ab.x, ab.y) * Math.hypot(cb.x, cb.y);
  if (!mag) return 180;
  return Math.acos(Math.max(-1, Math.min(1, dot / mag))) * 180 / Math.PI;
}

function detectKneeling(landmarks) {
  const leftReady = landmarkVisible(landmarks[23]) && landmarkVisible(landmarks[25]) && landmarkVisible(landmarks[27]);
  const rightReady = landmarkVisible(landmarks[24]) && landmarkVisible(landmarks[26]) && landmarkVisible(landmarks[28]);
  const bent = [];
  if (leftReady) bent.push(angleDegrees(landmarks[23], landmarks[25], landmarks[27]) < 135);
  if (rightReady) bent.push(angleDegrees(landmarks[24], landmarks[26], landmarks[28]) < 135);
  if (!bent.length) return null;
  return bent.some(Boolean);
}

async function analyze(result) {
  if (!result.landmarks || !result.landmarks.length) {
    if (faceDetector) {
      try {
        const faces = await faceDetector.detect(video);
        if (faces.length) return {present: true, confidence: 0.75, parts: ['head/profile'], kneeling: null};
      } catch (_) {}
    }
    return {present: false, confidence: 0, parts: [], kneeling: null};
  }
  const landmarks = result.landmarks[0];
  const visibleCount = landmarks.filter((point) => (point.visibility ?? 1) > 0.35).length;
  const parts = classifyParts(landmarks);
  return {present: parts.length > 0 || visibleCount >= 2, confidence: Math.min(1, visibleCount / 12), parts, kneeling: detectKneeling(landmarks)};
}

let absentCandidateAt = null;

async function sendPresence(rawPresent, confidence, parts, kneeling) {
  const now = performance.now();
  let present = rawPresent;
  if (!rawPresent) {
    if (absentCandidateAt === null) absentCandidateAt = now;
    if (now - absentCandidateAt < 2000) present = lastPresent !== null ? lastPresent : true;
  } else {
    absentCandidateAt = null;
  }
  const partsText = parts.join(', ');
  setStatus(present ? 'In frame' : 'Out of frame', present ? 'ok' : 'bad');
  kneelWarning.hidden = !kneelEnabled || kneeling === true;
  if (present === lastPresent && partsText === lastParts && kneeling === lastKneeling && now - lastSent < 5000) return;
  lastPresent = present;
  lastKneeling = kneeling;
  lastParts = partsText;
  lastSent = now;
  await updateBeep();
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({type: 'presence', present, confidence, parts, kneeling}));
  }
}

async function initPose() {
  setStatus('Loading MediaPipe JS');
  setStep('stepJs', 'active');
  const mediaPipe = await import("https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.19/vision_bundle.mjs");
  setStep('stepJs', 'done');
  setStatus('Loading MediaPipe WASM');
  setStep('stepWasm', 'active');
  const vision = await mediaPipe.FilesetResolver.forVisionTasks("https://cdn.jsdelivr.net/npm/@mediapipe/tasks-vision@0.10.19/wasm");
  setStep('stepWasm', 'done');
  setStatus('Loading pose model');
  setStep('stepModel', 'active');
  poseLandmarker = await mediaPipe.PoseLandmarker.createFromOptions(vision, {
    baseOptions: {
      modelAssetPath: "https://storage.googleapis.com/mediapipe-models/pose_landmarker/pose_landmarker_lite/float16/latest/pose_landmarker_lite.task",
      delegate: "GPU"
    },
    runningMode: "VIDEO",
    numPoses: 1
  });
  setStep('stepModel', 'done');
  if ('FaceDetector' in window) {
    try {
      faceDetector = new FaceDetector({fastMode: true, maxDetectedFaces: 1});
    } catch (_) {
      faceDetector = null;
    }
  }
}

async function startClient(audioStart = null) {
  if (running) return;
  running = true;
  setMessage('');
  const audioPromise = audioStart || ensureAudioStarted();
  setStatus('Requesting camera');
  setStep('stepCamera', 'active');
  const stream = await navigator.mediaDevices.getUserMedia({video: {facingMode: 'user'}, audio: true});
  cameraStream = stream;
  setStep('stepCamera', 'done');
  video.srcObject = stream;
  await video.play();
  initNoiseDetection(stream);
  audioPromise.then((ok) => {
    if (ok) logAudio('ready');
  });
  connectWs();
  await initPose();
  setStep('stepDetect', 'active');
  liveTimer = setInterval(() => maybeSendLiveFrame(performance.now()), 500);
  requestAnimationFrame(loop);
}

async function maybeSendLiveFrame(now) {
  if (!liveRequested || !allowLive.checked || !ws || ws.readyState !== WebSocket.OPEN || now - lastLiveAt < 500) return;
  lastLiveAt = now;
  const width = 480;
  const height = Math.round(width * video.videoHeight / video.videoWidth) || 270;
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(video, 0, 0, width, height);
  if (censorFaces.checked && faceDetector) {
    try {
      const faces = await faceDetector.detect(video);
      for (const face of faces) {
        const box = face.boundingBox;
        const x = box.x * width / video.videoWidth;
        const y = box.y * height / video.videoHeight;
        const w = box.width * width / video.videoWidth;
        const h = box.height * height / video.videoHeight;
        ctx.filter = 'blur(18px)';
        ctx.drawImage(canvas, x, y, w, h, x, y, w, h);
        ctx.filter = 'none';
        ctx.fillStyle = 'rgba(0,0,0,.18)';
        ctx.fillRect(x, y, w, h);
      }
    } catch (_) {}
  }
  ws.send(JSON.stringify({type: 'live_frame', frame: canvas.toDataURL('image/jpeg', 0.55)}));
}

async function loop() {
  if (poseLandmarker && video.readyState >= 2) {
    const result = poseLandmarker.detectForVideo(video, performance.now());
    const analyzed = await analyze(result);
    await sendPresence(analyzed.present, analyzed.confidence, analyzed.parts, analyzed.kneeling);
    setStep('stepDetect', 'done');
    loadSteps.hidden = true;
  }
  requestAnimationFrame(loop);
}

async function resumePetSession() {
  const res = await fetch('/api/pet/me');
  if (!res.ok) return;
  const payload = await res.json();
  beginPetSession(payload.pet).catch((error) => {
    console.error(error);
    setStatus('Camera/model failed', 'bad');
    setMessage(error?.message || 'Startup failed');
    running = false;
  });
}
resumePetSession();
</script>
"""
