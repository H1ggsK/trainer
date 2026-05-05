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
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from common.protocol import PROTOCOL_VERSION, compatible


APP_NAME = "Clicker Trainer"
ROOT = Path(__file__).resolve().parents[2]
DB_PATH = Path(os.environ.get("TRAINER_DB_PATH", ROOT / "server" / "trainer.sqlite3"))
AUDIO_DIR = Path(os.environ.get("TRAINER_AUDIO_DIR", ROOT / "server" / "audio"))
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
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    pet_id INTEGER,
                    event TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '{}'
                );
                """
            )
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
            "created_at": row["created_at"],
        }


class Hub:
    def __init__(self, store: Store) -> None:
        self.store = store
        self.clients: dict[int, set[WebSocket]] = {}
        self.client_pet: dict[WebSocket, int] = {}
        self.trainers: set[WebSocket] = set()
        self.presence: dict[int, bool | None] = {}
        self.parts: dict[int, list[str]] = {}
        self.connected_at: dict[int, str] = {}
        self.live_allowed: dict[int, bool] = {}
        self.live_enabled: dict[int, bool] = {}
        self.next_click_at: dict[int, float] = {}
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
            self.parts.setdefault(pet_id, [])
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
                self.parts[pet_id] = []
                self.connected_at.pop(pet_id, None)
                self.live_enabled[pet_id] = False
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
        min_seconds = max(1, min_seconds)
        max_seconds = max(min_seconds, max_seconds)
        await self.store.set_random_click(pet_id, enabled, min_seconds, max_seconds)
        self.next_click_at.pop(pet_id, None)
        await self.store.log("random_click_updated", pet_id, {"enabled": enabled, "min_seconds": min_seconds, "max_seconds": max_seconds})
        await self.broadcast_trainers()

    async def manual_click(self, pet_id: int) -> None:
        await self.store.log("manual_click", pet_id, {})
        await self.broadcast_clients(pet_id, {"type": "play_click", "source": "manual"})
        await self.broadcast_trainers()

    async def update_presence(self, pet_id: int, present: bool, confidence: float | None, parts: list[str]) -> None:
        previous = self.presence.get(pet_id)
        self.presence[pet_id] = present
        self.parts[pet_id] = parts
        if previous != present:
            event = "pet_returned" if present else "pet_left_frame"
            await self.store.log(event, pet_id, {"confidence": confidence, "parts": parts})
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
        if role == "trainer":
            pets = await self.store.list_pets()
            await self._expire_stay_if_needed(pets)
            pets = await self.store.list_pets()
        elif role == "admin":
            trainers = await self.store.list_trainers()
        return {
            "protocol_version": PROTOCOL_VERSION,
            "me": me,
            "pets": [self._public_pet(pet) for pet in pets],
            "trainers": trainers,
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
        return {"stay_in_frame_enabled": self._stay_active(pet)}

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
            "parts": self.parts.get(pet["id"], []),
            "connected_at": self.connected_at.get(pet["id"]),
            "live_allowed": self.live_allowed.get(pet["id"], False),
            "live_enabled": self.live_enabled.get(pet["id"], False),
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
            await self.broadcast_trainers()

    async def _random_loop(self) -> None:
        while True:
            await asyncio.sleep(0.5)
            now = time.time()
            for pet in await self.store.list_pets():
                pet_id = pet["id"]
                if not pet["random_enabled"] or not self.clients.get(pet_id):
                    self.next_click_at.pop(pet_id, None)
                    continue
                due = self.next_click_at.get(pet_id)
                if due is None:
                    self.next_click_at[pet_id] = now + random.randint(pet["click_min_seconds"], pet["click_max_seconds"])
                    continue
                if now >= due:
                    await self.store.log("random_click", pet_id, {})
                    await self.broadcast_clients(pet_id, {"type": "play_click", "source": "random"})
                    self.next_click_at[pet_id] = now + random.randint(pet["click_min_seconds"], pet["click_max_seconds"])
                    await self.broadcast_trainers()


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
app.mount("/audio", StaticFiles(directory=AUDIO_DIR), name="audio")


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
    return HTMLResponse(
        f"""<!doctype html>
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
                )
            elif payload.get("type") == "live_allowed":
                await hub.set_live_allowed(pet_id, bool(payload.get("allowed")))
            elif payload.get("type") == "live_frame":
                await hub.forward_live_frame(pet_id, str(payload.get("frame", "")))
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
        <h2>Random Clicks</h2>
        <div class="toolbar">
          <button id="randomOn">Enable</button>
          <button class="secondary" id="randomOff">Disable</button>
        </div>
        <div class="row">
          <div class="field"><label>Min seconds</label><input id="clickMin" type="number" min="1" step="1" value="30"></div>
          <div class="field"><label>Max seconds</label><input id="clickMax" type="number" min="1" step="1" value="300"></div>
        </div>
        <div id="randomState" class="quiet"></div>
      </section>
      <section class="panel stack">
        <h2>Event Log</h2>
        <div class="logs" id="logs"></div>
      </section>
    </main>
  </div>
</div>
<script>
const $ = (id) => document.getElementById(id);
let state = null;
let logs = [];
let selectedPetId = null;
let liveFramePetId = null;

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
  for (const id of ['manualClick','liveOn','liveOff','stayOn','stayOff','randomOn','randomOff']) $(id).disabled = disabled;
  if (!pet) return;
  $('selectedTitle').textContent = pet.name;
  if (pet.connected) setBadge('petStatus', `${pet.clients} connected`, 'ok'); else setBadge('petStatus', 'offline', 'bad');
  if (pet.presence === true) setBadge('presence', 'in frame', 'ok');
  else if (pet.presence === false) setBadge('presence', 'out of frame', 'bad');
  else setBadge('presence', 'unknown');
  $('parts').textContent = pet.parts?.length ? `Detected: ${pet.parts.join(', ')}` : 'No parts detected yet';
  $('stayState').textContent = pet.stay_enabled
    ? `On${pet.stay_seconds_remaining === null ? '' : `, ${pet.stay_seconds_remaining}s remaining`}`
    : 'Off';
  $('randomState').textContent = pet.random_enabled ? `Enabled, ${pet.click_min_seconds}-${pet.click_max_seconds}s` : 'Disabled';
  $('clickMin').value = pet.click_min_seconds;
  $('clickMax').value = pet.click_max_seconds;
  $('liveState').textContent = pet.live_allowed
    ? (pet.live_enabled ? 'Client allowed live feed; trainer view is on.' : 'Client allowed live feed; trainer view is off.')
    : 'Client has not allowed live feed.';
  if (!pet.live_allowed || !pet.live_enabled || liveFramePetId !== pet.id) clearLiveCanvas();
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
  renderPets();
  renderSelected();
  renderLogs();
}

window.selectPet = (id) => { selectedPetId = id; clearLiveCanvas(); render({state, logs}); };
window.changeCode = async (id) => {
  const code = prompt('New code');
  if (code) await post(`/api/pets/${id}/code`, {code});
};
window.removePet = (id, button) => del(`/api/pets/${id}`, button);

$('addPet').onclick = (e) => post('/api/pets', {name: $('newPetName').value, code: $('newPetCode').value}, e.target);
$('manualClick').onclick = (e) => post(`/api/pets/${selectedPet().id}/click`, {}, e.target);
$('liveOn').onclick = (e) => { clearLiveCanvas(); post(`/api/pets/${selectedPet().id}/live`, {enabled: true}, e.target); };
$('liveOff').onclick = (e) => { clearLiveCanvas(); post(`/api/pets/${selectedPet().id}/live`, {enabled: false}, e.target); };
$('stayOn').onclick = (e) => post(`/api/pets/${selectedPet().id}/stay`, {enabled: true, duration_seconds: Number($('stayDuration').value || 0) || null}, e.target);
$('stayOff').onclick = (e) => post(`/api/pets/${selectedPet().id}/stay`, {enabled: false}, e.target);
$('randomOn').onclick = (e) => post(`/api/pets/${selectedPet().id}/random-click`, {enabled: true, min_seconds: Number($('clickMin').value || 30), max_seconds: Number($('clickMax').value || 300)}, e.target);
$('randomOff').onclick = (e) => post(`/api/pets/${selectedPet().id}/random-click`, {enabled: false, min_seconds: Number($('clickMin').value || 30), max_seconds: Number($('clickMax').value || 300)}, e.target);
$('copyLink').onclick = async () => { await navigator.clipboard.writeText($('petLink').value); showToast('Copied'); };
$('logout').onclick = async () => { await fetch('/api/logout', {method: 'POST'}); location.href = '/'; };

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
      <button id="enableSound" class="secondary" type="button" hidden>Enable sound</button>
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
const clientMessage = document.getElementById('clientMessage');
const allowLive = document.getElementById('allowLive');
const enableSound = document.getElementById('enableSound');
const canvas = document.getElementById('canvas');
const loadSteps = document.getElementById('loadSteps');
const loadStepIds = ['stepCamera', 'stepJs', 'stepWasm', 'stepModel', 'stepDetect'];
const beep = new Audio('/audio/beep.mp3');
const click = new Audio('/audio/click.mp3');
beep.loop = true;
beep.preload = 'auto';
click.preload = 'auto';
let ws = null;
let poseLandmarker = null;
let faceDetector = null;
let stayEnabled = false;
let lastPresent = null;
let lastParts = '';
let lastSent = 0;
let running = false;
let liveRequested = false;
let lastLiveAt = 0;
let liveTimer = null;
let cameraStream = null;
let intentionalDisconnect = false;
let audioUnlocked = false;

function setStatus(text, cls = '') {
  status.className = `badge ${cls}`;
  status.textContent = text;
}

function setMessage(text = '') {
  clientMessage.textContent = text;
  clientMessage.hidden = !text;
}

async function unlockAudio() {
  if (audioUnlocked) return true;
  enableSound.hidden = true;
  const promises = [];
  for (const audio of [beep, click]) {
    const previousMuted = audio.muted;
    const previousVolume = audio.volume;
    audio.muted = true;
    audio.volume = 0;
    const attempt = audio.play();
    if (attempt) {
      promises.push(
        attempt.then(() => {
          audio.pause();
          audio.currentTime = 0;
          audio.muted = previousMuted;
          audio.volume = previousVolume;
          return true;
        }).catch(() => {
          audio.muted = previousMuted;
          audio.volume = previousVolume;
          return false;
        })
      );
    }
  }
  const results = await Promise.all(promises);
  audioUnlocked = results.every(result => result);
  if (!audioUnlocked) {
    enableSound.hidden = false;
  }
  return audioUnlocked;
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

async function beginPetSession(pet) {
  intentionalDisconnect = false;
  petName.textContent = pet.name;
  codePanel.hidden = true;
  clientPanel.hidden = false;
  enableSound.hidden = audioUnlocked;
  resetSteps();
  await startClient();
}

async function submitPetCode() {
  await unlockAudio();
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
  beginPetSession(payload.pet).catch((error) => {
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
  stayWarning.hidden = true;
  clientPanel.hidden = true;
  codePanel.hidden = false;
  petCode.value = '';
  loginPet.disabled = false;
  loginPet.textContent = 'Continue';
  petCode.focus();
};

allowLive.onchange = () => {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({type: 'live_allowed', allowed: allowLive.checked}));
  }
};

enableSound.onclick = async () => {
  await unlockAudio();
  setTimeout(async () => await updateBeep(lastPresent), 150);
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
      stayWarning.hidden = !stayEnabled;
      await updateBeep(lastPresent);
    }
    if (message.type === 'play_click') {
      if (!audioUnlocked) await unlockAudio();
      click.currentTime = 0;
      await click.play().catch((error) => setMessage(`Click sound blocked: ${error.message || error}`));
    }
    if (message.type === 'live_request') {
      liveRequested = Boolean(message.enabled);
    }
    if (message.type === 'error') setStatus(message.message, 'bad');
  };
}

async function updateBeep(present) {
  if (stayEnabled && present === false) {
    if (!audioUnlocked) await unlockAudio();
    beep.play().catch((error) => setMessage(`Beep sound blocked: ${error.message || error}`));
  } else {
    beep.pause();
    beep.currentTime = 0;
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

async function analyze(result) {
  if (!result.landmarks || !result.landmarks.length) {
    if (faceDetector) {
      try {
        const faces = await faceDetector.detect(video);
        if (faces.length) return {present: true, confidence: 0.75, parts: ['head/profile']};
      } catch (_) {}
    }
    return {present: false, confidence: 0, parts: []};
  }
  const landmarks = result.landmarks[0];
  const visibleCount = landmarks.filter((point) => (point.visibility ?? 1) > 0.35).length;
  const parts = classifyParts(landmarks);
  return {present: parts.length > 0 || visibleCount >= 2, confidence: Math.min(1, visibleCount / 12), parts};
}

async function sendPresence(present, confidence, parts) {
  const now = performance.now();
  const partsText = parts.join(', ');
  setStatus(present ? 'In frame' : 'Out of frame', present ? 'ok' : 'bad');
  if (present === lastPresent && partsText === lastParts && now - lastSent < 5000) return;
  lastPresent = present;
  lastParts = partsText;
  lastSent = now;
  await updateBeep(present);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify({type: 'presence', present, confidence, parts}));
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

async function startClient() {
  if (running) return;
  running = true;
  setMessage('');
  setStatus('Requesting camera');
  setStep('stepCamera', 'active');
  const stream = await navigator.mediaDevices.getUserMedia({video: {facingMode: 'user'}, audio: false});
  cameraStream = stream;
  setStep('stepCamera', 'done');
  video.srcObject = stream;
  await video.play();
  connectWs();
  await initPose();
  setStep('stepDetect', 'active');
  liveTimer = setInterval(() => maybeSendLiveFrame(performance.now()), 500);
  requestAnimationFrame(loop);
}

function maybeSendLiveFrame(now) {
  if (!liveRequested || !allowLive.checked || !ws || ws.readyState !== WebSocket.OPEN || now - lastLiveAt < 500) return;
  lastLiveAt = now;
  const width = 480;
  const height = Math.round(width * video.videoHeight / video.videoWidth) || 270;
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  ctx.drawImage(video, 0, 0, width, height);
  ws.send(JSON.stringify({type: 'live_frame', frame: canvas.toDataURL('image/jpeg', 0.55)}));
}

async function loop() {
  if (poseLandmarker && video.readyState >= 2) {
    const result = poseLandmarker.detectForVideo(video, performance.now());
    const analyzed = await analyze(result);
    await sendPresence(analyzed.present, analyzed.confidence, analyzed.parts);
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
