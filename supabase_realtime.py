"""
Capa online de Chat WiFi con Supabase Realtime + Auth anónima + Postgres RLS.

- Login anónimo persistente.
- Salas y miembros en tablas con RPC.
- Canales privados con token.
- Aprobación de entrada, expulsión y cierre.
- Broadcast cifrado con Fernet.
"""

import asyncio
import base64
import hashlib
import mimetypes
import secrets
import threading
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone

import httpx
from cryptography.fernet import Fernet
from PyQt6.QtCore import QObject, pyqtSignal
from realtime import AsyncRealtimeClient, RealtimeSubscribeStates

import message_protocol as proto

SUPABASE_URL = "https://uofdyltvfpbcjcpktqql.supabase.co"
SUPABASE_KEY = "sb_publishable_Ny0lTst8JT0UZsYRKS_Dpw_xPhTVo8Z"
REALTIME_URL = "wss://uofdyltvfpbcjcpktqql.supabase.co/realtime/v1"

MAX_ONLINE_USERS = 10
ROOM_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

COLOR_MAP = {
    "rojo": "#ef4444", "azul": "#3b82f6", "verde": "#22c55e",
    "amarillo": "#eab308", "naranja": "#f97316", "rosa": "#ec4899",
    "morado": "#8b5cf6", "blanco": "#ffffff", "negro": "#000000",
}


def derive_key(secret: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), b"chatwifi_salt", 100000, 32)


def make_fernet(secret: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(derive_key(secret)))


class SupabaseRealtime(QObject):
    connected = pyqtSignal(bool, str)
    status_changed = pyqtSignal(str)
    message_received = pyqtSignal(str, str, dict)
    reaction_received = pyqtSignal(str, str, str)
    read_received = pyqtSignal(str)
    latency_received = pyqtSignal(float)
    command_received = pyqtSignal(str, str, str)
    system_message = pyqtSignal(str)
    user_list_updated = pyqtSignal(list)
    error_occurred = pyqtSignal(str)
    room_created = pyqtSignal(str)
    waiting_approval = pyqtSignal(str)
    room_ready = pyqtSignal(dict)
    admin_updated = pyqtSignal(dict)
    session_updated = pyqtSignal(dict)
    kicked = pyqtSignal()
    room_closed = pyqtSignal()
    file_received = pyqtSignal(str, dict)
    file_sent = pyqtSignal(dict)
    file_downloaded = pyqtSignal(str, str, object)
    file_error = pyqtSignal(str)
    file_delete_result = pyqtSignal(str, bool, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._loop = None
        self._thread = None
        self._ready = threading.Event()
        self._client = None
        self._channel = None
        self._lock = None
        self._auth_lock = None
        self._reconnect_task = None
        self._heartbeat_task = None
        self._presence_task = None
        self._approval_task = None
        self._want_connected = False
        self._subscribed = False
        self._stopping = False
        self._tearing_down = False

        self._username = "Usuario"
        self._code = ""
        self._room_id = ""
        self._topic = ""
        self._fernet = None
        self._presence_key = secrets.token_hex(8)
        self._seen_ids: set[str] = set()

        self._is_admin = False
        self._approved = False
        self._expires_at = 0.0
        self._session = {
            "access_token": "",
            "refresh_token": "",
            "user_id": "",
            "expires_at": 0.0,
        }

    # ── Sesión ────────────────────────────────────────────────────────────
    def set_session(self, session: dict | None):
        if not session:
            return
        self._session.update({
            "access_token": session.get("access_token", ""),
            "refresh_token": session.get("refresh_token", ""),
            "user_id": session.get("user_id", ""),
            "expires_at": float(session.get("expires_at", 0) or 0),
        })

    @property
    def user_id(self) -> str:
        return self._session.get("user_id", "")

    @property
    def is_connected(self) -> bool:
        return self._subscribed

    @property
    def is_admin(self) -> bool:
        return self._is_admin

    @property
    def room_code(self) -> str:
        return self._code

    # ── Hilo asyncio ──────────────────────────────────────────────────────
    def start(self):
        if self._thread is not None and self._thread.is_alive():
            return
        self._stopping = False
        self._ready.clear()
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=3)

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._ready.set()
        self._loop.run_forever()

    def _submit(self, coro):
        if self._loop is None or not self._loop.is_running():
            self.start()
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    # ── API pública ───────────────────────────────────────────────────────
    def create_room(self, secret: str, username: str,
                    approval_required: bool = True, duration_hours: int = 0):
        self.start()
        self._username = (username or "Usuario").strip()
        self._fernet = make_fernet(secret)
        self._code = self._generate_code()
        raw = f"{self._code}:{secret}".encode("utf-8")
        self._topic = "chatwifi:" + hashlib.sha256(raw).hexdigest()[:24]
        self._want_connected = True
        self._submit(
            self._create_room_async(
                self._code, self._topic, self._username,
                approval_required, duration_hours,
            )
        )

    def join_room(self, code: str, secret: str, username: str):
        self.start()
        self._username = (username or "Usuario").strip()
        self._fernet = make_fernet(secret)
        self._code = code.upper().strip()
        self._want_connected = True
        self._submit(self._join_room_async())

    def leave(self):
        self._want_connected = False
        if self._loop is not None and self._loop.is_running():
            self._submit(self._leave_async())

    def stop(self):
        self._want_connected = False
        self._stopping = True
        if self._loop is not None and self._loop.is_running():
            try:
                self._submit(self._leave_async())
            except Exception:
                pass
            time.sleep(0.4)
            try:
                self._loop.call_soon_threadsafe(self._loop.stop)
            except Exception:
                pass

    def send_text(self, text: str, reply_to: dict | None = None,
                  ttl: int | None = None, msg_id: str | None = None,
                  command_target: str | None = None):
        if not self._subscribed:
            self.error_occurred.emit("No estás conectado a la sala online.")
            return
        self._submit(self._send_envelope_async(
            "message", id=msg_id, text=text, reply_to=reply_to,
            expires_at=(time.time() + ttl) if ttl else None,
            command_target=command_target,
        ))

    def send_reaction(self, target: str, emoji: str):
        if self._subscribed:
            self._submit(self._send_envelope_async("reaction", target=target, emoji=emoji))

    def send_read(self, target: str):
        if self._subscribed:
            self._submit(self._send_envelope_async("read", target=target))

    def send_ping(self):
        if self._subscribed:
            self._submit(self._send_envelope_async("ping", ts=time.time()))

    def send_file(self, filepath: str, expires_at: float | None = None):
        if not self._subscribed:
            self.error_occurred.emit("No estás conectado a la sala online.")
            return
        self._submit(self._send_file_async(filepath, expires_at=expires_at))

    def delete_files(self, paths: list[str]):
        paths = [p for p in (paths or []) if p]
        if paths:
            self._submit(self._delete_files_async(paths))

    def download_file(self, request_id: str, name: str, storage_path: str):
        if not self._subscribed:
            self.file_error.emit("No estás conectado a la sala online.")
            return
        self._submit(self._download_file_async(request_id, name, storage_path))

    # ── Administración ────────────────────────────────────────────────────
    def refresh_admin(self):
        if self._is_admin:
            self._submit(self._refresh_admin_async())

    def approve_member(self, user_id: str, approve: bool):
        if self._is_admin:
            self._submit(self._approve_async(user_id, approve))

    def kick_member(self, user_id: str):
        if self._is_admin:
            self._submit(self._kick_async(user_id))

    def close_room(self):
        if self._is_admin:
            self._submit(self._close_room_async())

    # ── Auth ──────────────────────────────────────────────────────────────
    def _auth_headers(self) -> dict:
        return {
            "apikey": SUPABASE_KEY,
            "Authorization": f"Bearer {self._session.get('access_token', '')}",
            "Content-Type": "application/json",
        }

    def _store_session(self, data: dict, keep_user: bool = True):
        user = data.get("user") or {}
        uid = user.get("id") or (self._session.get("user_id") if keep_user else "")
        expires_at = data.get("expires_at")
        if expires_at:
            expires_at = float(expires_at)
        else:
            expires_at = time.time() + float(data.get("expires_in", 3600)) - 60
        self._session = {
            "access_token": data.get("access_token", ""),
            "refresh_token": data.get("refresh_token", self._session.get("refresh_token", "")),
            "user_id": uid,
            "expires_at": expires_at,
        }
        self.session_updated.emit(dict(self._session))

    async def _update_realtime_auth(self):
        """Reenvía el access_token actualizado al canal privado ya conectado.

        El token anónimo caduca (~1 h). El heartbeat refresca la sesión, pero si
        no se actualiza el token del canal Realtime, Supabase cierra el canal al
        expirar el token viejo y la sala se desconecta "al rato".
        """
        client = self._client
        if client is not None:
            try:
                await client.set_auth(self._session.get("access_token", ""))
            except Exception:
                pass

    async def _ensure_auth(self):
        if self._auth_lock is None:
            self._auth_lock = asyncio.Lock()
        async with self._auth_lock:
            now = time.time()
            if (
                self._session.get("access_token")
                and float(self._session.get("expires_at", 0)) > now + 60
            ):
                return

            if self._session.get("refresh_token"):
                try:
                    async with httpx.AsyncClient(timeout=30) as client:
                        r = await client.post(
                            SUPABASE_URL + "/auth/v1/token?grant_type=refresh_token",
                            headers={
                                "apikey": SUPABASE_KEY,
                                "Content-Type": "application/json",
                            },
                            json={"refresh_token": self._session["refresh_token"]},
                        )
                    if r.status_code == 200:
                        self._store_session(r.json(), keep_user=True)
                        await self._update_realtime_auth()
                        return
                except Exception:
                    pass

            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    SUPABASE_URL + "/auth/v1/signup",
                    headers={
                        "apikey": SUPABASE_KEY,
                        "Content-Type": "application/json",
                    },
                    json={"data": {}, "gotrue_meta_security": {}},
                )
            if r.status_code >= 400:
                raise RuntimeError("No se pudo iniciar sesión anónima en Supabase.")
            self._store_session(r.json(), keep_user=False)
            await self._update_realtime_auth()

    async def _rpc(self, name: str, payload: dict):
        await self._ensure_auth()
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(
                SUPABASE_URL + f"/rest/v1/rpc/{name}",
                headers=self._auth_headers(),
                json=payload,
            )
        if r.status_code == 401 and self._session.get("refresh_token"):
            self._session["expires_at"] = 0
            await self._ensure_auth()
            async with httpx.AsyncClient(timeout=30) as client:
                r = await client.post(
                    SUPABASE_URL + f"/rest/v1/rpc/{name}",
                    headers=self._auth_headers(),
                    json=payload,
                )
        if r.status_code >= 400:
            try:
                message = r.json().get("message") or r.text
            except Exception:
                message = r.text
            raise RuntimeError(message)
        if not r.content:
            return None
        return r.json()

    # ── Salas ─────────────────────────────────────────────────────────────
    def _generate_code(self) -> str:
        return "".join(secrets.choice(ROOM_ALPHABET) for _ in range(6))

    def _parse_ts(self, value) -> float:
        if not value:
            return 0.0
        try:
            if isinstance(value, (int, float)):
                return float(value)
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0

    def _room_info(self) -> dict:
        return {
            "code": self._code,
            "room_id": self._room_id,
            "topic": self._topic,
            "is_admin": self._is_admin,
            "expires_at": self._expires_at,
            "user_id": self.user_id,
            "approval_required": not self._approved or self._is_admin,
        }

    async def _create_room_async(self, code, topic, username,
                                 approval_required, duration_hours):
        try:
            expires_at = None
            if duration_hours:
                expires_at = (
                    datetime.now(timezone.utc) + timedelta(hours=duration_hours)
                ).isoformat()
            rows = await self._rpc("chat_create_room", {
                "p_code": code,
                "p_topic": topic,
                "p_name": username,
                "p_expires_at": expires_at,
                "p_approval_required": approval_required,
            })
            row = rows[0] if isinstance(rows, list) else rows
            self._room_id = row.get("room_id", "")
            self._topic = row.get("topic", topic)
            self._expires_at = self._parse_ts(expires_at)
            self._is_admin = True
            self._approved = True
            self.room_created.emit(code)
            self.room_ready.emit(self._room_info())
            await self._connect_channel()
        except Exception as exc:
            self._subscribed = False
            self.error_occurred.emit(f"No se pudo crear la sala: {exc}")
            self.connected.emit(False, f"Error creando sala: {exc}")

    async def _join_room_async(self):
        try:
            rows = await self._rpc("chat_join_room", {
                "p_code": self._code,
                "p_name": self._username,
            })
            row = rows[0] if isinstance(rows, list) else rows
            if not row:
                raise RuntimeError("La sala no respondió.")
            self._room_id = row.get("out_room_id", "")
            self._topic = row.get("out_topic", "")
            self._expires_at = self._parse_ts(row.get("out_expires_at"))
            self._approved = bool(row.get("out_approved"))
            if row.get("out_closed"):
                raise RuntimeError("La sala está cerrada.")
            if self._expires_at and time.time() > self._expires_at:
                raise RuntimeError("La sala expiró.")

            if not self._approved:
                self.waiting_approval.emit(
                    "Esperando aprobación del administrador de la sala…"
                )
                self._approval_task = asyncio.create_task(self._wait_approval())
                return

            await self._after_approved()
        except Exception as exc:
            self._subscribed = False
            self.error_occurred.emit(f"No se pudo entrar a la sala: {exc}")
            self.connected.emit(False, f"Error al unirse: {exc}")

    async def _wait_approval(self):
        while self._want_connected:
            await asyncio.sleep(3)
            try:
                rows = await self._rpc("chat_join_room", {
                    "p_code": self._code,
                    "p_name": self._username,
                })
                row = rows[0] if isinstance(rows, list) else rows
                if row.get("out_closed"):
                    self.error_occurred.emit("La sala fue cerrada.")
                    await self._leave_async()
                    return
                if self._parse_ts(row.get("out_expires_at")) and time.time() > self._parse_ts(row.get("out_expires_at")):
                    self.error_occurred.emit("La sala expiró.")
                    await self._leave_async()
                    return
                if row.get("out_approved"):
                    self._approved = True
                    await self._after_approved()
                    return
            except Exception as exc:
                self.error_occurred.emit(f"Esperando aprobación: {exc}")
                await self._leave_async()
                return

    async def _after_approved(self):
        await self._refresh_membership()
        self.room_ready.emit(self._room_info())
        await self._connect_channel()

    async def _refresh_membership(self):
        try:
            rows = await self._rpc("chat_room_members", {"p_room_id": self._room_id})
            for row in rows or []:
                if row.get("user_id") == self.user_id:
                    self._is_admin = row.get("role") == "admin"
                    self._approved = bool(row.get("approved"))
                    return
        except Exception:
            pass

    # ── Realtime ──────────────────────────────────────────────────────────
    async def _connect_channel(self):
        if self._lock is None:
            self._lock = asyncio.Lock()
        async with self._lock:
            if not self._want_connected or not self._room_id or not self._approved:
                return
            await self._teardown_async()
            self.status_changed.emit("Conectando al canal privado…")
            try:
                await self._ensure_auth()
                client = AsyncRealtimeClient(REALTIME_URL, SUPABASE_KEY)
                await client.set_auth(self._session.get("access_token", ""))
                channel = client.channel(
                    self._topic,
                    {
                        "config": {
                            "broadcast": {"self": False, "ack": True},
                            "presence": {"key": self._presence_key, "enabled": True},
                            "private": True,
                        }
                    },
                )
                channel.on_broadcast("message", self._on_broadcast)
                channel.on_presence_sync(self._presence_cb)
                channel.on_presence_join(self._presence_cb)
                channel.on_presence_leave(self._presence_cb)

                await asyncio.wait_for(client.connect(), timeout=25)
                self._client = client
                self._channel = channel
                await asyncio.wait_for(
                    channel.subscribe(self._on_subscribe),
                    timeout=15,
                )
            except asyncio.TimeoutError:
                await self._teardown_async()
                self._subscribed = False
                message = (
                    "Tiempo de espera agotado conectando con Supabase. "
                    "Revisa tu conexión a Internet."
                )
                self.connected.emit(False, message)
                self.error_occurred.emit(message)
                self._schedule_reconnect()
            except Exception as exc:
                await self._teardown_async()
                self._subscribed = False
                message = f"No se pudo conectar al canal: {exc}"
                self.connected.emit(False, message)
                self.error_occurred.emit(message)
                self._schedule_reconnect()

    async def _teardown_async(self):
        self._tearing_down = True
        channel, client = self._channel, self._client
        self._channel = None
        self._client = None
        self._subscribed = False
        try:
            if channel is not None:
                try:
                    await channel.untrack()
                except Exception:
                    pass
                try:
                    await channel.unsubscribe()
                except Exception:
                    pass
            if client is not None:
                try:
                    await client.close()
                except Exception:
                    pass
        finally:
            self._tearing_down = False

    def _on_subscribe(self, status, err):
        if self._tearing_down:
            return
        if status == RealtimeSubscribeStates.SUBSCRIBED:
            self._subscribed = True
            text = f"Online · sala {self._code}"
            self.connected.emit(True, text)
            self.status_changed.emit(f"Conectado a la sala {self._code}")
            asyncio.create_task(self._track_presence())
            self._start_heartbeat()
            self._start_presence_loop()
        elif status in (
            RealtimeSubscribeStates.CHANNEL_ERROR,
            RealtimeSubscribeStates.TIMED_OUT,
            RealtimeSubscribeStates.CLOSED,
        ):
            self._subscribed = False
            detail = err or (status.value if hasattr(status, "value") else str(status))
            self.connected.emit(False, f"Desconectado: {detail}")
            if self._want_connected and not self._stopping:
                self._schedule_reconnect()

    async def _track_presence(self):
        try:
            if self._channel is not None:
                await self._channel.track({"name": self._username})
                self._emit_presence()
        except Exception as exc:
            self.error_occurred.emit(f"No se pudo publicar tu presencia: {exc}")

    def _presence_cb(self, *args):
        self._emit_presence()

    def _emit_presence(self):
        if self._channel is None:
            self.user_list_updated.emit([])
            return
        try:
            state = self._channel.presence_state() or {}
        except Exception:
            state = {}
        names = []
        for metas in state.values():
            for meta in metas or []:
                name = (meta or {}).get("name")
                if name and name not in names:
                    names.append(name)
        self.user_list_updated.emit(names)
        if len(names) > MAX_ONLINE_USERS:
            self.system_message.emit(
                f"La sala supera el límite recomendado de {MAX_ONLINE_USERS} usuarios ({len(names)})."
            )

    # ── Heartbeat y administración ────────────────────────────────────────
    def _start_presence_loop(self):
        if self._presence_task is not None and not self._presence_task.done():
            return
        self._presence_task = asyncio.create_task(self._presence_loop())

    async def _presence_loop(self):
        while self._want_connected and self._subscribed:
            await asyncio.sleep(3)
            self._emit_presence()

    def _start_heartbeat(self):
        if self._heartbeat_task is not None and not self._heartbeat_task.done():
            return
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())

    async def _heartbeat_loop(self):
        while self._want_connected and self._room_id:
            await asyncio.sleep(30)
            if not self._subscribed:
                continue
            try:
                rows = await self._rpc("chat_join_room", {
                    "p_code": self._code,
                    "p_name": self._username,
                })
                row = rows[0] if isinstance(rows, list) else rows
                if row.get("out_closed"):
                    self.room_closed.emit()
                    await self._leave_async()
                    return
                if not row.get("out_approved"):
                    self.kicked.emit()
                    await self._leave_async()
                    return
            except Exception as exc:
                message = str(exc).lower()
                if any(word in message for word in ("cerrada", "expiró", "bloqueado")):
                    self.room_closed.emit()
                    await self._leave_async()
                    return
            if self._expires_at and time.time() > self._expires_at:
                self.room_closed.emit()
                await self._leave_async()
                return
            if self._is_admin:
                try:
                    await self._refresh_admin_async()
                except Exception:
                    pass

    async def _refresh_admin_async(self):
        if not self._is_admin:
            return
        pending = await self._rpc("chat_pending_members", {"p_room_id": self._room_id})
        members = await self._rpc("chat_room_members", {"p_room_id": self._room_id})
        self.admin_updated.emit({
            "code": self._code,
            "room_id": self._room_id,
            "pending": pending or [],
            "members": members or [],
            "expires_at": self._expires_at,
        })

    async def _approve_async(self, user_id: str, approve: bool):
        try:
            await self._rpc("chat_approve_member", {
                "p_room_id": self._room_id,
                "p_user_id": user_id,
                "p_approve": approve,
            })
            self.system_message.emit(
                "Miembro aprobado." if approve else "Solicitud rechazada."
            )
            await self._refresh_admin_async()
        except Exception as exc:
            self.error_occurred.emit(f"No se pudo aprobar: {exc}")

    async def _kick_async(self, user_id: str):
        try:
            await self._rpc("chat_kick_member", {
                "p_room_id": self._room_id,
                "p_user_id": user_id,
            })
            await self._send_envelope_async("kick", target=user_id)
            self.system_message.emit("Miembro expulsado y bloqueado.")
            await self._refresh_admin_async()
        except Exception as exc:
            self.error_occurred.emit(f"No se pudo expulsar: {exc}")

    async def _close_room_async(self):
        try:
            # Enviar el aviso antes de cerrar: después, la política RLS
            # bloquea los mensajes de una sala cerrada.
            await self._send_envelope_async("room_closed")
            await self._rpc("chat_close_room", {"p_room_id": self._room_id})
            self.room_closed.emit()
            await self._leave_async()
        except Exception as exc:
            self.error_occurred.emit(f"No se pudo cerrar la sala: {exc}")

    async def _leave_async(self):
        self._want_connected = False
        for task in (self._heartbeat_task, self._presence_task, self._approval_task, self._reconnect_task):
            if task is not None and not task.done():
                task.cancel()
        self._heartbeat_task = None
        self._presence_task = None
        self._approval_task = None
        self._reconnect_task = None
        await self._teardown_async()
        self._room_id = ""
        self._topic = ""
        self._is_admin = False
        self._approved = False
        self._expires_at = 0.0
        self.connected.emit(False, "Desconectado de la sala online")
        self.user_list_updated.emit([])

    # ── mensajes ──────────────────────────────────────────────────────────
    async def _send_envelope_async(self, kind: str, **fields):
        if not self._subscribed or self._channel is None or self._fernet is None:
            return
        try:
            payload_text = proto.encode(kind, **fields)
            encrypted = self._fernet.encrypt(payload_text.encode("utf-8"))
            payload = {
                "from": self._username,
                "data": base64.b64encode(encrypted).decode("ascii"),
            }
            await self._channel.send_broadcast("message", payload)
        except Exception as exc:
            self.error_occurred.emit(f"No se pudo enviar el mensaje: {exc}")

    async def _send_file_async(self, filepath: str, expires_at: float | None = None):
        path = Path(filepath)
        if not path.is_file():
            self.file_error.emit("El archivo no existe.")
            return
        if self._fernet is None or not self._room_id:
            self.file_error.emit("No hay una sala activa para subir el archivo.")
            return
        size = path.stat().st_size
        if size > 45 * 1024 * 1024:
            self.file_error.emit("El archivo supera el límite de 45 MB.")
            return
        try:
            await self._ensure_auth()
            data = path.read_bytes()
            encrypted = self._fernet.encrypt(data)
            storage_path = f"rooms/{self._room_id}/{proto.new_id()}.bin"
            headers = {
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {self._session.get('access_token', '')}",
                "x-upsert": "true",
                "Content-Type": "application/octet-stream",
            }
            async with httpx.AsyncClient(timeout=180) as client:
                r = await client.post(
                    SUPABASE_URL + f"/storage/v1/object/chatwifi/{storage_path}",
                    headers=headers,
                    content=encrypted,
                )
            if r.status_code >= 400:
                raise RuntimeError(r.text or "Error subiendo el archivo.")
            meta = {
                "id": proto.new_id(),
                "name": path.name,
                "size": size,
                "mime": mimetypes.guess_type(path.name)[0] or "application/octet-stream",
                "storage_path": storage_path,
                "expires_at": expires_at,
            }
            await self._send_envelope_async("file", **meta)
            self.file_sent.emit(meta)
        except Exception as exc:
            self.file_error.emit(f"No se pudo enviar el archivo: {exc}")

    async def _download_file_async(self, request_id: str, name: str, storage_path: str):
        if self._fernet is None:
            self.file_error.emit("No hay una clave de sala para descifrar el archivo.")
            return
        try:
            await self._ensure_auth()
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.post(
                    SUPABASE_URL + f"/storage/v1/object/sign/chatwifi/{storage_path}",
                    headers=self._auth_headers(),
                    json={"expiresIn": 3600},
                )
            if r.status_code >= 400:
                raise RuntimeError(r.text or "No se pudo firmar el archivo.")
            signed = r.json().get("signedURL", "")
            if signed.startswith("http"):
                full_url = signed
            elif signed.startswith("/storage/v1"):
                full_url = SUPABASE_URL + signed
            else:
                full_url = SUPABASE_URL + "/storage/v1" + signed
            async with httpx.AsyncClient(timeout=180) as client:
                r2 = await client.get(full_url)
            if r2.status_code >= 400:
                raise RuntimeError(r2.text or "No se pudo descargar el archivo.")
            decrypted = self._fernet.decrypt(r2.content)
            self.file_downloaded.emit(request_id, name, decrypted)
        except Exception as exc:
            self.file_error.emit(f"No se pudo descargar el archivo: {exc}")

    async def _delete_files_async(self, paths: list[str]):
        try:
            await self._ensure_auth()
            headers = {
                "apikey": SUPABASE_KEY,
                "Authorization": f"Bearer {self._session.get('access_token', '')}",
            }
            async with httpx.AsyncClient(timeout=60) as client:
                for storage_path in paths:
                    try:
                        r = await client.delete(
                            SUPABASE_URL
                            + f"/storage/v1/object/chatwifi/{storage_path}",
                            headers=headers,
                        )
                        if r.status_code >= 400:
                            self.file_delete_result.emit(
                                storage_path, False, r.text or f"HTTP {r.status_code}"
                            )
                        else:
                            self.file_delete_result.emit(storage_path, True, "")
                    except Exception as exc:
                        self.file_delete_result.emit(storage_path, False, str(exc))
        except Exception as exc:
            for storage_path in paths:
                self.file_delete_result.emit(storage_path, False, str(exc))

    def _on_broadcast(self, *args):
        if not args:
            return
        data = args[-1]
        if isinstance(data, dict) and isinstance(data.get("payload"), dict):
            data = data["payload"]
        if not isinstance(data, dict) or self._fernet is None:
            return

        sender = data.get("from", "Remoto")
        try:
            raw = base64.b64decode(data.get("data", ""))
            plain = self._fernet.decrypt(raw).decode("utf-8")
            env = proto.decode(plain)
        except Exception as exc:
            self.error_occurred.emit(
                f"Mensaje recibido con un secreto distinto o corrupto ({type(exc).__name__})."
            )
            return

        kind = env.get("kind", "message")

        if kind == "kick":
            if env.get("target") == self.user_id:
                self.kicked.emit()
                self._submit(self._leave_async())
            return
        if kind == "room_closed":
            self.room_closed.emit()
            self._submit(self._leave_async())
            return
        if kind == "file":
            self.file_received.emit(sender, env)
            return

        if kind == "message":
            text = env.get("text", "")
            if text.startswith("/"):
                if text.startswith("/color "):
                    parts = text.split(" ", 2)
                    if len(parts) >= 3:
                        env["color"] = COLOR_MAP.get(parts[1].lower(), parts[1])
                        text = parts[2]
                    else:
                        self.system_message.emit("Uso: /color [color] [texto]")
                        return
                else:
                    command, text_target = proto.parse_remote_command(text)
                    if command:
                        target = str(
                            env.get("command_target") or text_target or ""
                        ).strip()
                        if target and target.casefold() != (self._username or "").casefold():
                            return
                        self.command_received.emit(sender, command, target)
                        return
                    self.system_message.emit(f"Comando desconocido: {text}")
                    return

            mid = env.get("id")
            if mid:
                if mid in self._seen_ids:
                    return
                self._seen_ids.add(mid)
            env["from"] = sender
            self.message_received.emit(sender, text, env)
        elif kind == "reaction":
            self.reaction_received.emit(
                env.get("target", ""), env.get("emoji", ""), sender
            )
        elif kind == "read":
            self.read_received.emit(env.get("target", ""))
        elif kind == "ping":
            self._submit(self._send_envelope_async("pong", ts=env.get("ts", time.time())))
        elif kind == "pong":
            try:
                ms = (time.time() - float(env.get("ts", time.time()))) * 1000
            except Exception:
                ms = 0.0
            self.latency_received.emit(ms)

    # ── Reconexión ────────────────────────────────────────────────────────
    def _schedule_reconnect(self):
        if not self._want_connected or self._stopping:
            return
        if self._reconnect_task is not None and not self._reconnect_task.done():
            return

        async def _reconnect():
            await asyncio.sleep(3)
            if self._want_connected and not self._stopping:
                await self._connect_channel()

        self._reconnect_task = asyncio.create_task(_reconnect())
