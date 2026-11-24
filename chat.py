"""
Chat WiFi - Escritorio (PyQt6) · versión 2.4.7
Interfaz mejorada con 4 temas (claro, oscuro, neon, matrix).
Pantallas: Servidores · Chat · Ajustes
Red local: TCP 45873 + descubrimiento UDP 45874.
Red online: Supabase Realtime (Broadcast + Presence, cifrado E2E).
Comandos: /off · /screamer · /color [color] [texto]
Ajustes persistentes en JSON. Estilos en estilos_chat.css.
"""

import sys
import json
import re
import html
import ipaddress
import mimetypes
import socket
import struct
import hashlib
import secrets
import subprocess
import tempfile
import threading
import time
import base64
import ctypes
from pathlib import Path
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QFrame, QLabel, QLineEdit, QPushButton, QComboBox,
    QListWidget, QListWidgetItem, QScrollArea, QStackedWidget,
    QInputDialog, QMessageBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QCheckBox, QButtonGroup, QSizePolicy,
    QGraphicsDropShadowEffect, QMenu, QDialog, QFileDialog, QProgressDialog,
    QSystemTrayIcon, QStyle
)
from PyQt6.QtCore import (
    Qt, QTimer, pyqtSignal, QObject, QByteArray, QPoint, QUrl,
    QEvent, QStandardPaths
)
from PyQt6.QtGui import (
    QFont, QColor, QFontMetrics, QPixmap, QDesktopServices, QAction
)
from PyQt6.QtNetwork import (
    QNetworkAccessManager, QNetworkRequest, QNetworkReply,
    QLocalServer, QLocalSocket, QNetworkInterface
)

from supabase_realtime import (
    SupabaseRealtime, MAX_ONLINE_USERS, SUPABASE_URL, SUPABASE_KEY
)
import message_protocol as proto

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ══════════════════════════════════════════════════════════════════════════════
APP_NAME = "Chat WiFi"
APP_VERSION = "2.4.7"
UPDATE_REPO = "Juedorigamer/ChatWifi"
UPDATE_MANIFEST_URL = (
    f"https://github.com/{UPDATE_REPO}/releases/latest/download/latest.json"
)
PORT = 45873
DISCOVERY_PORT = 45874
BUFFER_SIZE = 65536
MAX_FILE_SIZE = 10 * 1024 * 1024
REMOTE_COMMAND_COOLDOWN = 30
SETTINGS_FILE = Path.home() / ".chat_wifi_settings.json"


def app_base_dir() -> Path:
    """Directorio de recursos, tanto en desarrollo como empaquetado."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).parent


CSS_FILE = app_base_dir() / "estilos_chat.css"

AUTH_MODES = ["contraseña", "código", "clave"]
CHAT_FONTS = [
    "Arial", "Times New Roman", "Courier New", "Verdana", "Georgia",
    "Tahoma", "Trebuchet MS", "Impact", "Comic Sans MS", "Consolas"
]
THEMES = ["claro", "oscuro", "neon", "matrix"]
EMOJIS = [
    "😀", "😂", "😍", "😎", "😢", "😮", "🤔", "😅",
    "👍", "👎", "❤️", "🔥", "🎉", "✅", "❌", "🙏",
    "💬", "👋", "💪", "🤝", "🥳", "😱", "😴", "🌙",
]
COLOR_MAP = {
    "rojo": "#ef4444", "azul": "#3b82f6", "verde": "#22c55e",
    "amarillo": "#eab308", "naranja": "#f97316", "rosa": "#ec4899",
    "morado": "#8b5cf6", "blanco": "#ffffff", "negro": "#000000",
}


# ══════════════════════════════════════════════════════════════════════════════
# UTILIDADES
# ══════════════════════════════════════════════════════════════════════════════
def _ipv4_entries():
    """Lista de (ip, netmask, broadcast) de interfaces IPv4 útiles."""
    entries = []
    for iface in QNetworkInterface.allInterfaces():
        flags = iface.flags()
        if flags & QNetworkInterface.InterfaceFlag.IsLoopBack:
            continue
        if not (flags & QNetworkInterface.InterfaceFlag.IsUp):
            continue
        for entry in iface.addressEntries():
            ip = entry.ip().toString()
            if ":" in ip or ip.startswith("127.") or ip.startswith("169.254."):
                continue
            entries.append((ip, entry.netmask().toString(), entry.broadcast().toString()))
    return entries


def get_all_local_ips() -> list:
    return list(dict.fromkeys(ip for ip, _, _ in _ipv4_entries()))


def get_all_broadcast_ips() -> list:
    out = []
    for _, _, broadcast in _ipv4_entries():
        if broadcast and broadcast != "0.0.0.0":
            out.append(broadcast)
    out.append("255.255.255.255")
    return list(dict.fromkeys(out))


def _local_ip_for_peer(peer_ip: str) -> str:
    """IP local de la interfaz que comparte subred con peer_ip."""
    try:
        peer = ipaddress.ip_address(peer_ip)
    except ValueError:
        peer = None
    if peer is not None:
        for ip, netmask, _ in _ipv4_entries():
            try:
                network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
            except ValueError:
                continue
            if peer in network:
                return ip
    return get_local_ip()


def get_local_ip() -> str:
    # Preferimos la interfaz que sale a Internet (elegida por el SO).
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    # Sin Internet: primera IPv4 real de una interfaz activa.
    ips = get_all_local_ips()
    if ips:
        return ips[0]
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def get_broadcast_ip() -> str:
    broadcasts = get_all_broadcast_ips()
    for b in broadcasts:
        if b != "255.255.255.255":
            return b
    return "255.255.255.255"


def derive_key(secret: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", secret.encode(), b"chatwifi_salt", 100000, 32)


def make_fernet(secret: str) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(derive_key(secret)))


def load_css() -> str:
    if CSS_FILE.exists():
        return CSS_FILE.read_text(encoding="utf-8")
    return ""


def filter_css_for_theme(css: str, theme: str) -> str:
    start_marker = f"/* === THEME: {theme} === */"
    end_marker = "/* === END THEME === */"
    s = css.find(start_marker)
    if s == -1:
        return css
    s = css.find("\n", s)
    s = len(css) if s == -1 else s + 1
    e = css.find(end_marker, s)
    if e == -1:
        e = len(css)
    return css[s:e]


def load_settings() -> dict:
    defaults = {
        "username": "Usuario",
        "theme": "claro",
        "font": "Arial",
        "auth_mode": "contraseña",
        "shared_secret": "",
        "confirm_commands": False,
        "ttl_seconds": 0,
        "read_receipts": True,
        "screenshot_protection": False,
        "window_geometry": "",
        "sb_access_token": "",
        "sb_refresh_token": "",
        "sb_user_id": "",
        "sb_expires_at": 0.0,
        "auto_check_updates": True,
        "remote_command_policy": "allow",
        "file_ttl_days": 7,
        "auto_delete_downloads": True,
        "native_notifications": True,
        "pending_file_deletes": [],
        "settings_version": 2,
        "last_screen": "servidores",
    }
    if SETTINGS_FILE.exists():
        try:
            loaded = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            defaults.update(loaded)
            if "remote_command_policy" not in loaded:
                defaults["remote_command_policy"] = (
                    "ask" if defaults.get("confirm_commands", False) else "allow"
                )
            # Migración 2.4.1: la confirmación de comandos remotos queda
            # desactivada por defecto una sola vez. Después el usuario puede
            # volver a activarla y se respeta su elección.
            if int(loaded.get("settings_version", 1) or 1) < 2:
                defaults["confirm_commands"] = False
                defaults["remote_command_policy"] = "allow"
                defaults["settings_version"] = 2
        except Exception:
            pass
    return defaults


def save_settings(settings: dict):
    try:
        SETTINGS_FILE.write_text(
            json.dumps(settings, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    except Exception as e:
        print(f"[settings] error: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# RED
# ══════════════════════════════════════════════════════════════════════════════
class NetworkManager(QObject):
    message_received = pyqtSignal(str, str, dict)
    reaction_received = pyqtSignal(str, str, str)
    read_received = pyqtSignal(str)
    latency_received = pyqtSignal(float)
    system_message = pyqtSignal(str)
    connection_status = pyqtSignal(bool, str)
    user_list_updated = pyqtSignal(list)
    file_received = pyqtSignal(str, str)
    error_occurred = pyqtSignal(str)
    servers_found = pyqtSignal(list)
    host_started = pyqtSignal(str)
    screamer_requested = pyqtSignal()
    command_requested = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.sock: socket.socket | None = None
        self.server_sock: socket.socket | None = None
        self.is_connected = False
        self.hosting = False
        self.running = False
        self.cipher: Fernet | None = None
        self.msg_counter = 0
        self.remote_counter = 0
        self.username = "Usuario"
        self.auth_mode = "contraseña"
        self.shared_secret = ""
        self.remote_name = ""
        self.confirm_commands = False
        self.ignore_remote_commands = False
        self._last_remote_command_at = 0.0
        self._last_challenge = ""
        self._seen_ids: set[str] = set()
        self._accept_thread: threading.Thread | None = None
        self._discovery_thread: threading.Thread | None = None
    # ── Host ──
    def start_server(self):
        if self.is_connected or self.hosting:
            return
        self.hosting = True
        self.running = True
        self.cipher = None
        self.remote_name = ""
        self.msg_counter = 0
        self.remote_counter = 0
        self._seen_ids.clear()
        self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._accept_thread.start()

    def _accept_loop(self):
        server = None
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", PORT))
            server.listen(2)
            server.settimeout(1.0)
            self.server_sock = server
        except Exception as e:
            detail = str(e)
            if "10048" in detail or "10013" in detail:
                message = (
                    f"No se pudo crear la sala LAN: el puerto {PORT} está ocupado. "
                    "Cierra otra instancia de Chat WiFi o reinicia la app."
                )
            else:
                message = f"No se pudo crear la sala: {e}"
            self.error_occurred.emit(message)
            self.hosting = False
            self.running = False
            if server is not None:
                try:
                    server.close()
                except Exception:
                    pass
            if self.server_sock is server:
                self.server_sock = None
            self.connection_status.emit(False, "No se pudo crear la sala LAN")
            return

        if not (self.hosting and self.running):
            # El usuario canceló mientras se abría el puerto.
            try:
                server.close()
            except Exception:
                pass
            if self.server_sock is server:
                self.server_sock = None
            return

        # El descubrimiento se inicia solo cuando el puerto TCP ya escucha.
        self._discovery_thread = threading.Thread(
            target=self._discovery_responder, daemon=True
        )
        self._discovery_thread.start()
        self.system_message.emit("Sala creada. Esperando conexiones…")
        self.host_started.emit(get_local_ip())

        while self.running and self.hosting and self.server_sock is server:
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            self._setup_connection(conn)
            while self.running and self.is_connected and self.sock is not None:
                time.sleep(0.2)
        try:
            server.close()
        except Exception:
            pass
        if self.server_sock is server:
            self.server_sock = None

    def _discovery_responder(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", DISCOVERY_PORT))
            s.settimeout(1.0)
        except Exception as e:
            self.system_message.emit(
                f"Descubrimiento LAN no disponible (UDP {DISCOVERY_PORT}): {e}"
            )
            return
        while self.hosting and self.running:
            try:
                data, addr = s.recvfrom(2048)
            except socket.timeout:
                continue
            except Exception:
                break
            if data == b"CHATWIFI_DISCOVER":
                reply = json.dumps({
                    "name": self.username,
                    "ip": _local_ip_for_peer(addr[0]),
                    "auth": self.auth_mode,
                    "port": PORT,
                    "users": 1 if self.is_connected else 0,
                }).encode("utf-8")
                try:
                    s.sendto(reply, addr)
                except Exception:
                    pass
        try:
            s.close()
        except Exception:
            pass

    # ── Cliente ──
    def connect_to(self, host: str):
        if self.is_connected:
            return
        if self.hosting:
            self.error_occurred.emit(
                "Ya estás creando una sala LAN. Cancélala antes de conectarte a otra."
            )
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(8.0)
            sock.connect((host, PORT))
            sock.settimeout(None)
            self._setup_connection(sock)
        except Exception as e:
            self.error_occurred.emit(f"No se pudo conectar a {host}: {e}")
            self.connection_status.emit(False, f"No se pudo conectar a {host}")

    def _setup_connection(self, conn: socket.socket):
        self.sock = conn
        try:
            conn.settimeout(10.0)  # límite para el handshake inicial
        except Exception:
            pass
        self.is_connected = True
        self.cipher = None
        self.remote_name = ""
        self.msg_counter = 0
        self.remote_counter = 0
        self._seen_ids.clear()
        self._last_remote_command_at = 0.0
        if self.hosting:
            self._last_challenge = secrets.token_hex(16)
            self._send_raw({"type": "challenge", "challenge": self._last_challenge})
        threading.Thread(target=self._recv_loop, daemon=True).start()
        self.connection_status.emit(True, "Conectado")

    def _drop_connection(self, message: str | None = None):
        """Cierra solo la conexión actual; si somos host, la sala sigue viva."""
        if message:
            self.error_occurred.emit(message)
        sock = self.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_WR)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass

    def _send_raw(self, obj: dict):
        if not self.sock:
            return
        try:
            data = json.dumps(obj).encode("utf-8")
            self.sock.sendall(struct.pack(">I", len(data)) + data)
        except Exception as e:
            self._drop_connection(f"Error enviando: {e}")

    def _encrypt_bytes(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data) if self.cipher else data

    def _decrypt_bytes(self, data: bytes) -> bytes:
        if self.cipher:
            try:
                return self.cipher.decrypt(data)
            except InvalidToken:
                return data
        return data

    def _recv_exact(self, n: int, sock: socket.socket | None = None) -> bytes:
        sock = sock or self.sock
        chunks = []
        while n > 0:
            try:
                chunk = sock.recv(min(n, BUFFER_SIZE))
            except Exception:
                return b""
            if not chunk:
                return b""
            chunks.append(chunk)
            n -= len(chunk)
        return b"".join(chunks)

    def _recv_loop(self):
        sock = self.sock
        while self.running or sock:
            try:
                header = self._recv_exact(4, sock)
                if not header:
                    break
                length = struct.unpack(">I", header)[0]
                if length > 64 * 1024 * 1024:
                    break
                data = self._recv_exact(length, sock)
                if not data:
                    break
                self._handle_message(json.loads(data.decode("utf-8")), sock)
            except Exception:
                break
        if self.sock is sock:
            self.sock = None
            self.is_connected = False
            self.cipher = None
            self.remote_name = ""
            self.msg_counter = 0
            self.remote_counter = 0
            self._last_remote_command_at = 0.0
            self._seen_ids.clear()
            self.connection_status.emit(False, "Desconectado")
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    def _activate_cipher(self):
        if self.cipher:
            return
        self.cipher = make_fernet(self.shared_secret)
        if self.sock is not None:
            try:
                self.sock.settimeout(None)
            except Exception:
                pass
        self._send_raw({"type": "hello", "name": self.username})
        self.user_list_updated.emit([self.username])

    def _handle_message(self, obj: dict, source: socket.socket | None = None):
        if source is not None and source is not self.sock:
            return
        mtype = obj.get("type")
        if mtype not in ("challenge", "challenge_response", "auth_error"):
            if self.cipher is None:
                self._drop_connection("Mensaje recibido antes de autenticarse.")
                return
        if mtype == "challenge":
            if self.hosting:
                self._drop_connection("Handshake inválido: el host no responde retos.")
                return
            challenge = obj.get("challenge", "")
            resp = hashlib.sha256((challenge + self.shared_secret).encode()).hexdigest()
            self._send_raw({"type": "challenge_response", "response": resp})
            self._activate_cipher()
        elif mtype == "challenge_response":
            if not self.hosting:
                self._drop_connection("Handshake inválido: el cliente no valida retos.")
                return
            expected = hashlib.sha256(
                (self._last_challenge + self.shared_secret).encode()
            ).hexdigest()
            if obj.get("response") == expected:
                self._activate_cipher()
                self.system_message.emit("Cifrado activado.")
            else:
                try:
                    self._send_raw({
                        "type": "auth_error",
                        "message": "Secreto incorrecto. Conexión rechazada.",
                    })
                except Exception:
                    pass
                time.sleep(0.2)
                self._drop_connection("Secreto incorrecto. Conexión rechazada.")
        elif mtype == "auth_error":
            self.error_occurred.emit(
                obj.get("message") or "Secreto incorrecto. Conexión rechazada."
            )
            self._drop_connection()
        elif mtype == "hello":
            self.remote_name = obj.get("name", "Remoto")
            users = [self.username]
            if self.remote_name and self.remote_name not in users:
                users.append(self.remote_name)
            self.user_list_updated.emit(users)
            self.system_message.emit(f"{self.remote_name} se ha conectado.")
        elif mtype == "text":
            self.remote_counter = max(self.remote_counter, obj.get("counter", 0))
            raw = base64.b64decode(obj.get("data", ""))
            plain = self._decrypt_bytes(raw).decode(errors="replace")
            env = proto.decode(plain)
            kind = env.get("kind", "message")
            sender = obj.get("from", "Remoto")

            if kind == "message":
                text = env.get("text", "")
                if text.startswith("/"):
                    self._handle_remote_command(
                        sender, text, env.get("command_target", "")
                    )
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
                self._send_envelope("pong", ts=env.get("ts", time.time()))
            elif kind == "pong":
                try:
                    ms = (time.time() - float(env.get("ts", time.time()))) * 1000
                except Exception:
                    ms = 0.0
                self.latency_received.emit(ms)
        elif mtype == "file":
            self._handle_file(obj)

    def _handle_remote_command(
        self, sender: str, text: str, command_target: str = ""
    ):
        command, text_target = proto.parse_remote_command(text)
        target = (command_target or text_target or "").strip()
        if command:
            if target and target.casefold() != (self.username or "").casefold():
                return
            now = time.time()
            if now - self._last_remote_command_at < REMOTE_COMMAND_COOLDOWN:
                self.system_message.emit(
                    "Comando remoto ignorado: espera "
                    f"{REMOTE_COMMAND_COOLDOWN} s entre comandos."
                )
                return
            self._last_remote_command_at = now
            if self.ignore_remote_commands:
                self.system_message.emit(
                    f"Comando remoto de {sender} ignorado automáticamente."
                )
                return
            if self.confirm_commands:
                self.command_requested.emit(command)
            else:
                self.system_message.emit(
                    f"Comando remoto de {sender}: {command} ejecutado."
                )
                self.execute_remote_command(command)
            return
        if text.startswith("/color"):
            parts = text.split(" ", 2)
            if len(parts) >= 3:
                color = COLOR_MAP.get(parts[1].lower(), parts[1])
                self.message_received.emit(
                    sender, parts[2], {"id": proto.new_id(), "color": color}
                )
            else:
                self.system_message.emit("Uso: /color [color] [texto]")
        else:
            self.system_message.emit(f"Comando desconocido: {text}")

    def execute_remote_command(self, text: str):
        if text == "/off":
            self.system_message.emit("Comando remoto /off recibido. Apagando…")
            try:
                subprocess.run(["shutdown", "/s", "/t", "0"], check=True)
            except Exception as e:
                self.error_occurred.emit(f"No se pudo apagar: {e}")
        elif text == "/screamer":
            self.screamer_requested.emit()

    def _handle_file(self, obj: dict):
        fname = obj.get("filename", "archivo")
        raw = base64.b64decode(obj.get("data", ""))
        try:
            save_path = Path(tempfile.gettempdir()) / fname
            save_path.write_bytes(self._decrypt_bytes(raw))
            self.file_received.emit(fname, str(save_path))
        except Exception as e:
            self.error_occurred.emit(f"Error guardando archivo: {e}")

    # ── Envío ──
    def _send_envelope(self, kind: str, **fields):
        if not self.is_connected:
            return
        self.msg_counter += 1
        payload = proto.encode(kind, **fields)
        encrypted = self._encrypt_bytes(payload.encode("utf-8"))
        self._send_raw({
            "type": "text",
            "from": self.username,
            "counter": self.msg_counter,
            "data": base64.b64encode(encrypted).decode(),
        })

    def send_text(self, text: str, reply_to: dict | None = None,
                  ttl: int | None = None, msg_id: str | None = None,
                  command_target: str | None = None):
        self._send_envelope(
            "message",
            id=msg_id,
            text=text,
            reply_to=reply_to,
            expires_at=(time.time() + ttl) if ttl else None,
            command_target=command_target,
        )

    def send_reaction(self, target: str, emoji: str):
        self._send_envelope("reaction", target=target, emoji=emoji)

    def send_read(self, target: str):
        self._send_envelope("read", target=target)

    def send_ping(self):
        self._send_envelope("ping", ts=time.time())

    def send_file(self, filepath: str):
        if not self.is_connected:
            return
        path = Path(filepath)
        if path.stat().st_size > MAX_FILE_SIZE:
            self.error_occurred.emit("Archivo demasiado grande (máx. 10 MB)")
            return
        self.msg_counter += 1
        encrypted = self._encrypt_bytes(path.read_bytes())
        self._send_raw({
            "type": "file",
            "from": self.username,
            "counter": self.msg_counter,
            "filename": path.name,
            "data": base64.b64encode(encrypted).decode(),
        })

    # ── Descubrimiento ──
    def discover_servers(self, timeout: float = 2.2):
        threading.Thread(target=self._discover_worker, args=(timeout,), daemon=True).start()

    def _discover_worker(self, timeout: float):
        found = {}
        local_ips = set(get_all_local_ips())
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.settimeout(0.4)
            for bcast in get_all_broadcast_ips():
                try:
                    s.sendto(b"CHATWIFI_DISCOVER", (bcast, DISCOVERY_PORT))
                except Exception:
                    pass
            end = time.time() + timeout
            while time.time() < end:
                try:
                    data, addr = s.recvfrom(4096)
                except socket.timeout:
                    continue
                except Exception:
                    break
                try:
                    obj = json.loads(data.decode("utf-8"))
                except Exception:
                    continue
                ip = obj.get("ip") or addr[0]
                if ip in local_ips:
                    continue
                found[ip] = {
                    "name": obj.get("name", "Sala"),
                    "ip": ip,
                    "auth": obj.get("auth", "—"),
                    "users": obj.get("users", 0),
                }
            s.close()
        except Exception:
            pass
        finally:
            self.servers_found.emit(list(found.values()))

    def disconnect(self):
        self.running = False
        self.hosting = False
        self.is_connected = False
        for sock in (self.sock, self.server_sock):
            try:
                if sock:
                    sock.close()
            except Exception:
                pass
        self.sock = None
        self.server_sock = None
        self.cipher = None
        self.remote_name = ""
        self.msg_counter = 0
        self.remote_counter = 0
        self._last_remote_command_at = 0.0
        self._seen_ids.clear()
        self.connection_status.emit(False, "Desconectado")


# ══════════════════════════════════════════════════════════════════════════════
# VENTANA PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════
class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} · {APP_VERSION}")
        self.resize(1200, 840)
        self.setMinimumSize(1000, 680)
        self.setAcceptDrops(True)

        self.settings = load_settings()
        self.network = NetworkManager()
        self.network.username = self.settings.get("username", "Usuario")
        self.network.auth_mode = self.settings.get("auth_mode", "contraseña")
        self.network.shared_secret = self.settings.get("shared_secret", "")
        self.network.confirm_commands = (
            self.settings.get("remote_command_policy", "allow") == "ask"
        )
        self.network.ignore_remote_commands = (
            self.settings.get("remote_command_policy", "allow") == "ignore"
        )

        self._css = load_css()
        self.previous_screen: int | None = None
        self._found_servers: list[dict] = []
        self._searching = False
        self._screamer_win = None
        self.mode = "lan"
        self.online_connected = False
        self.supabase = SupabaseRealtime(self)
        self.supabase.set_session({
            "access_token": self.settings.get("sb_access_token", ""),
            "refresh_token": self.settings.get("sb_refresh_token", ""),
            "user_id": self.settings.get("sb_user_id", ""),
            "expires_at": self.settings.get("sb_expires_at", 0.0),
        })
        self._admin_dialog = None
        self._admin_data: dict = {}
        self._room_info: dict = {}

        self._msg_widgets: dict[str, QWidget] = {}
        self._seen_ids: set[str] = set()
        self._reactions: dict[str, list[tuple[str, str]]] = {}
        self._reply_to: dict | None = None
        self._preview_manager = QNetworkAccessManager(self)
        self._update_manager = QNetworkAccessManager(self)
        self._update_reply = None
        self._update_file = None
        self._update_dest: Path | None = None
        self._update_part: Path | None = None
        self._update_info: dict = {}
        self._update_dialog: QProgressDialog | None = None
        self._update_cancelled = False
        self._manual_update_check = False
        self._tray = None
        self._tray_mute = None
        self._notifications_muted = False
        self._notif_pending = []
        self._notif_timer = QTimer(self)
        self._notif_timer.setSingleShot(True)
        self._notif_timer.setInterval(700)
        self._notif_timer.timeout.connect(self._flush_notifications)
        self._last_received = None
        self._last_online_command_at = 0.0
        self._last_command_sent_at = 0.0

        self.setup_ui()
        self._connect_signals()
        self.apply_theme(self.settings.get("theme", "claro"))
        self._update_identity()
        self._set_chat_enabled(False)
        self.on_user_list([])
        self._setup_tray()
        self._cleanup_timer = QTimer(self)
        self._cleanup_timer.setInterval(60 * 60 * 1000)
        self._cleanup_timer.timeout.connect(self._run_file_cleanup)
        self._cleanup_timer.start()
        QTimer.singleShot(5000, self._run_file_cleanup)

        geometry = self.settings.get("window_geometry", "")
        if geometry:
            try:
                self.restoreGeometry(QByteArray.fromBase64(geometry.encode("ascii")))
            except Exception:
                pass

        self._latency_timer = QTimer(self)
        self._latency_timer.setInterval(120000)
        self._latency_timer.timeout.connect(self._request_latency)
        self._latency_timer.start()
        QTimer.singleShot(0, self._apply_screenshot_protection)

        last = self.settings.get("last_screen", "servidores")
        idx = {"servidores": 0, "chat": 1, "ajustes": 2}.get(last, 0)
        self.stack.setCurrentIndex(idx)
        self._set_nav_active(idx)
        self.statusBar().showMessage("Listo")
        if self.settings.get("auto_check_updates", True):
            QTimer.singleShot(5000, lambda: self.check_updates(manual=False))

    # ══════════════════════════════════════════════════════════════════════════
    # NOTIFICACIONES NATIVAS
    # ══════════════════════════════════════════════════════════════════════════
    def _setup_tray(self):
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        icon = self.windowIcon()
        if icon.isNull():
            icon = self.style().standardIcon(
                QStyle.StandardPixmap.SP_MessageBoxInformation
            )
        tray = QSystemTrayIcon(icon, self)
        tray.setToolTip(APP_NAME)
        menu = QMenu(self)
        action_open = menu.addAction("Abrir Chat WiFi")
        action_open.triggered.connect(self._show_from_tray)
        menu.addSeparator()
        self._tray_mute = menu.addAction("Silenciar notificaciones")
        self._tray_mute.setCheckable(True)
        self._tray_mute.toggled.connect(self._set_notifications_muted)
        menu.addSeparator()
        action_quit = menu.addAction("Salir")
        action_quit.triggered.connect(lambda: QApplication.instance().quit())
        tray.setContextMenu(menu)
        tray.activated.connect(self._on_tray_activated)
        tray.show()
        self._tray = tray

    def _on_tray_activated(self, reason):
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self._show_from_tray()

    def _show_from_tray(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _set_notifications_muted(self, muted: bool):
        self._notifications_muted = bool(muted)
        if self._tray_mute is not None:
            self._tray_mute.setText(
                "Activar notificaciones" if muted else "Silenciar notificaciones"
            )

    def _notifications_allowed(self) -> bool:
        if not self.settings.get("native_notifications", True):
            return False
        if self._notifications_muted or self._tray is None:
            return False
        if (
            self.isActiveWindow()
            and not self.isMinimized()
            and self.stack.currentIndex() == 1
        ):
            return False
        return True

    def _notify_message(self, sender: str, text: str):
        if not self._notifications_allowed():
            return
        self._notif_pending.append((sender, text))
        if not self._notif_timer.isActive():
            self._notif_timer.start()

    def _notify_file(self, sender: str, name: str):
        if not self._notifications_allowed():
            return
        if not self._tray.supportsMessages():
            return
        self._tray.showMessage(
            f"{APP_NAME} · archivo de {sender}",
            self._elide(name or "Archivo", 140),
            QSystemTrayIcon.MessageIcon.Information,
            6000,
        )

    def _flush_notifications(self):
        items = self._notif_pending
        self._notif_pending = []
        if not items or self._tray is None:
            return
        if not self._tray.supportsMessages():
            return
        if len(items) == 1:
            sender, text = items[0]
            title = f"{APP_NAME} · {sender}"
            body = self._elide(text, 160)
        else:
            title = f"{APP_NAME} · {len(items)} mensajes"
            body = "\n".join(
                f"{sender}: {self._elide(text, 70)}"
                for sender, text in items[-4:]
            )
        self._tray.showMessage(
            title,
            body,
            QSystemTrayIcon.MessageIcon.Information,
            6000,
        )


    # ══════════════════════════════════════════════════════════════════════════
    # CONSTRUCCIÓN DE UI
    # ══════════════════════════════════════════════════════════════════════════
    def setup_ui(self):
        central = QWidget()
        central.setObjectName("root")
        self.setCentralWidget(central)

        main = QVBoxLayout(central)
        main.setContentsMargins(22, 18, 22, 18)
        main.setSpacing(14)

        # ── Cabecera: título + navegación ──
        header = QHBoxLayout()
        header.setSpacing(10)

        title_box = QVBoxLayout()
        title_box.setSpacing(0)
        lbl_title = QLabel(APP_NAME)
        lbl_title.setObjectName("app_title")
        lbl_sub = QLabel("Mensajería privada en tu red y online")
        lbl_sub.setObjectName("subtitle")
        title_box.addWidget(lbl_title)
        title_box.addWidget(lbl_sub)

        header.addLayout(title_box)
        header.addStretch()

        self.btn_nav_servidores = QPushButton("Servidores")
        self.btn_nav_chat = QPushButton("Chat")
        self.btn_nav_ajustes = QPushButton("Ajustes")
        for b in (self.btn_nav_servidores, self.btn_nav_chat, self.btn_nav_ajustes):
            b.setObjectName("nav_btn")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            header.addWidget(b)

        main.addLayout(header)

        # ── Contenedor principal ──
        self.contenedor = QFrame()
        self.contenedor.setObjectName("contenedor_principal")
        self.contenedor.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.contenedor.setMaximumWidth(1200)
        self.contenedor.setMinimumSize(920, 560)

        shadow = QGraphicsDropShadowEffect(self.contenedor)
        shadow.setBlurRadius(34)
        shadow.setOffset(0, 10)
        shadow.setColor(QColor(15, 23, 42, 45))
        self.contenedor.setGraphicsEffect(shadow)

        cont_lay = QVBoxLayout(self.contenedor)
        cont_lay.setContentsMargins(18, 18, 18, 18)
        cont_lay.setSpacing(0)

        self.stack = QStackedWidget()
        cont_lay.addWidget(self.stack)

        self.page_servidores = self._build_servidores()
        self.page_chat = self._build_chat()
        self.page_ajustes = self._build_ajustes()
        self.stack.addWidget(self.page_servidores)
        self.stack.addWidget(self.page_chat)
        self.stack.addWidget(self.page_ajustes)

        main.addWidget(self.contenedor, stretch=1, alignment=Qt.AlignmentFlag.AlignHCenter)

    # ── Pantalla: SERVIDORES ────────────────────────────────────────────────
    def _build_servidores(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(2, 2, 2, 2)
        lay.setSpacing(14)

        head = QVBoxLayout()
        head.setSpacing(2)
        t = QLabel("Servidores cercanos")
        t.setObjectName("page_title")
        s = QLabel("Crea una sala LAN, o usa Online para conectar fuera de tu WiFi.")
        s.setObjectName("page_subtitle")
        head.addWidget(t)
        head.addWidget(s)
        lay.addLayout(head)

        top = QHBoxLayout()
        top.setSpacing(16)

        # Tabla
        table_card = QFrame()
        table_card.setObjectName("servidores_tabla")
        tc_lay = QVBoxLayout(table_card)
        tc_lay.setContentsMargins(1, 1, 1, 1)
        tc_lay.setSpacing(0)

        self.tabla = QTableWidget(0, 3)
        self.tabla.setHorizontalHeaderLabels(["Nombre", "IP y usuarios", "Autenticación"])
        self.tabla.verticalHeader().setVisible(False)
        self.tabla.verticalHeader().setDefaultSectionSize(38)
        self.tabla.setShowGrid(False)
        self.tabla.setAlternatingRowColors(True)
        self.tabla.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tabla.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tabla.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tabla.setFrameShape(QFrame.Shape.NoFrame)
        self.tabla.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.tabla.setTextElideMode(Qt.TextElideMode.ElideRight)
        hh = self.tabla.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        hh.setHighlightSections(False)

        self.lbl_tabla_hint = QLabel(
            "Sin salas detectadas todavía.\nPulsa «Buscar» o crea una sala con el botón verde."
        )
        self.lbl_tabla_hint.setObjectName("hint_chat")
        self.lbl_tabla_hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_tabla_hint.setWordWrap(True)

        tc_lay.addWidget(self.tabla, stretch=1)
        tc_lay.addWidget(self.lbl_tabla_hint)
        tc_lay.addSpacing(8)
        top.addWidget(table_card, stretch=1)

        # Opciones de conexión: LAN / Online
        opts = QFrame()
        opts.setObjectName("servidores_opciones")
        opts.setFixedWidth(265)
        ol = QVBoxLayout(opts)
        ol.setContentsMargins(16, 16, 16, 16)
        ol.setSpacing(8)

        o1 = QLabel("OPCIONES DE CONEXIÓN")
        o1.setObjectName("section_label")
        ol.addWidget(o1)

        mode_row = QHBoxLayout()
        mode_row.setSpacing(6)
        self.btn_mode_lan = QPushButton("LAN")
        self.btn_mode_online = QPushButton("Online")
        for b in (self.btn_mode_lan, self.btn_mode_online):
            b.setObjectName("nav_btn")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_mode_lan.setChecked(True)
        mode_group = QButtonGroup(self)
        mode_group.setExclusive(True)
        mode_group.addButton(self.btn_mode_lan)
        mode_group.addButton(self.btn_mode_online)
        mode_row.addWidget(self.btn_mode_lan)
        mode_row.addWidget(self.btn_mode_online)
        mode_row.addStretch()
        ol.addLayout(mode_row)

        f2 = QLabel("Secreto compartido")
        f2.setObjectName("lbl_field")
        ol.addWidget(f2)

        self.txt_secret = QLineEdit()
        self.txt_secret.setPlaceholderText("Mismo secreto en ambos equipos")
        self.txt_secret.setText(self.settings.get("shared_secret", ""))
        ol.addWidget(self.txt_secret)

        self.mode_stack = QStackedWidget()

        # Página LAN
        lan_page = QWidget()
        ll = QVBoxLayout(lan_page)
        ll.setContentsMargins(0, 4, 0, 0)
        ll.setSpacing(8)

        f1 = QLabel("Tipo de secreto")
        f1.setObjectName("lbl_field")
        ll.addWidget(f1)

        self.combo_auth = QComboBox()
        self.combo_auth.addItems(AUTH_MODES)
        self.combo_auth.setCurrentText(self.settings.get("auth_mode", "contraseña"))
        self.combo_auth.setToolTip(
            "Informativo: se muestra en la búsqueda. El secreto se valida igual."
        )
        ll.addWidget(self.combo_auth)

        self.btn_host = QPushButton("Crear sala LAN")
        self.btn_host.setObjectName("verde")
        self.btn_host.setCursor(Qt.CursorShape.PointingHandCursor)
        ll.addWidget(self.btn_host)

        self.lbl_host = QLabel("Sin sala activa")
        self.lbl_host.setObjectName("hint_chat")
        self.lbl_host.setWordWrap(True)
        self.lbl_host.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        ll.addWidget(self.lbl_host)

        lan_tip = QLabel("Conexión directa en la misma WiFi. Sin Internet.")
        lan_tip.setObjectName("hint_chat")
        lan_tip.setWordWrap(True)
        ll.addWidget(lan_tip)
        ll.addStretch()
        self.mode_stack.addWidget(lan_page)

        # Página Online
        on_page = QWidget()
        onl = QVBoxLayout(on_page)
        onl.setContentsMargins(0, 4, 0, 0)
        onl.setSpacing(6)

        self.lbl_online_status = QLabel("Sin conexión")
        self.lbl_online_status.setObjectName("hint_chat")
        self.lbl_online_status.setWordWrap(True)
        onl.addWidget(self.lbl_online_status)

        room_label = QLabel("Código de sala")
        room_label.setObjectName("lbl_field")
        onl.addWidget(room_label)

        self.txt_room = QLineEdit()
        self.txt_room.setPlaceholderText("Ej. K7F2Q9")
        self.txt_room.setMaxLength(8)
        self.txt_room.returnPressed.connect(self.on_online_join)
        onl.addWidget(self.txt_room)

        self.btn_online_create = QPushButton("Crear sala")
        self.btn_online_create.setObjectName("verde")
        self.btn_online_create.setToolTip("Crear una sala online y generar código")
        self.btn_online_create.setCursor(Qt.CursorShape.PointingHandCursor)

        self.btn_online_join = QPushButton("Unirse")
        self.btn_online_join.setObjectName("btn_primario")
        self.btn_online_join.setToolTip("Unirse con el código de sala")
        self.btn_online_join.setCursor(Qt.CursorShape.PointingHandCursor)

        first_row = QHBoxLayout()
        first_row.setSpacing(8)
        first_row.addWidget(self.btn_online_create)
        first_row.addWidget(self.btn_online_join)
        onl.addLayout(first_row)

        self.btn_online_leave = QPushButton("Salir")
        self.btn_online_leave.setObjectName("btn_accion")
        self.btn_online_leave.setToolTip("Salir de la sala online")
        self.btn_online_leave.setCursor(Qt.CursorShape.PointingHandCursor)

        self.btn_online_check = QPushButton("Supabase")
        self.btn_online_check.setObjectName("btn_accion")
        self.btn_online_check.setToolTip("Comprobar si el proyecto Supabase responde")
        self.btn_online_check.setCursor(Qt.CursorShape.PointingHandCursor)

        second_row = QHBoxLayout()
        second_row.setSpacing(8)
        second_row.addWidget(self.btn_online_leave)
        second_row.addWidget(self.btn_online_check)
        onl.addLayout(second_row)

        self.chk_approval = QCheckBox("Requerir aprobación")
        self.chk_approval.setToolTip("El administrador debe aprobar a cada nuevo miembro")
        self.chk_approval.setChecked(True)
        onl.addWidget(self.chk_approval)

        duration_row = QHBoxLayout()
        duration_row.setSpacing(8)
        duration_label = QLabel("Duración")
        duration_label.setObjectName("lbl_field")
        self.combo_duration = QComboBox()
        for text, hours in (
            ("Sin caducidad", 0), ("1 hora", 1), ("24 horas", 24), ("7 días", 168),
        ):
            self.combo_duration.addItem(text, hours)
        duration_row.addWidget(duration_label)
        duration_row.addWidget(self.combo_duration)
        duration_row.addStretch()
        onl.addLayout(duration_row)

        online_tip = QLabel(
            f"Online: sin abrir puertos · máx. {MAX_ONLINE_USERS} usuarios."
        )
        online_tip.setObjectName("hint_chat")
        online_tip.setWordWrap(True)
        onl.addWidget(online_tip)
        onl.addStretch()
        self.mode_stack.addWidget(on_page)

        ol.addWidget(self.mode_stack, stretch=1)
        top.addWidget(opts)
        lay.addLayout(top, stretch=1)

        # Botonera inferior
        bottom = QHBoxLayout()
        bottom.setSpacing(10)
        self.btn_conectar = QPushButton("Conectar")
        self.btn_conectar.setObjectName("btn_primario")
        self.btn_conectar.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_buscar = QPushButton("Buscar")
        self.btn_buscar.setObjectName("btn_accion")
        self.btn_buscar.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_cancelar = QPushButton("Cancelar")
        self.btn_cancelar.setObjectName("btn_accion")
        self.btn_cancelar.setCursor(Qt.CursorShape.PointingHandCursor)

        self.btn_serv_chat = QPushButton("Abrir chat")
        self.btn_serv_chat.setObjectName("btn_accion")
        self.btn_serv_chat.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_serv_ajustes = QPushButton("Ajustes")
        self.btn_serv_ajustes.setObjectName("btn_accion")
        self.btn_serv_ajustes.setCursor(Qt.CursorShape.PointingHandCursor)

        bottom.addWidget(self.btn_conectar)
        bottom.addWidget(self.btn_buscar)
        bottom.addWidget(self.btn_cancelar)
        bottom.addStretch()
        bottom.addWidget(self.btn_serv_ajustes)
        bottom.addWidget(self.btn_serv_chat)
        lay.addLayout(bottom)

        self.btn_conectar.clicked.connect(self.on_conectar)
        self.btn_buscar.clicked.connect(self.on_buscar)
        self.btn_cancelar.clicked.connect(self.on_cancelar)
        self.btn_host.clicked.connect(self.on_host)
        self.combo_auth.currentTextChanged.connect(self._on_auth_mode_changed)
        self.btn_mode_lan.clicked.connect(lambda: self._set_connection_mode("lan"))
        self.btn_mode_online.clicked.connect(lambda: self._set_connection_mode("online"))
        self.btn_online_create.clicked.connect(self.on_online_create)
        self.btn_online_join.clicked.connect(self.on_online_join)
        self.btn_online_leave.clicked.connect(self.on_online_leave)
        self.btn_online_check.clicked.connect(self.on_online_check)
        self.btn_serv_chat.clicked.connect(lambda: self.show_screen("chat"))
        self.btn_serv_ajustes.clicked.connect(lambda: self.show_screen("ajustes"))
        self.tabla.itemActivated.connect(lambda *_: self.on_conectar())
        self.combo_auth.currentTextChanged.connect(lambda t: self._set_setting("auth_mode", t))
        self.txt_secret.textChanged.connect(lambda t: self._set_setting("shared_secret", t))
        return page

    # ── Pantalla: CHAT ──────────────────────────────────────────────────────
    def _build_chat(self) -> QWidget:
        page = QWidget()
        lay = QHBoxLayout(page)
        lay.setContentsMargins(2, 2, 2, 2)
        lay.setSpacing(16)

        # Columna izquierda
        izq = QFrame()
        izq.setObjectName("chat_izq")
        izq.setFixedWidth(250)
        il = QVBoxLayout(izq)
        il.setContentsMargins(0, 0, 0, 0)
        il.setSpacing(12)

        self.btn_chat_ajustes = QPushButton("AJUSTES")
        self.btn_chat_ajustes.setObjectName("btn_chat_ajustes")
        self.btn_chat_ajustes.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_chat_ajustes.clicked.connect(lambda: self.show_screen("ajustes"))

        panel = QFrame()
        panel.setObjectName("panel_usuarios")
        pl = QVBoxLayout(panel)
        pl.setContentsMargins(14, 14, 14, 14)
        pl.setSpacing(8)

        head_row = QHBoxLayout()
        lbl_users = QLabel("USUARIOS")
        lbl_users.setObjectName("lbl_usuarios")
        self.lbl_user_count = QLabel("0")
        self.lbl_user_count.setObjectName("hint_chat")
        head_row.addWidget(lbl_users)
        head_row.addStretch()
        head_row.addWidget(self.lbl_user_count)
        pl.addLayout(head_row)

        self.list_usuarios = QListWidget()
        self.list_usuarios.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        pl.addWidget(self.list_usuarios, stretch=1)

        self.btn_desconectar = QPushButton("DESCONECTAR")
        self.btn_desconectar.setObjectName("btn_desconectar")
        self.btn_desconectar.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_desconectar.clicked.connect(self.on_desconectar)

        self.btn_admin = QPushButton("ADMINISTRAR SALA")
        self.btn_admin.setObjectName("btn_accion")
        self.btn_admin.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_admin.clicked.connect(self.on_admin_open)
        self.btn_admin.hide()

        il.addWidget(self.btn_chat_ajustes)
        il.addWidget(panel, stretch=1)
        il.addWidget(self.btn_admin)
        il.addWidget(self.btn_desconectar)
        lay.addWidget(izq)

        # Columna derecha
        der = QFrame()
        dl = QVBoxLayout(der)
        dl.setContentsMargins(0, 0, 0, 0)
        dl.setSpacing(12)

        hrow = QHBoxLayout()
        self.btn_chat_servidores = QPushButton("SERVIDORES")
        self.btn_chat_servidores.setObjectName("btn_chat_servidores")
        self.btn_chat_servidores.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_chat_servidores.clicked.connect(lambda: self.show_screen("servidores"))
        hrow.addWidget(self.btn_chat_servidores)
        hrow.addStretch()

        self.lbl_latency = QLabel("")
        self.lbl_latency.setObjectName("hint_chat")
        hrow.addWidget(self.lbl_latency)

        self.frame_nametag = QFrame()
        self.frame_nametag.setObjectName("frame_nametag")
        self.frame_nametag.setCursor(Qt.CursorShape.PointingHandCursor)
        self.frame_nametag.setFixedHeight(52)
        self.frame_nametag.setMinimumWidth(170)
        nl = QHBoxLayout(self.frame_nametag)
        nl.setContentsMargins(10, 6, 14, 6)
        nl.setSpacing(8)
        self.lbl_avatar = QLabel("U")
        self.lbl_avatar.setObjectName("avatar")
        self.lbl_avatar.setFixedSize(28, 28)
        self.lbl_avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_nametag = QLabel("nametag")
        self.lbl_nametag.setObjectName("lbl_nametag")
        nl.addWidget(self.lbl_avatar)
        nl.addWidget(self.lbl_nametag)
        self.frame_nametag.mouseDoubleClickEvent = self._edit_nametag
        self.frame_nametag.setToolTip("Doble clic para cambiar tu nombre")
        hrow.addWidget(self.frame_nametag)
        dl.addLayout(hrow)

        # Área del chat
        self.chat_scroll = QScrollArea()
        self.chat_scroll.setWidgetResizable(True)
        self.chat_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.chat_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.chat_scroll.viewport().setAutoFillBackground(False)

        self.chat_area = QFrame()
        self.chat_area.setObjectName("area_chat")
        self.chat_area.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.chat_area.setAcceptDrops(True)
        self.chat_area.installEventFilter(self)
        self.chat_lay = QVBoxLayout(self.chat_area)
        self.chat_lay.setContentsMargins(18, 18, 18, 18)
        self.chat_lay.setSpacing(10)
        self.chat_lay.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.empty_widget = QWidget()
        el = QVBoxLayout(self.empty_widget)
        el.setAlignment(Qt.AlignmentFlag.AlignCenter)
        el.setSpacing(6)
        et = QLabel("Chat")
        et.setObjectName("chat_title")
        et.setAlignment(Qt.AlignmentFlag.AlignCenter)
        eh = QLabel("Conéctate a una sala para empezar a escribir.")
        eh.setObjectName("hint_chat")
        eh.setAlignment(Qt.AlignmentFlag.AlignCenter)
        el.addWidget(et)
        el.addWidget(eh)
        el.addSpacing(10)
        eb = QPushButton("Ir a servidores")
        eb.setObjectName("btn_accion")
        eb.setCursor(Qt.CursorShape.PointingHandCursor)
        eb.clicked.connect(lambda: self.show_screen("servidores"))
        el.addWidget(eb, alignment=Qt.AlignmentFlag.AlignCenter)
        self.chat_lay.addWidget(self.empty_widget, stretch=1)

        self.chat_scroll.setWidget(self.chat_area)
        dl.addWidget(self.chat_scroll, stretch=1)

        # Barra de respuesta
        self.reply_bar = QFrame()
        self.reply_bar.setObjectName("panel")
        rl = QHBoxLayout(self.reply_bar)
        rl.setContentsMargins(10, 6, 10, 6)
        rl.setSpacing(8)
        self.lbl_reply = QLabel("")
        self.lbl_reply.setObjectName("hint_chat")
        self.lbl_reply.setWordWrap(True)
        btn_reply_cancel = QPushButton("✕")
        btn_reply_cancel.setObjectName("fmt_btn")
        btn_reply_cancel.setFixedSize(28, 26)
        btn_reply_cancel.setToolTip("Cancelar respuesta")
        btn_reply_cancel.setAccessibleName("Cancelar respuesta")
        btn_reply_cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_reply_cancel.clicked.connect(self._clear_reply)
        rl.addWidget(self.lbl_reply, stretch=1)
        rl.addWidget(btn_reply_cancel)
        self.reply_bar.hide()
        dl.addWidget(self.reply_bar)

        # Barra de formato
        fmt = QHBoxLayout()
        fmt.setSpacing(6)
        fmt_label = QLabel("Formato")
        fmt_label.setObjectName("hint_chat")
        fmt.addWidget(fmt_label)
        for label, marker, tip in (
            ("B", "**", "Negrita"),
            ("I", "*", "Cursiva"),
            ("</>", "`", "Código"),
        ):
            b = QPushButton(label)
            b.setObjectName("fmt_btn")
            b.setFixedSize(40, 30)
            b.setToolTip(f"{tip}: selecciona texto y pulsa este botón")
            b.setAccessibleName(tip)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            if label == "B":
                f = QFont()
                f.setBold(True)
                b.setFont(f)
            elif label == "I":
                f = QFont()
                f.setItalic(True)
                b.setFont(f)
            else:
                b.setFont(QFont("Consolas", 9))
            b.clicked.connect(lambda _=False, m=marker: self._wrap_selection(m))
            fmt.addWidget(b)
        fmt.addSpacing(8)
        self.btn_attach = QPushButton("📎")
        self.btn_attach.setObjectName("fmt_btn")
        self.btn_attach.setFixedSize(40, 30)
        self.btn_attach.setToolTip("Adjuntar archivo")
        self.btn_attach.setAccessibleName("Adjuntar archivo")
        self.btn_attach.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_attach.clicked.connect(self.on_attach_file)
        fmt.addWidget(self.btn_attach)
        self.btn_emoji = QPushButton("😊")
        self.btn_emoji.setObjectName("fmt_btn")
        self.btn_emoji.setFixedSize(40, 30)
        self.btn_emoji.setToolTip("Insertar emoji")
        self.btn_emoji.setAccessibleName("Insertar emoji")
        self.btn_emoji.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_emoji.clicked.connect(self._show_emoji_picker)
        fmt.addWidget(self.btn_emoji)
        fmt.addStretch()
        fmt_hint = QLabel(
            "Clic derecho en un mensaje: responder o reaccionar · Ctrl+R responde al último"
        )
        fmt_hint.setObjectName("hint_chat")
        fmt.addWidget(fmt_hint)
        dl.addLayout(fmt)

        # Entrada
        row = QHBoxLayout()
        row.setSpacing(10)
        self.txt_input = QLineEdit()
        self.txt_input.setObjectName("barra_texto")
        self.txt_input.setPlaceholderText("Escribe un mensaje y pulsa Enter…")
        self.txt_input.returnPressed.connect(self.on_send_message)
        self.txt_input.installEventFilter(self)
        self.btn_send = QPushButton("➤")
        self.btn_send.setObjectName("btn_send")
        self.btn_send.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_send.setFixedSize(46, 46)
        self.btn_send.setToolTip("Enviar mensaje (Enter)")
        self.btn_send.clicked.connect(self.on_send_message)
        row.addWidget(self.txt_input, stretch=1)
        row.addWidget(self.btn_send)
        dl.addLayout(row)

        lay.addWidget(der, stretch=1)
        return page

    # ── Pantalla: AJUSTES ───────────────────────────────────────────────────
    def _build_ajustes(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(2, 2, 2, 2)
        lay.setSpacing(10)

        self.btn_volver = QPushButton("VOLVER")
        self.btn_volver.setObjectName("btn_volver")
        self.btn_volver.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_volver.clicked.connect(self.on_volver)
        lay.addWidget(self.btn_volver, alignment=Qt.AlignmentFlag.AlignLeft)

        content = QHBoxLayout()
        content.setSpacing(32)

        # Menú izquierdo
        menu = QFrame()
        menu.setFixedWidth(220)
        ml = QVBoxLayout(menu)
        ml.setContentsMargins(0, 6, 0, 0)
        ml.setSpacing(4)

        self.menu_group = QButtonGroup(self)
        self.menu_group.setExclusive(True)
        self.menu_buttons = []
        for i, text in enumerate(["Gráficos", "Privacidad", "Otros"]):
            b = QPushButton(text)
            b.setObjectName("menu_btn")
            b.setCheckable(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(lambda _=False, idx=i: self.right_stack.setCurrentIndex(idx))
            self.menu_group.addButton(b, i)
            self.menu_buttons.append(b)
            ml.addWidget(b)
        self.menu_buttons[0].setChecked(True)
        ml.addStretch()
        content.addWidget(menu)

        # Panel derecho
        self.right_stack = QStackedWidget()

        # — Gráficos —
        g = QWidget()
        gl = QVBoxLayout(g)
        gl.setContentsMargins(0, 6, 0, 0)
        gl.setSpacing(16)

        row1 = QHBoxLayout()
        row1.setSpacing(14)
        l1 = QLabel("Tema")
        l1.setObjectName("lbl_field")
        l1.setFixedWidth(110)
        self.combo_tema = QComboBox()
        self.combo_tema.addItems(THEMES)
        self.combo_tema.setCurrentText(self.settings.get("theme", "claro"))
        self.combo_tema.setMinimumWidth(220)
        row1.addWidget(l1)
        row1.addWidget(self.combo_tema)
        row1.addStretch()
        gl.addLayout(row1)

        row2 = QHBoxLayout()
        row2.setSpacing(14)
        l2 = QLabel("Caligrafía")
        l2.setObjectName("lbl_field")
        l2.setFixedWidth(110)
        self.combo_font = QComboBox()
        self.combo_font.addItems(CHAT_FONTS)
        self.combo_font.setCurrentText(self.settings.get("font", "Arial"))
        self.combo_font.setMinimumWidth(220)
        row2.addWidget(l2)
        row2.addWidget(self.combo_font)
        row2.addStretch()
        gl.addLayout(row2)

        self.btn_aplicar = QPushButton("Aplicar cambios")
        self.btn_aplicar.setObjectName("btn_aplicar")
        self.btn_aplicar.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_aplicar.clicked.connect(self.on_aplicar)
        gl.addWidget(self.btn_aplicar, alignment=Qt.AlignmentFlag.AlignLeft)
        gl.addStretch()
        self.right_stack.addWidget(g)

        # — Privacidad —
        p = QWidget()
        pl = QVBoxLayout(p)
        pl.setContentsMargins(0, 6, 0, 0)
        pl.setSpacing(14)
        p_info = QLabel("Tus mensajes se cifran con Fernet antes de salir del equipo.")
        p_info.setObjectName("hint_chat")
        p_info.setWordWrap(True)
        pl.addWidget(p_info)

        ttl_row = QHBoxLayout()
        ttl_row.setSpacing(12)
        ttl_label = QLabel("Mensajes efímeros")
        ttl_label.setObjectName("lbl_field")
        ttl_label.setFixedWidth(160)
        self.combo_ttl = QComboBox()
        for text, seconds in (
            ("Desactivado", 0), ("30 segundos", 30), ("5 minutos", 300),
            ("1 hora", 3600), ("24 horas", 86400),
        ):
            self.combo_ttl.addItem(text, seconds)
        current_ttl = int(self.settings.get("ttl_seconds", 0) or 0)
        index = self.combo_ttl.findData(current_ttl)
        self.combo_ttl.setCurrentIndex(index if index >= 0 else 0)
        self.combo_ttl.currentIndexChanged.connect(self._on_ttl_changed)
        ttl_row.addWidget(ttl_label)
        ttl_row.addWidget(self.combo_ttl)
        ttl_row.addStretch()
        pl.addLayout(ttl_row)

        files_row = QHBoxLayout()
        files_row.setSpacing(12)
        files_label = QLabel("Borrar archivos")
        files_label.setObjectName("lbl_field")
        files_label.setFixedWidth(160)
        self.combo_files = QComboBox()
        for text, days in (
            ("Nunca", 0), ("1 día", 1), ("7 días", 7), ("30 días", 30),
        ):
            self.combo_files.addItem(text, days)
        current_days = int(self.settings.get("file_ttl_days", 7) or 0)
        file_index = self.combo_files.findData(current_days)
        self.combo_files.setCurrentIndex(file_index if file_index >= 0 else 0)
        self.combo_files.currentIndexChanged.connect(self._on_file_ttl_changed)
        files_row.addWidget(files_label)
        files_row.addWidget(self.combo_files)
        files_row.addStretch()
        pl.addLayout(files_row)

        self.chk_auto_delete_downloads = QCheckBox(
            "Borrar también las copias descargadas"
        )
        self.chk_auto_delete_downloads.setChecked(
            self.settings.get("auto_delete_downloads", True)
        )
        self.chk_auto_delete_downloads.toggled.connect(
            self._on_auto_delete_downloads_toggled
        )
        pl.addWidget(self.chk_auto_delete_downloads)

        files_hint = QLabel(
            "Los archivos online se borran de Supabase cuando el emisor vuelva "
            "a abrir la app después del plazo. Las copias locales se borran de "
            "Descargas\\ChatWiFi."
        )
        files_hint.setObjectName("hint_chat")
        files_hint.setWordWrap(True)
        pl.addWidget(files_hint)

        self.chk_notifications = QCheckBox("Mostrar notificaciones nativas")
        self.chk_notifications.setChecked(
            self.settings.get("native_notifications", True)
        )
        self.chk_notifications.toggled.connect(self._on_notifications_toggled)
        pl.addWidget(self.chk_notifications)

        self.chk_read = QCheckBox("Compartir confirmaciones de leído")
        self.chk_read.setChecked(self.settings.get("read_receipts", True))
        self.chk_read.toggled.connect(self._on_read_toggled)
        pl.addWidget(self.chk_read)

        self.chk_capture = QCheckBox("Protegerme contra capturas de pantalla")
        self.chk_capture.setChecked(self.settings.get("screenshot_protection", False))
        self.chk_capture.toggled.connect(self._on_capture_toggled)
        pl.addWidget(self.chk_capture)

        remote_row = QHBoxLayout()
        remote_row.setSpacing(12)
        remote_label = QLabel("Comandos remotos")
        remote_label.setObjectName("lbl_field")
        remote_label.setFixedWidth(160)
        self.combo_remote = QComboBox()
        self.combo_remote.addItem("Permitir sin preguntar", "allow")
        self.combo_remote.addItem("Preguntar antes de ejecutar", "ask")
        self.combo_remote.addItem("Ignorar siempre (no ejecutar)", "ignore")
        policy = self.settings.get("remote_command_policy", "allow")
        remote_index = self.combo_remote.findData(policy)
        self.combo_remote.setCurrentIndex(
            remote_index if remote_index >= 0 else 0
        )
        self.combo_remote.currentIndexChanged.connect(
            self._on_remote_policy_changed
        )
        remote_row.addWidget(remote_label)
        remote_row.addWidget(self.combo_remote)
        remote_row.addStretch()
        pl.addLayout(remote_row)

        remote_hint = QLabel(
            "Permitir ejecuta sin ventana; Preguntar pide permiso; "
            "Ignorar descarta el comando. Hay un cooldown de 30 segundos."
        )
        remote_hint.setObjectName("hint_chat")
        remote_hint.setWordWrap(True)
        pl.addWidget(remote_hint)

        self.btn_limpiar = QPushButton("Limpiar conversación")
        self.btn_limpiar.setObjectName("btn_accion")
        self.btn_limpiar.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_limpiar.clicked.connect(self.clear_chat)
        pl.addWidget(self.btn_limpiar, alignment=Qt.AlignmentFlag.AlignLeft)

        self.btn_panic = QPushButton("Borrar todo y cerrar")
        self.btn_panic.setObjectName("btn_volver")
        self.btn_panic.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_panic.clicked.connect(self.on_panic)
        pl.addWidget(self.btn_panic, alignment=Qt.AlignmentFlag.AlignLeft)
        pl.addStretch()
        self.right_stack.addWidget(p)

        # — Otros —
        o = QWidget()
        ol = QVBoxLayout(o)
        ol.setContentsMargins(0, 6, 0, 0)
        ol.setSpacing(14)
        on = QLabel("Nombre de usuario")
        on.setObjectName("lbl_field")
        ol.addWidget(on)
        self.txt_username = QLineEdit()
        self.txt_username.setText(self.settings.get("username", "Usuario"))
        self.txt_username.setMaximumWidth(320)
        ol.addWidget(self.txt_username)
        self.btn_guardar_nombre = QPushButton("Guardar nombre")
        self.btn_guardar_nombre.setObjectName("btn_accion")
        self.btn_guardar_nombre.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_guardar_nombre.clicked.connect(self.on_save_username)
        ol.addWidget(self.btn_guardar_nombre, alignment=Qt.AlignmentFlag.AlignLeft)
        ver = QLabel(f"{APP_NAME} v{APP_VERSION}  ·  Puerto TCP {PORT}")
        ver.setObjectName("version_label")
        ol.addWidget(ver)

        self.chk_auto_update = QCheckBox("Buscar actualizaciones al iniciar")
        self.chk_auto_update.setChecked(self.settings.get("auto_check_updates", True))
        self.chk_auto_update.toggled.connect(self._on_auto_update_toggled)
        ol.addWidget(self.chk_auto_update)

        self.lbl_update_status = QLabel("")
        self.lbl_update_status.setObjectName("hint_chat")
        self.lbl_update_status.setWordWrap(True)
        ol.addWidget(self.lbl_update_status)

        self.btn_check_updates = QPushButton("Buscar actualizaciones")
        self.btn_check_updates.setObjectName("btn_accion")
        self.btn_check_updates.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_check_updates.clicked.connect(lambda: self.check_updates(manual=True))
        ol.addWidget(self.btn_check_updates, alignment=Qt.AlignmentFlag.AlignLeft)
        ol.addStretch()
        self.right_stack.addWidget(o)

        content.addWidget(self.right_stack, stretch=1)
        lay.addLayout(content, stretch=1)

        big = QLabel("AJUSTES")
        big.setObjectName("big_title")
        big.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(big)
        return page

    # ══════════════════════════════════════════════════════════════════════════
    # ACTUALIZACIONES (GitHub Releases)
    # ══════════════════════════════════════════════════════════════════════════
    @staticmethod
    def _version_key(version: str) -> tuple:
        return tuple(int(n) for n in re.findall(r"\d+", str(version))[:4])

    def _on_auto_update_toggled(self, checked: bool):
        self.settings["auto_check_updates"] = bool(checked)
        save_settings(self.settings)

    def check_updates(self, manual: bool = False):
        if self._update_reply is not None:
            return
        if not UPDATE_REPO or "/" not in UPDATE_REPO:
            self.lbl_update_status.setText("Actualizaciones no configuradas.")
            return
        self._manual_update_check = manual
        self.btn_check_updates.setEnabled(False)
        self.lbl_update_status.setText("Buscando actualizaciones…")
        request = QNetworkRequest(QUrl(UPDATE_MANIFEST_URL))
        request.setRawHeader(b"User-Agent", f"ChatWiFi/{APP_VERSION}".encode("ascii"))
        request.setRawHeader(b"Cache-Control", b"no-cache")
        request.setAttribute(
            QNetworkRequest.Attribute.RedirectPolicyAttribute,
            QNetworkRequest.RedirectPolicy.NoLessSafeRedirectPolicy,
        )
        reply = self._update_manager.get(request)
        self._update_reply = reply
        reply.finished.connect(lambda: self._on_update_check_finished(reply))

    def _on_update_check_finished(self, reply):
        if reply is not self._update_reply:
            return
        self._update_reply = None
        self.btn_check_updates.setEnabled(True)
        manual = self._manual_update_check
        self._manual_update_check = False
        status = reply.attribute(QNetworkRequest.Attribute.HttpStatusCodeAttribute)
        raw = bytes(reply.readAll())
        err = reply.error()
        err_text = reply.errorString()
        reply.deleteLater()

        if err != QNetworkReply.NetworkError.NoError:
            if status == 404:
                message = "Todavía no hay actualizaciones publicadas en GitHub."
            else:
                message = f"No se pudo comprobar la actualización: {err_text}"
            self.lbl_update_status.setText(message)
            if manual:
                QMessageBox.information(self, "Actualizaciones", message)
            return

        try:
            info = json.loads(raw.decode("utf-8-sig"))
            remote = str(info.get("version", "")).strip()
            if not remote:
                raise ValueError("Falta el campo version.")
        except Exception as exc:
            message = f"Respuesta de actualización no válida: {exc}"
            self.lbl_update_status.setText(message)
            if manual:
                QMessageBox.warning(self, "Actualizaciones", message)
            return

        if self._version_key(remote) > self._version_key(APP_VERSION):
            self.lbl_update_status.setText(f"Actualización disponible: v{remote}")
            notes = str(info.get("notes", "")).strip()
            text = f"Hay una nueva versión: v{remote}"
            if notes:
                text += f"\n\n{notes}"
            text += "\n\n¿Descargarla e instalarla ahora?"
            answer = QMessageBox.question(
                self,
                "Actualización disponible",
                text,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes,
            )
            if answer == QMessageBox.StandardButton.Yes:
                self._start_update_download(info)
        else:
            message = f"Estás en la última versión (v{APP_VERSION})."
            self.lbl_update_status.setText(message)
            if manual:
                QMessageBox.information(self, "Actualizaciones", message)

    def _start_update_download(self, info: dict):
        if self._update_reply is not None:
            return
        url = str(info.get("url", "")).strip()
        if not url:
            QMessageBox.warning(
                self, "Actualización",
                "El manifiesto no incluye la URL del instalador.",
            )
            return
        if not (
            url.lower().startswith("https://")
            or url.lower().startswith("http://127.0.0.1")
            or url.lower().startswith("http://localhost")
        ):
            QMessageBox.warning(
                self, "Actualización",
                "La URL del instalador debe usar HTTPS.",
            )
            return
        if not str(info.get("sha256", "")).strip():
            QMessageBox.warning(
                self, "Actualización",
                "El manifiesto no incluye el SHA-256 del instalador.",
            )
            return

        version = re.sub(r"[^0-9A-Za-z._-]", "_", str(info.get("version", "nueva")))
        dest = Path(tempfile.gettempdir()) / f"ChatWiFi_Setup_{version}.exe"
        part = dest.with_name(dest.name + ".part")
        try:
            self._update_file = open(part, "wb")
        except Exception as exc:
            QMessageBox.warning(
                self, "Actualización", f"No se pudo crear el archivo temporal: {exc}"
            )
            return

        self._update_info = info
        self._update_dest = dest
        self._update_part = part
        self._update_cancelled = False

        dialog = QProgressDialog(
            "Descargando actualización…", "Cancelar", 0, 100, self
        )
        dialog.setWindowTitle("Actualizando Chat WiFi")
        dialog.setWindowModality(Qt.WindowModality.WindowModal)
        dialog.setMinimumDuration(0)
        dialog.setAutoClose(False)
        dialog.setAutoReset(False)
        dialog.canceled.connect(self._cancel_update_download)
        self._update_dialog = dialog
        dialog.show()

        request = QNetworkRequest(QUrl(url))
        request.setRawHeader(b"User-Agent", f"ChatWiFi/{APP_VERSION}".encode("ascii"))
        request.setAttribute(
            QNetworkRequest.Attribute.RedirectPolicyAttribute,
            QNetworkRequest.RedirectPolicy.NoLessSafeRedirectPolicy,
        )
        reply = self._update_manager.get(request)
        self._update_reply = reply
        reply.readyRead.connect(lambda: self._write_update_chunk(reply))
        reply.downloadProgress.connect(self._on_update_download_progress)
        reply.finished.connect(lambda: self._on_update_download_finished(reply))

    def _write_update_chunk(self, reply):
        if reply is not self._update_reply or self._update_file is None:
            return
        data = reply.readAll()
        if data:
            try:
                self._update_file.write(bytes(data))
            except Exception:
                pass

    def _on_update_download_progress(self, received: int, total: int):
        if self._update_dialog is None:
            return
        if total > 0:
            self._update_dialog.setMaximum(100)
            self._update_dialog.setValue(int(received * 100 / total))
        else:
            self._update_dialog.setMaximum(0)

    def _cancel_update_download(self):
        self._update_cancelled = True
        if self._update_reply is not None:
            try:
                self._update_reply.abort()
            except Exception:
                pass
        self.lbl_update_status.setText("Descarga cancelada.")

    def _close_update_dialog(self):
        dialog = self._update_dialog
        self._update_dialog = None
        if dialog is not None:
            try:
                dialog.canceled.disconnect(self._cancel_update_download)
            except Exception:
                pass
            try:
                dialog.close()
                dialog.deleteLater()
            except Exception:
                pass

    def _cleanup_update_files(self):
        if self._update_file is not None:
            try:
                self._update_file.close()
            except Exception:
                pass
            self._update_file = None
        for path in (self._update_part, self._update_dest):
            if path is not None:
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass
        self._update_part = None
        self._update_dest = None

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _on_update_download_finished(self, reply):
        if reply is not self._update_reply:
            return
        self._update_reply = None
        err = reply.error()
        err_text = reply.errorString()
        reply.deleteLater()

        if self._update_file is not None:
            try:
                self._update_file.close()
            except Exception:
                pass
            self._update_file = None

        self._close_update_dialog()

        if self._update_cancelled:
            self._cleanup_update_files()
            return
        if err != QNetworkReply.NetworkError.NoError:
            self._cleanup_update_files()
            message = f"No se pudo descargar la actualización: {err_text}"
            self.lbl_update_status.setText(message)
            QMessageBox.warning(self, "Actualización", message)
            return

        part = self._update_part
        dest = self._update_dest
        info = self._update_info
        if part is None or dest is None:
            self._cleanup_update_files()
            return

        expected = str(info.get("sha256", "")).strip().lower()
        if expected:
            actual = self._sha256_file(part)
            if actual != expected:
                self._cleanup_update_files()
                message = (
                    "El instalador descargado no coincide con el SHA-256 publicado. "
                    "Se canceló la actualización por seguridad."
                )
                self.lbl_update_status.setText(message)
                QMessageBox.critical(self, "Actualización", message)
                return

        try:
            part.replace(dest)
        except Exception as exc:
            self._cleanup_update_files()
            message = f"No se pudo preparar el instalador: {exc}"
            self.lbl_update_status.setText(message)
            QMessageBox.warning(self, "Actualización", message)
            return

        self._update_part = None
        self.lbl_update_status.setText(
            f"Actualización v{info.get('version', '')} descargada."
        )
        answer = QMessageBox.question(
            self,
            "Actualización lista",
            (
                f"Se descargó Chat WiFi v{info.get('version', '')}.\n\n"
                "La app se cerrará y el instalador la actualizará. "
                "¿Instalar ahora?"
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if answer == QMessageBox.StandardButton.Yes:
            self._install_update()
        else:
            self.lbl_update_status.setText(
                f"Instalador guardado en: {dest}"
            )

    def _install_update(self):
        path = self._update_dest
        if path is None or not path.exists():
            QMessageBox.warning(
                self, "Actualización", "No se encontró el instalador descargado."
            )
            return
        try:
            subprocess.Popen(
                [str(path), "/SILENT", "/CLOSEAPPLICATIONS"],
                close_fds=True,
            )
        except Exception as exc:
            QMessageBox.critical(
                self, "Actualización", f"No se pudo iniciar el instalador: {exc}"
            )
            return
        self.statusBar().showMessage("Instalando actualización…", 0)
        QTimer.singleShot(900, QApplication.instance().quit)


    # ══════════════════════════════════════════════════════════════════════════
    # SEÑALES
    # ══════════════════════════════════════════════════════════════════════════
    def _connect_signals(self):
        self.btn_nav_servidores.clicked.connect(lambda: self.show_screen("servidores"))
        self.btn_nav_chat.clicked.connect(lambda: self.show_screen("chat"))
        self.btn_nav_ajustes.clicked.connect(lambda: self.show_screen("ajustes"))

        n = self.network
        n.message_received.connect(self.on_message_received)
        n.reaction_received.connect(self.on_reaction_received)
        n.read_received.connect(self.on_read_received)
        n.latency_received.connect(self.on_latency)
        n.system_message.connect(self.on_system_message)
        n.connection_status.connect(self.on_connection_status)
        n.user_list_updated.connect(self.on_user_list)
        n.file_received.connect(self.on_file_received)
        n.error_occurred.connect(self.on_error)
        n.servers_found.connect(self.on_servers_found)
        n.host_started.connect(self.on_host_started)
        n.screamer_requested.connect(self.on_screamer)
        n.command_requested.connect(self.on_command_requested)

        s = self.supabase
        s.connected.connect(self.on_online_connected)
        s.status_changed.connect(self.on_online_status)
        s.message_received.connect(self.on_message_received)
        s.reaction_received.connect(self.on_reaction_received)
        s.read_received.connect(self.on_read_received)
        s.latency_received.connect(self.on_latency)
        s.command_received.connect(self.on_online_command)
        s.system_message.connect(self.on_system_message)
        s.user_list_updated.connect(self.on_user_list)
        s.error_occurred.connect(self.on_online_error)
        s.room_created.connect(self.on_online_room_created)
        s.waiting_approval.connect(self.on_waiting_approval)
        s.room_ready.connect(self.on_room_ready)
        s.admin_updated.connect(self.on_admin_updated)
        s.session_updated.connect(self.on_session_updated)
        s.kicked.connect(self.on_kicked)
        s.room_closed.connect(self.on_room_closed)
        s.file_sent.connect(self.on_file_sent)
        s.file_received.connect(self.on_file_received_online)
        s.file_downloaded.connect(self.on_file_downloaded)
        s.file_error.connect(self.on_file_error)
        s.file_delete_result.connect(self.on_file_delete_result)

    # ══════════════════════════════════════════════════════════════════════════
    # TEMA / NAVEGACIÓN
    # ══════════════════════════════════════════════════════════════════════════
    def apply_theme(self, theme_name: str):
        if self._css:
            self.setStyleSheet(filter_css_for_theme(self._css, theme_name))
        chosen = self.settings.get("font", "Arial")
        self.chat_area.setFont(QFont(chosen, 10))
        self.txt_input.setFont(QFont(chosen, 10))

    def show_screen(self, name: str):
        idx = {"servidores": 0, "chat": 1, "ajustes": 2}[name]
        if name == "ajustes":
            cur = self.stack.currentIndex()
            if cur != 2:
                self.previous_screen = cur
        self.stack.setCurrentIndex(idx)
        self._set_nav_active(idx)
        self.settings["last_screen"] = name
        save_settings(self.settings)

    def _set_nav_active(self, index: int):
        for i, b in enumerate(
            [self.btn_nav_servidores, self.btn_nav_chat, self.btn_nav_ajustes]
        ):
            b.setChecked(i == index)

    def on_volver(self):
        if self.previous_screen is not None:
            self.stack.setCurrentIndex(self.previous_screen)
            self._set_nav_active(self.previous_screen)
            self.settings["last_screen"] = ["servidores", "chat", "ajustes"][self.previous_screen]
        else:
            self.show_screen("chat")
        save_settings(self.settings)

    def _set_setting(self, key, value):
        self.settings[key] = value

    def on_aplicar(self):
        theme = self.combo_tema.currentText()
        font = self.combo_font.currentText()
        self.settings["theme"] = theme
        self.settings["font"] = font
        save_settings(self.settings)
        self.apply_theme(theme)
        self.statusBar().showMessage("Ajustes aplicados y guardados.", 4000)

    # ══════════════════════════════════════════════════════════════════════════
    # SERVIDORES
    # ══════════════════════════════════════════════════════════════════════════
    def on_host(self):
        if not self._check_secret():
            return
        if self.network.hosting:
            return
        if self.network.is_connected:
            QMessageBox.information(
                self, "Sala LAN",
                "Ya estás conectado a una sala LAN. Pulsa Cancelar o Desconectar antes de crear otra.",
            )
            return
        self._set_connection_mode("lan")
        self.mode = "lan"
        self.network.username = self.settings.get("username", "Usuario")
        self.network.auth_mode = self.combo_auth.currentText()
        self.network.shared_secret = self.txt_secret.text()
        self.btn_host.setEnabled(False)
        self.btn_host.setText("Creando sala…")
        self.lbl_host.setText("Abriendo el puerto LAN…")
        self.network.start_server()

    def on_host_started(self, ip: str):
        if not self.network.hosting:
            return
        self.btn_host.setEnabled(False)
        self.btn_host.setText("Sala activa")
        self.lbl_host.setText(f"Sala activa en {ip}:{PORT}")
        self.btn_buscar.setEnabled(False)
        self.btn_conectar.setEnabled(False)
        self.statusBar().showMessage(f"Sala creada. Comparte tu IP: {ip}", 0)

    # ── Modo LAN / Online ──────────────────────────────────────────────────
    def _set_connection_mode(self, mode: str):
        if mode == "online":
            self.btn_mode_online.setChecked(True)
            self.mode_stack.setCurrentIndex(1)
            if self.network.is_connected or self.network.hosting:
                self.network.disconnect()
            self.btn_buscar.setEnabled(False)
            self.btn_conectar.setEnabled(False)
        else:
            self.btn_mode_lan.setChecked(True)
            self.mode_stack.setCurrentIndex(0)
            if self.online_connected or self.mode == "online":
                self.supabase.leave()
                self.online_connected = False
            if not self.network.is_connected and not self.network.hosting:
                self.btn_buscar.setEnabled(True)
                self.btn_conectar.setEnabled(True)
        self.mode = mode
        self._refresh_chat_enabled()

    def on_online_create(self):
        if not self._check_secret():
            return
        if self.network.is_connected:
            self.network.disconnect()
        self._set_connection_mode("online")
        self.mode = "online"
        self.lbl_online_status.setText("Creando sala online…")
        self.statusBar().showMessage("Creando sala online…", 0)
        self.supabase.create_room(
            self.txt_secret.text(),
            self.settings.get("username", "Usuario"),
            approval_required=self.chk_approval.isChecked(),
            duration_hours=int(self.combo_duration.currentData() or 0),
        )

    def on_online_join(self):
        code = self.txt_room.text().strip().upper()
        if len(code) < 4:
            QMessageBox.warning(
                self, "Código requerido",
                "Escribe el código de la sala (por ejemplo, K7F2Q9).",
            )
            self.txt_room.setFocus()
            return
        if not self._check_secret():
            return
        if self.network.is_connected:
            self.network.disconnect()
        self._set_connection_mode("online")
        self.mode = "online"
        self.lbl_online_status.setText(f"Conectando a la sala {code}…")
        self.statusBar().showMessage(f"Conectando a la sala {code}…", 0)
        self.supabase.join_room(
            code,
            self.txt_secret.text(),
            self.settings.get("username", "Usuario"),
        )

    # ── Archivos ───────────────────────────────────────────────────────────
    def on_attach_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Adjuntar archivo")
        if path:
            self.on_send_file(path)

    def on_send_file(self, filepath: str):
        path = Path(filepath)
        if not path.is_file():
            return
        size = path.stat().st_size
        mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        if self.mode == "online":
            if not self.supabase.is_connected:
                self.statusBar().showMessage("No estás conectado a la sala online.", 4000)
                return
            if size > 45 * 1024 * 1024:
                QMessageBox.warning(
                    self, "Archivo demasiado grande",
                    "El límite para archivos online es de 45 MB.",
                )
                return
            self._show_file_progress("Subiendo archivo…")
            days = int(self.settings.get("file_ttl_days", 0) or 0)
            expires_at = (time.time() + days * 86400) if days > 0 else None
            self.supabase.send_file(str(path), expires_at=expires_at)
        else:
            if not self.network.is_connected:
                self.statusBar().showMessage("No estás conectado a ninguna sala.", 4000)
                return
            if size > MAX_FILE_SIZE:
                QMessageBox.warning(
                    self, "Archivo demasiado grande",
                    "El límite para LAN es de 10 MB.",
                )
                return
            self.network.send_file(str(path))
            self._add_file_bubble("Tú", {
                "id": proto.new_id(),
                "name": path.name,
                "size": size,
                "mime": mime,
                "storage_path": "",
            }, sent=True)

    def _show_file_progress(self, text: str):
        self._close_file_progress()
        dialog = QProgressDialog(text, "", 0, 0, self)
        dialog.setWindowTitle("Chat WiFi")
        dialog.setCancelButton(None)
        dialog.setMinimumDuration(0)
        dialog.setWindowModality(Qt.WindowModality.NonModal)
        dialog.show()
        self._file_progress = dialog

    def _close_file_progress(self):
        dialog = getattr(self, "_file_progress", None)
        if dialog is not None:
            dialog.close()
            dialog.deleteLater()
            self._file_progress = None

    @staticmethod
    def _format_size(size: int) -> str:
        if size < 1024:
            return f"{size} B"
        if size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        return f"{size / (1024 * 1024):.1f} MB"

    def on_file_sent(self, meta: dict):
        self._close_file_progress()
        self._queue_file_delete(
            meta.get("storage_path", ""), meta.get("expires_at")
        )
        self._add_file_bubble("Tú", meta, sent=True)
        self.statusBar().showMessage(f"Archivo enviado: {meta.get('name', '')}", 4000)

    def on_file_received_online(self, sender: str, meta: dict):
        self._notify_file(sender, meta.get("name", "Archivo"))
        self._add_file_bubble(sender, meta, sent=False)

    def _add_file_bubble(self, sender: str, meta: dict, sent: bool):
        mid = meta.get("id") or proto.new_id()
        if mid in self._seen_ids:
            return
        self._seen_ids.add(mid)
        self.empty_widget.hide()

        wrapper = QWidget()
        wrapper.setProperty("is_message", True)
        wrapper.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        wrapper._msg_id = mid
        wrapper._sender = sender
        wrapper._text = meta.get("name", "archivo")
        wrapper._sent = sent
        wrapper._file_meta = meta
        wrapper._downloaded_path = ""
        h = QHBoxLayout(wrapper)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)

        bubble = QFrame()
        bubble.setObjectName("burbuja_der" if sent else "burbuja_izq")
        bubble.setFixedWidth(360)
        bl = QVBoxLayout(bubble)
        bl.setContentsMargins(14, 10, 14, 10)
        bl.setSpacing(4)

        if not sent:
            who = QLabel(self._elide(sender, 28))
            who.setObjectName("bubble_sender")
            bl.addWidget(who)

        mime = meta.get("mime", "")
        icon = "🖼️" if mime.startswith("image/") else "📎"
        title = QLabel(f"{icon} {self._elide(meta.get('name', 'archivo'), 48)}")
        title.setObjectName("bubble_text")
        title.setWordWrap(True)
        title.setToolTip(meta.get("name", ""))
        bl.addWidget(title)

        size_label = QLabel(self._format_size(int(meta.get("size", 0))))
        size_label.setObjectName("bubble_time")
        bl.addWidget(size_label)

        preview = QLabel("")
        preview.setObjectName("hint_chat")
        preview.setAlignment(Qt.AlignmentFlag.AlignCenter)
        preview.setMaximumWidth(340)
        preview.hide()
        bl.addWidget(preview)

        button = QPushButton("Descargar")
        button.setObjectName("fmt_btn")
        button.setMinimumWidth(110)
        button.setFixedHeight(30)
        button.setCursor(Qt.CursorShape.PointingHandCursor)
        if sent:
            button.hide()
            status = QLabel("Enviado")
            status.setObjectName("bubble_time")
            bl.addWidget(status)
        else:
            bl.addWidget(button, alignment=Qt.AlignmentFlag.AlignLeft)

        wrapper._file_button = button
        wrapper._preview_label = preview

        if sent:
            h.addStretch(1)
            h.addWidget(bubble)
        else:
            h.addWidget(bubble)
            h.addStretch(1)

        self.chat_lay.insertWidget(self.chat_lay.count() - 1, wrapper)
        self._msg_widgets[mid] = wrapper

        local_path = meta.get("local_path")
        if local_path:
            wrapper._downloaded_path = local_path
            button.setText("Abrir")
            button.show()
            button.clicked.connect(
                lambda _=False, p=local_path: self._open_local_file(p)
            )
            self._show_image_preview(wrapper, local_path)
        elif not sent:
            button.clicked.connect(
                lambda _=False, m=meta, w=wrapper: self._download_file(m, w)
            )
            if mime.startswith("image/") and int(meta.get("size", 0)) < 8 * 1024 * 1024:
                QTimer.singleShot(400, lambda m=meta, w=wrapper: self._download_file(m, w))

        if not sent and self.settings.get("read_receipts", True):
            QTimer.singleShot(600, lambda m=mid: self._send_read(m))

        expires = meta.get("expires_at")
        if expires and not sent:
            if float(expires) <= time.time():
                button.setText("Expirado")
                button.setEnabled(False)
            else:
                delay = max(0, int((float(expires) - time.time()) * 1000))
                QTimer.singleShot(
                    delay,
                    lambda w=wrapper: self._expire_file_button(w),
                )

        QTimer.singleShot(50, self._scroll_bottom)

    @staticmethod
    def _expire_file_button(wrapper):
        if getattr(wrapper, "_downloaded_path", ""):
            return
        button = getattr(wrapper, "_file_button", None)
        if button is not None:
            button.setText("Expirado")
            button.setEnabled(False)

    def _download_file(self, meta: dict, wrapper: QWidget):
        if wrapper._downloaded_path:
            self._open_local_file(wrapper._downloaded_path)
            return
        self._pending_file_button = wrapper._file_button
        wrapper._file_button.setText("Descargando…")
        wrapper._file_button.setEnabled(False)
        self._show_file_progress("Descargando archivo…")
        self.supabase.download_file(
            meta.get("id", ""),
            meta.get("name", "archivo"),
            meta.get("storage_path", ""),
        )

    def _safe_download_dir(self) -> Path:
        base = QStandardPaths.writableLocation(
            QStandardPaths.StandardLocation.DownloadLocation
        )
        root = Path(base) if base else (Path.home() / "Downloads")
        target = root / "ChatWiFi"
        target.mkdir(parents=True, exist_ok=True)
        return target

    def _save_downloaded_file(self, name: str, data: bytes) -> Path:
        target_dir = self._safe_download_dir()
        safe_name = Path(name).name or "archivo"
        path = target_dir / safe_name
        if path.exists():
            stem, suffix = path.stem, path.suffix
            index = 1
            while path.exists():
                path = target_dir / f"{stem} ({index}){suffix}"
                index += 1
        path.write_bytes(data)
        return path

    def on_file_downloaded(self, request_id: str, name: str, data: object):
        self._close_file_progress()
        wrapper = self._msg_widgets.get(request_id)
        if wrapper is None:
            return
        try:
            raw = bytes(data)
        except Exception:
            self.on_file_error("No se pudo leer el archivo descargado.")
            return
        path = self._save_downloaded_file(name, raw)
        wrapper._downloaded_path = str(path)
        button = wrapper._file_button
        button.setText("Abrir")
        button.setEnabled(True)
        try:
            button.clicked.disconnect()
        except Exception:
            pass
        button.clicked.connect(lambda _=False, p=str(path): self._open_local_file(p))
        self._show_image_preview(wrapper, str(path))
        self.statusBar().showMessage(f"Archivo guardado en {path}", 6000)

    def _show_image_preview(self, wrapper: QWidget, path: str):
        meta = getattr(wrapper, "_file_meta", {})
        if not str(meta.get("mime", "")).startswith("image/"):
            return
        pix = QPixmap(path)
        if pix.isNull():
            return
        label = getattr(wrapper, "_preview_label", None)
        if label is None:
            return
        label.setPixmap(pix.scaled(
            320, 200,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        ))
        label.show()

    def _open_local_file(self, path: str):
        QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def on_file_error(self, message: str):
        self._close_file_progress()
        button = getattr(self, "_pending_file_button", None)
        if button is not None:
            try:
                button.setText("Descargar")
                button.setEnabled(True)
            except Exception:
                pass
            self._pending_file_button = None
        self.statusBar().showMessage(message, 6000)
        QMessageBox.warning(self, "Archivo", message)

    def _queue_file_delete(self, storage_path: str, expires_at):
        if not storage_path or not expires_at:
            return
        queue = self.settings.setdefault("pending_file_deletes", [])
        if not any(item.get("path") == storage_path for item in queue):
            queue.append({
                "path": storage_path,
                "expires_at": float(expires_at),
            })
            save_settings(self.settings)

    def _run_file_cleanup(self):
        try:
            self._cleanup_local_downloads()
        except Exception:
            pass
        try:
            self._cleanup_remote_files()
        except Exception:
            pass

    def _cleanup_local_downloads(self):
        if not self.settings.get("auto_delete_downloads", True):
            return
        days = int(self.settings.get("file_ttl_days", 0) or 0)
        if days <= 0:
            return
        cutoff = time.time() - days * 86400
        removed = 0
        target = self._safe_download_dir()
        for path in target.iterdir():
            if not path.is_file():
                continue
            try:
                if path.stat().st_mtime >= cutoff:
                    continue
                path.unlink()
                removed += 1
            except Exception:
                pass
        if removed:
            self.statusBar().showMessage(
                f"Se borraron {removed} archivo(s) descargado(s) antiguos.",
                5000,
            )

    def _cleanup_remote_files(self):
        queue = self.settings.get("pending_file_deletes", []) or []
        if not queue:
            return
        now = time.time()
        expired = [
            item.get("path", "")
            for item in queue
            if item.get("path") and float(item.get("expires_at", 0) or 0) <= now
        ]
        if not expired:
            return
        if not (
            self.settings.get("sb_access_token")
            or self.settings.get("sb_refresh_token")
        ):
            return
        self.supabase.delete_files(expired)

    def on_file_delete_result(self, storage_path: str, ok: bool, error: str):
        queue = self.settings.get("pending_file_deletes", []) or []
        if ok:
            self.settings["pending_file_deletes"] = [
                item for item in queue if item.get("path") != storage_path
            ]
            save_settings(self.settings)
            self.statusBar().showMessage(
                "Archivo antiguo borrado de Supabase.", 4000
            )
        else:
            self.statusBar().showMessage(
                f"No se pudo borrar un archivo antiguo: {error}", 6000
            )

    def eventFilter(self, obj, event):
        text_input = getattr(self, "txt_input", None)
        chat_area = getattr(self, "chat_area", None)
        if text_input is not None and obj is text_input and event.type() == QEvent.Type.KeyPress:
            if (
                event.key() == Qt.Key.Key_V
                and event.modifiers() & Qt.KeyboardModifier.ControlModifier
            ):
                image = QApplication.clipboard().image()
                if not image.isNull():
                    temp = Path(tempfile.gettempdir()) / f"pasted_{proto.new_id()}.png"
                    if image.save(str(temp), "PNG"):
                        self.on_send_file(str(temp))
                        return True
            if (
                event.key() == Qt.Key.Key_R
                and event.modifiers() & Qt.KeyboardModifier.ControlModifier
                and not event.modifiers() & Qt.KeyboardModifier.ShiftModifier
            ):
                if self._last_received:
                    self._reply_to = dict(self._last_received)
                    preview = self._elide(self._reply_to.get("text", ""), 70)
                    self.lbl_reply.setText(
                        f"Respondiendo a {self._reply_to.get('sender', '')}: {preview}"
                    )
                    self.reply_bar.show()
                    self.txt_input.setFocus()
                return True
        if chat_area is not None and obj is chat_area:
            if event.type() == QEvent.Type.DragEnter:
                if event.mimeData().hasUrls():
                    event.acceptProposedAction()
                    return True
            if event.type() == QEvent.Type.Drop:
                for url in event.mimeData().urls():
                    if url.isLocalFile():
                        self.on_send_file(url.toLocalFile())
                event.acceptProposedAction()
                return True
        return super().eventFilter(obj, event)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            if url.isLocalFile():
                self.on_send_file(url.toLocalFile())
        event.acceptProposedAction()

    def on_online_leave(self):
        self.supabase.leave()
        self.online_connected = False
        self.lbl_online_status.setText("Sin conexión")
        self.list_usuarios.clear()
        self.lbl_user_count.setText("0")
        self.btn_admin.hide()
        self._room_info = {}
        self._refresh_chat_enabled()
        self.statusBar().showMessage("Saliste de la sala online.", 4000)

    def on_online_check(self):
        request = QNetworkRequest(QUrl(SUPABASE_URL + "/auth/v1/health"))
        request.setRawHeader(b"apikey", SUPABASE_KEY.encode("ascii"))
        reply = self._preview_manager.get(request)
        self.lbl_online_status.setText("Comprobando Supabase…")

        def _done():
            try:
                status = reply.attribute(
                    QNetworkRequest.Attribute.HttpStatusCodeAttribute
                )
                if status is None:
                    detail = reply.errorString() or "sin respuesta"
                    message = (
                        f"No se pudo comprobar Supabase: {detail}. "
                        "Revisa tu conexión a Internet."
                    )
                elif status == 200:
                    message = "Supabase responde correctamente."
                else:
                    message = (
                        f"Supabase respondió {status}. Si el proyecto estuvo "
                        "7 días inactivo, restáuralo en el dashboard."
                    )
            except Exception:
                message = "No se pudo comprobar Supabase. Revisa la conexión."
            self.lbl_online_status.setText(message)
            self.statusBar().showMessage(message, 6000)
            reply.deleteLater()

        reply.finished.connect(_done)

    def on_waiting_approval(self, message: str):
        self.online_connected = False
        self.lbl_online_status.setText(message)
        self.statusBar().showMessage(message, 0)
        self._refresh_chat_enabled()

    def on_room_ready(self, info: dict):
        self._room_info = info
        expiry = self._format_expiry(info.get("expires_at"))
        text = f"Sala {info.get('code', '')} · {expiry}"
        self.lbl_online_status.setText(text)
        if info.get("is_admin"):
            self.btn_admin.show()
        else:
            self.btn_admin.hide()

    def on_session_updated(self, session: dict):
        self.settings["sb_access_token"] = session.get("access_token", "")
        self.settings["sb_refresh_token"] = session.get("refresh_token", "")
        self.settings["sb_user_id"] = session.get("user_id", "")
        self.settings["sb_expires_at"] = session.get("expires_at", 0.0)
        save_settings(self.settings)

    def on_kicked(self):
        self.online_connected = False
        self.btn_admin.hide()
        self.lbl_online_status.setText("Fuiste expulsado de la sala.")
        self.list_usuarios.clear()
        self.lbl_user_count.setText("0")
        self._refresh_chat_enabled()
        QMessageBox.warning(self, "Sala", "El administrador te expulsó de la sala.")
        self.show_screen("servidores")

    def on_room_closed(self):
        self.online_connected = False
        self.btn_admin.hide()
        self.lbl_online_status.setText("La sala fue cerrada.")
        self.list_usuarios.clear()
        self.lbl_user_count.setText("0")
        self._refresh_chat_enabled()
        self.show_screen("servidores")

    @staticmethod
    def _format_expiry(timestamp) -> str:
        if not timestamp:
            return "sin caducidad"
        try:
            return datetime.fromtimestamp(float(timestamp)).strftime("%d/%m/%Y %H:%M")
        except Exception:
            return "sin caducidad"

    # ── Administración de sala ─────────────────────────────────────────────
    def on_admin_open(self):
        if not self.supabase.is_admin:
            return
        if self._admin_dialog is not None and self._admin_dialog.isVisible():
            self._admin_dialog.raise_()
            return

        colors = self._admin_colors()
        dialog = QDialog(self)
        dialog.setObjectName("admin_dialog")
        dialog.setWindowTitle("Administrar sala")
        dialog.resize(820, 660)
        dialog.setMinimumSize(700, 540)
        dialog.setStyleSheet(self._admin_stylesheet(colors))

        outer = QVBoxLayout(dialog)
        outer.setContentsMargins(18, 18, 18, 18)
        outer.setSpacing(14)

        # Encabezado: sala, caducidad y contadores
        header = QFrame()
        header.setObjectName("admin_header")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(20, 16, 20, 16)
        hl.setSpacing(16)

        left = QVBoxLayout()
        left.setSpacing(2)
        kicker = QLabel("ADMINISTRAR SALA")
        kicker.setObjectName("admin_kicker")
        self.lbl_admin_room = QLabel("Sala ------")
        self.lbl_admin_room.setObjectName("admin_code")
        self.lbl_admin_info = QLabel("")
        self.lbl_admin_info.setObjectName("admin_sub")
        self.lbl_admin_info.setWordWrap(True)
        left.addWidget(kicker)
        left.addWidget(self.lbl_admin_room)
        left.addWidget(self.lbl_admin_info)
        hl.addLayout(left, 1)

        stats = QHBoxLayout()
        stats.setSpacing(10)
        self._admin_pending_stat, pending_stat = self._admin_stat("Pendientes")
        self._admin_members_stat, members_stat = self._admin_stat("Miembros")
        stats.addWidget(pending_stat)
        stats.addWidget(members_stat)
        hl.addLayout(stats)
        outer.addWidget(header)

        # Cuerpo: solicitudes y miembros
        body = QHBoxLayout()
        body.setSpacing(14)
        pending_panel, self._admin_pending_rows, self._admin_pending_badge = (
            self._admin_panel("Solicitudes")
        )
        members_panel, self._admin_members_rows, self._admin_members_badge = (
            self._admin_panel("Miembros")
        )
        body.addWidget(pending_panel, 1)
        body.addWidget(members_panel, 1)
        outer.addLayout(body, 1)

        # Pie de acciones
        footer = QHBoxLayout()
        footer.setSpacing(8)
        btn_refresh = QPushButton("Actualizar")
        btn_refresh.setObjectName("admin_refresh")
        btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_refresh.clicked.connect(lambda: self.supabase.refresh_admin())
        btn_close_room = QPushButton("Cerrar sala")
        btn_close_room.setObjectName("admin_danger")
        btn_close_room.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_close_room.clicked.connect(self.on_admin_close_room)
        btn_close = QPushButton("Cerrar ventana")
        btn_close.setObjectName("admin_close")
        btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_close.clicked.connect(dialog.close)
        footer.addWidget(btn_refresh)
        footer.addStretch(1)
        footer.addWidget(btn_close_room)
        footer.addWidget(btn_close)
        outer.addLayout(footer)

        self._admin_dialog = dialog

        def _admin_closed(_=0):
            self._admin_dialog = None
            dialog.deleteLater()

        dialog.finished.connect(_admin_closed)
        dialog.show()
        if self._admin_data:
            self._populate_admin(self._admin_data)
        self.supabase.refresh_admin()

    def on_admin_updated(self, data: dict):
        self._admin_data = data
        if self._admin_dialog is not None and self._admin_dialog.isVisible():
            self._populate_admin(data)

    def _populate_admin(self, data: dict):
        if not hasattr(self, "_admin_pending_rows"):
            return
        pending = data.get("pending", []) or []
        members = data.get("members", []) or []
        visible_members = [
            row for row in members
            if row.get("role") == "admin"
            or row.get("approved")
            or row.get("banned")
        ]

        self.lbl_admin_room.setText(f"Sala {data.get('code', '')}")
        self.lbl_admin_info.setText(
            f"Caduca: {self._format_expiry(data.get('expires_at'))}  ·  "
            "Tú eres el administrador"
        )
        self._admin_pending_stat.setText(str(len(pending)))
        self._admin_members_stat.setText(str(len(visible_members)))
        self._admin_pending_badge.setText(str(len(pending)))
        self._admin_members_badge.setText(str(len(visible_members)))

        self._admin_clear_rows(self._admin_pending_rows)
        if pending:
            for row in pending:
                name = row.get("display_name") or "Sin nombre"
                uid = row.get("user_id", "")
                frame = self._admin_make_row(
                    name,
                    "Esperando aprobación",
                    [
                        (
                            "Aprobar",
                            "admin_approve",
                            lambda _=False, u=uid: self.supabase.approve_member(u, True),
                        ),
                        (
                            "Rechazar",
                            "admin_reject",
                            lambda _=False, u=uid, n=name: self._admin_reject_member(u, n),
                        ),
                    ],
                )
                self._admin_pending_rows.addWidget(frame)
            self._admin_pending_rows.addStretch(1)
        else:
            self._admin_empty(
                self._admin_pending_rows,
                "No hay solicitudes pendientes.\nCuando alguien pida entrar, aparecerá aquí.",
            )

        self._admin_clear_rows(self._admin_members_rows)
        if visible_members:
            for row in visible_members:
                name = row.get("display_name") or "Sin nombre"
                uid = row.get("user_id", "")
                role = row.get("role", "")
                if role == "admin":
                    status = "Administrador · Tú"
                elif row.get("banned"):
                    status = "Bloqueado"
                elif not row.get("approved", True):
                    status = "Pendiente"
                else:
                    status = "Miembro"

                actions = []
                if role != "admin" and not row.get("banned"):
                    actions.append(
                        (
                            "Expulsar",
                            "admin_kick",
                            lambda _=False, u=uid, n=name: self._admin_kick_member(u, n),
                        )
                    )
                frame = self._admin_make_row(name, status, actions)
                self._admin_members_rows.addWidget(frame)
            self._admin_members_rows.addStretch(1)
        else:
            self._admin_empty(
                self._admin_members_rows,
                "Todavía no hay otros miembros.\nComparte el código para que entren.",
            )

    def _admin_colors(self) -> dict:
        theme = self.settings.get("theme", "claro")
        palettes = {
            "claro": dict(
                window="#eef2f7", panel="#ffffff", text="#0f172a", muted="#64748b",
                border="#e2e8f0", subtle="#f8fafc", row="#ffffff", accent="#6366f1",
                on_accent="#ffffff", success="#22c55e", on_success="#ffffff",
                danger="#ef4444", on_danger="#ffffff",
            ),
            "oscuro": dict(
                window="#0b1220", panel="#111827", text="#e5e7eb", muted="#94a3b8",
                border="#1f2937", subtle="#0f172a", row="#111827", accent="#818cf8",
                on_accent="#0b1220", success="#22c55e", on_success="#052e16",
                danger="#f87171", on_danger="#450a0a",
            ),
            "neon": dict(
                window="#07070d", panel="#0e0e18", text="#d1fff0", muted="#3fbf8f",
                border="#12332a", subtle="#0b0b14", row="#0e0e18", accent="#00ff9c",
                on_accent="#001a10", success="#00ff9c", on_success="#001a10",
                danger="#ff2e63", on_danger="#1a0006",
            ),
            "matrix": dict(
                window="#000000", panel="#030a03", text="#00ff41", muted="#00aa2b",
                border="#0a2a0a", subtle="#061006", row="#030a03", accent="#00ff41",
                on_accent="#001a00", success="#00ff41", on_success="#001a00",
                danger="#ff3131", on_danger="#1a0000",
            ),
        }
        return palettes.get(theme, palettes["claro"])

    @staticmethod
    def _admin_stylesheet(c: dict) -> str:
        return f"""
        QDialog#admin_dialog {{ background: {c['window']}; }}
        QFrame#admin_header {{
            background: {c['panel']};
            border: 1px solid {c['border']};
            border-radius: 18px;
        }}
        QLabel#admin_kicker {{
            color: {c['muted']};
            font-size: 10px;
            font-weight: 800;
        }}
        QLabel#admin_code {{
            color: {c['text']};
            font-size: 26px;
            font-weight: 900;
        }}
        QLabel#admin_sub {{
            color: {c['muted']};
            font-size: 12px;
        }}
        QFrame#admin_stat {{
            background: {c['subtle']};
            border: 1px solid {c['border']};
            border-radius: 12px;
        }}
        QLabel#admin_stat_num {{
            color: {c['text']};
            font-size: 20px;
            font-weight: 900;
        }}
        QLabel#admin_stat_lbl {{
            color: {c['muted']};
            font-size: 9px;
            font-weight: 800;
        }}
        QFrame#admin_panel {{
            background: {c['panel']};
            border: 1px solid {c['border']};
            border-radius: 16px;
        }}
        QLabel#admin_panel_title {{
            color: {c['text']};
            font-size: 14px;
            font-weight: 800;
        }}
        QLabel#admin_count {{
            background: {c['subtle']};
            color: {c['muted']};
            border-radius: 9px;
            padding: 2px 8px;
            font-size: 11px;
            font-weight: 800;
        }}
        QScrollArea#admin_scroll {{
            background: transparent;
            border: none;
        }}
        QWidget#admin_rows {{ background: transparent; }}
        QFrame#admin_row {{
            background: {c['row']};
            border: 1px solid {c['border']};
            border-radius: 12px;
        }}
        QLabel#admin_avatar {{
            background: {c['accent']};
            color: {c['on_accent']};
            border-radius: 17px;
            font-size: 14px;
            font-weight: 900;
        }}
        QLabel#admin_name {{
            color: {c['text']};
            font-size: 13px;
            font-weight: 800;
        }}
        QLabel#admin_meta {{
            color: {c['muted']};
            font-size: 11px;
        }}
        QLabel#admin_empty {{
            color: {c['muted']};
            font-size: 12px;
        }}
        QPushButton#admin_approve {{
            background: {c['success']};
            color: {c['on_success']};
            border: none;
            border-radius: 8px;
            padding: 5px 10px;
            font-size: 11px;
            font-weight: 800;
        }}
        QPushButton#admin_reject, QPushButton#admin_kick {{
            background: transparent;
            color: {c['danger']};
            border: 1px solid {c['danger']};
            border-radius: 8px;
            padding: 5px 10px;
            font-size: 11px;
            font-weight: 800;
        }}
        QPushButton#admin_reject:hover, QPushButton#admin_kick:hover {{
            background: {c['danger']};
            color: {c['on_danger']};
        }}
        QPushButton#admin_refresh {{
            background: {c['subtle']};
            color: {c['text']};
            border: 1px solid {c['border']};
            border-radius: 10px;
            padding: 8px 14px;
            font-weight: 700;
        }}
        QPushButton#admin_refresh:hover {{
            border-color: {c['accent']};
            color: {c['accent']};
        }}
        QPushButton#admin_danger {{
            background: {c['danger']};
            color: {c['on_danger']};
            border: none;
            border-radius: 10px;
            padding: 8px 16px;
            font-weight: 800;
        }}
        QPushButton#admin_close {{
            background: {c['subtle']};
            color: {c['text']};
            border: 1px solid {c['border']};
            border-radius: 10px;
            padding: 8px 18px;
            font-weight: 800;
        }}
        QPushButton#admin_close:hover {{
            border-color: {c['accent']};
            color: {c['accent']};
        }}
        """

    @staticmethod
    def _admin_clear_rows(layout):
        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

    def _admin_stat(self, label: str):
        frame = QFrame()
        frame.setObjectName("admin_stat")
        box = QVBoxLayout(frame)
        box.setContentsMargins(14, 6, 14, 6)
        box.setSpacing(0)
        number = QLabel("0")
        number.setObjectName("admin_stat_num")
        number.setAlignment(Qt.AlignmentFlag.AlignCenter)
        caption = QLabel(label.upper())
        caption.setObjectName("admin_stat_lbl")
        caption.setAlignment(Qt.AlignmentFlag.AlignCenter)
        box.addWidget(number)
        box.addWidget(caption)
        return number, frame

    def _admin_panel(self, title: str):
        panel = QFrame()
        panel.setObjectName("admin_panel")
        box = QVBoxLayout(panel)
        box.setContentsMargins(14, 12, 14, 12)
        box.setSpacing(10)

        head = QHBoxLayout()
        head.setSpacing(8)
        caption = QLabel(title)
        caption.setObjectName("admin_panel_title")
        badge = QLabel("0")
        badge.setObjectName("admin_count")
        head.addWidget(caption)
        head.addStretch(1)
        head.addWidget(badge)
        box.addLayout(head)

        scroll = QScrollArea()
        scroll.setObjectName("admin_scroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.viewport().setAutoFillBackground(False)
        rows_widget = QWidget()
        rows_widget.setObjectName("admin_rows")
        rows = QVBoxLayout(rows_widget)
        rows.setContentsMargins(0, 0, 0, 0)
        rows.setSpacing(8)
        scroll.setWidget(rows_widget)
        box.addWidget(scroll, 1)
        return panel, rows, badge

    def _admin_make_row(self, name: str, meta: str, actions: list):
        frame = QFrame()
        frame.setObjectName("admin_row")
        frame.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        row = QHBoxLayout(frame)
        row.setContentsMargins(10, 8, 10, 8)
        row.setSpacing(10)

        avatar = QLabel((name.strip()[:1] or "?").upper())
        avatar.setObjectName("admin_avatar")
        avatar.setFixedSize(34, 34)
        avatar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        row.addWidget(avatar, 0, Qt.AlignmentFlag.AlignVCenter)

        col = QVBoxLayout()
        col.setSpacing(1)
        name_label = QLabel(self._elide(name or "Sin nombre", 22))
        name_label.setObjectName("admin_name")
        name_label.setToolTip(name or "")
        name_label.setSizePolicy(
            QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred
        )
        meta_label = QLabel(meta)
        meta_label.setObjectName("admin_meta")
        meta_label.setToolTip(meta)
        meta_label.setSizePolicy(
            QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred
        )
        col.addWidget(name_label)
        col.addWidget(meta_label)
        row.addLayout(col, 1)

        for text, object_name, callback in actions:
            button = QPushButton(text)
            button.setObjectName(object_name)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setFixedHeight(28)
            button.setSizePolicy(
                QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed
            )
            button.clicked.connect(callback)
            row.addWidget(button, 0, Qt.AlignmentFlag.AlignVCenter)
        return frame

    def _admin_empty(self, layout, text: str):
        label = QLabel(text)
        label.setObjectName("admin_empty")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setWordWrap(True)
        label.setMinimumHeight(120)
        layout.addWidget(label)
        layout.addStretch(1)

    def _admin_reject_member(self, uid: str, name: str):
        resp = QMessageBox.question(
            self, "Rechazar solicitud",
            f"¿Rechazar y bloquear a {name}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if resp == QMessageBox.StandardButton.Yes:
            self.supabase.kick_member(uid)

    def _admin_kick_member(self, uid: str, name: str):
        resp = QMessageBox.question(
            self, "Expulsar miembro",
            f"¿Expulsar y bloquear a {name}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if resp == QMessageBox.StandardButton.Yes:
            self.supabase.kick_member(uid)

    def on_admin_close_room(self):
        resp = QMessageBox.question(
            self, "Cerrar sala",
            "Se cerrará la sala para todos. ¿Continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if resp == QMessageBox.StandardButton.Yes:
            self.supabase.close_room()
            if self._admin_dialog is not None:
                self._admin_dialog.close()

    def on_online_room_created(self, code: str):
        self.txt_room.setText(code)
        QApplication.clipboard().setText(code)
        self.lbl_online_status.setText(
            f"Sala creada: {code}\nCódigo copiado al portapapeles."
        )
        self.statusBar().showMessage(f"Sala online creada: {code}", 0)

    def on_online_status(self, text: str):
        self.lbl_online_status.setText(text)
        self.statusBar().showMessage(text, 4000)

    def on_online_connected(self, connected: bool, info: str):
        self.online_connected = connected
        self.statusBar().showMessage(info, 0 if connected else 4000)
        self.lbl_online_status.setText(info)
        if connected:
            self.mode = "online"
            self._last_command_sent_at = 0.0
            self._last_online_command_at = 0.0
            self.btn_mode_online.setChecked(True)
            self.mode_stack.setCurrentIndex(1)
            self._refresh_chat_enabled()
            self.show_screen("chat")
        else:
            self._refresh_chat_enabled()
            if self.mode == "online":
                self.list_usuarios.clear()
                self.lbl_user_count.setText("0")

    def on_online_error(self, msg: str):
        low = msg.lower()
        if "paus" not in low and any(
            word in low for word in ("conectar", "conexión", "supabase")
        ):
            msg = (
                msg + " Si el proyecto estuvo 7 días sin actividad, "
                "puede estar pausado en Supabase."
            )
        self.statusBar().showMessage(msg, 6000)
        self.lbl_online_status.setText(msg)

    def on_online_command(self, sender: str, text: str, target: str = ""):
        if target and target.casefold() != self.settings.get(
            "username", "Usuario"
        ).casefold():
            return
        now = time.time()
        if now - self._last_online_command_at < REMOTE_COMMAND_COOLDOWN:
            self.statusBar().showMessage(
                "Comando remoto ignorado: espera "
                f"{REMOTE_COMMAND_COOLDOWN} s entre comandos.",
                4000,
            )
            return
        self._last_online_command_at = now
        policy = self.settings.get("remote_command_policy", "allow")
        if policy == "ignore":
            self.statusBar().showMessage(
                f"Comando remoto de {sender} ignorado automáticamente.", 4000
            )
            return
        if policy == "ask":
            action = "apagar este equipo" if text == "/off" else "mostrar una alerta falsa"
            self._attention()
            resp = QMessageBox.question(
                self, "Comando remoto",
                f"{sender} solicita {action}.\n¿Permitir?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if resp != QMessageBox.StandardButton.Yes:
                return
        if text == "/off":
            self.statusBar().showMessage(
                f"Comando remoto de {sender}: apagando equipo.", 4000
            )
            try:
                subprocess.run(["shutdown", "/s", "/t", "0"], check=True)
            except Exception as exc:
                self.on_online_error(f"No se pudo apagar: {exc}")
        elif text == "/screamer":
            self.statusBar().showMessage(
                f"Comando remoto de {sender}: mostrando alerta.", 4000
            )
            self.on_screamer()

    def on_buscar(self):
        if self._searching:
            return
        if self.network.hosting:
            QMessageBox.information(
                self, "Buscar salas",
                "Ya estás creando una sala LAN. Pulsa Cancelar si quieres buscar otra.",
            )
            return
        if self.network.is_connected:
            QMessageBox.information(
                self, "Buscar salas",
                "Ya estás conectado a una sala LAN. Desconéctate antes de buscar otra.",
            )
            return
        if self.mode == "online":
            QMessageBox.information(
                self, "Buscar salas",
                "Estás en modo Online. Cambia a LAN para buscar salas locales.",
            )
            return
        self._searching = True
        self.btn_buscar.setEnabled(False)
        self.lbl_tabla_hint.setText("Buscando salas en la red…")
        self.lbl_tabla_hint.setVisible(True)
        self._found_servers = []
        self.tabla.setRowCount(0)
        self.network.discover_servers()

    def on_servers_found(self, servers: list):
        if not self._searching:
            return
        self._searching = False
        self.btn_buscar.setEnabled(
            self.mode == "lan"
            and not self.network.hosting
            and not self.network.is_connected
        )
        self._found_servers = servers
        self.tabla.setRowCount(0)

        for s in servers:
            r = self.tabla.rowCount()
            self.tabla.insertRow(r)
            name_item = QTableWidgetItem(s.get("name") or "Sala")
            name_item.setData(Qt.ItemDataRole.UserRole, s.get("ip", ""))
            name_item.setToolTip(s.get("name") or "Sala")
            self.tabla.setItem(r, 0, name_item)

            ip_item = QTableWidgetItem(
                f'{s.get("ip", "?")}  ·  {s.get("users", 0)} conectado(s)'
            )
            ip_item.setToolTip(f'IP: {s.get("ip", "?")}')
            self.tabla.setItem(r, 1, ip_item)

            auth_item = QTableWidgetItem(s.get("auth", "—"))
            auth_item.setToolTip(s.get("auth", "—"))
            self.tabla.setItem(r, 2, auth_item)

        if servers:
            self.lbl_tabla_hint.setVisible(False)
            self.statusBar().showMessage(f"{len(servers)} sala(s) encontrada(s).", 4000)
        else:
            self.lbl_tabla_hint.setText(
                "No se encontraron salas.\nCrea una sala o revisa el firewall (UDP 45874)."
            )
            self.lbl_tabla_hint.setVisible(True)

    def _check_secret(self) -> bool:
        if len(self.txt_secret.text().strip()) < 3:
            QMessageBox.warning(
                self, "Secreto requerido",
                "Escribe un secreto compartido de al menos 3 caracteres.\n"
                "Debe ser idéntico en ambos equipos."
            )
            self.txt_secret.setFocus()
            return False
        return True

    def on_conectar(self):
        if self.network.hosting:
            QMessageBox.information(
                self, "Conectar",
                "Ya estás creando una sala LAN. Pulsa Cancelar antes de conectarte a otra.",
            )
            return
        if self.network.is_connected:
            return
        if self.mode == "online":
            QMessageBox.information(
                self, "Conectar",
                "Estás en modo Online. Cambia a LAN para conectarte a una sala local.",
            )
            return
        if not self._check_secret():
            return
        row = self.tabla.currentRow()
        ip = ""
        if row >= 0:
            item = self.tabla.item(row, 0)
            if item:
                ip = item.data(Qt.ItemDataRole.UserRole) or ""
        if not ip:
            if len(self._found_servers) == 1:
                ip = self._found_servers[0]["ip"]
            else:
                ip, ok = QInputDialog.getText(self, "Conectar", "IP del servidor:")
                if not ok:
                    return
                ip = ip.strip()
        if not ip:
            return
        if ip in ("127.0.0.1", "localhost") or ip in get_all_local_ips():
            QMessageBox.information(
                self, "Conectar",
                "Esa IP es de tu propia PC. Para probar sola, crea una sala y usa otro equipo.",
            )
            return
        self._set_connection_mode("lan")
        self.mode = "lan"
        self.network.username = self.settings.get("username", "Usuario")
        self.network.auth_mode = self.combo_auth.currentText()
        self.network.shared_secret = self.txt_secret.text()
        self.btn_conectar.setEnabled(False)
        self.btn_buscar.setEnabled(False)
        self.btn_host.setEnabled(False)
        self.statusBar().showMessage(f"Conectando a {ip}…", 0)
        self.network.connect_to(ip)

    def on_cancelar(self):
        self._searching = False
        self.network.disconnect()
        self.supabase.leave()
        self.online_connected = False
        self.btn_buscar.setEnabled(self.mode != "online")
        self.btn_conectar.setEnabled(self.mode != "online")
        self.btn_host.setEnabled(True)
        self.btn_host.setText("Crear sala LAN")
        self.lbl_host.setText("Sin sala activa")
        self.lbl_online_status.setText("Sin conexión")
        self.list_usuarios.clear()
        self.lbl_user_count.setText("0")
        self.btn_admin.hide()
        self._room_info = {}
        self._found_servers = []
        self.tabla.setRowCount(0)
        self.lbl_tabla_hint.setText(
            "Busca una sala en la red o crea la tuya."
        )
        self.lbl_tabla_hint.setVisible(True)
        self._refresh_chat_enabled()
        self.statusBar().showMessage("Conexión cancelada.", 4000)

    # ══════════════════════════════════════════════════════════════════════════
    # CHAT
    # ══════════════════════════════════════════════════════════════════════════
    def _command_targets(self) -> list[str]:
        names = []
        for i in range(self.list_usuarios.count()):
            item = self.list_usuarios.item(i)
            raw = item.data(Qt.ItemDataRole.UserRole) or item.text().strip()
            if not raw or raw == "Sin usuarios conectados":
                continue
            if raw.startswith("●"):
                raw = raw[1:].strip()
            if raw and raw not in names:
                names.append(raw)
        remote = getattr(self.network, "remote_name", "")
        if remote and remote not in names:
            names.append(remote)
        return names

    def on_send_message(self):
        text = self.txt_input.text().strip()
        if not text:
            return
        command, text_target = proto.parse_remote_command(text)
        command_target = None
        if command:
            my_name = self.settings.get("username", "Usuario")
            names = self._command_targets()
            others = [n for n in names if n.casefold() != my_name.casefold()]
            if not others:
                QMessageBox.information(
                    self, "Comando remoto",
                    "No hay otros usuarios conectados para recibir el comando.",
                )
                return
            if text_target:
                if text_target.casefold() == my_name.casefold():
                    QMessageBox.information(
                        self, "Comando remoto",
                        "No puedes apuntar un comando a tu propio equipo.",
                    )
                    return
                match = next(
                    (n for n in others if n.casefold() == text_target.casefold()),
                    None,
                )
                if not match:
                    QMessageBox.warning(
                        self, "Comando remoto",
                        f"No encontré al usuario «{text_target}».\n\n"
                        "Conectados: " + ", ".join(others[:10]),
                    )
                    return
                command_target = match
            now = time.time()
            if now - self._last_command_sent_at < REMOTE_COMMAND_COOLDOWN:
                remaining = max(
                    1,
                    int(REMOTE_COMMAND_COOLDOWN - (now - self._last_command_sent_at)) + 1,
                )
                QMessageBox.information(
                    self, "Comando remoto",
                    f"Espera {remaining} segundo(s) antes de enviar otro comando.",
                )
                return
        ttl = int(self.settings.get("ttl_seconds", 0) or 0)
        reply = self._reply_to
        mid = proto.new_id()
        send_extra = {"command_target": command_target} if command else {}
        if self.mode == "online":
            if not self.supabase.is_connected:
                self.statusBar().showMessage("No estás conectado a la sala online.", 4000)
                return
            self.supabase.send_text(
                text, reply_to=reply, ttl=ttl, msg_id=mid, **send_extra
            )
        else:
            if not self.network.is_connected:
                self.statusBar().showMessage("No estás conectado a ninguna sala.", 4000)
                return
            self.network.username = self.settings.get("username", "Usuario")
            self.network.send_text(
                text, reply_to=reply, ttl=ttl, msg_id=mid, **send_extra
            )
        if command:
            self._last_command_sent_at = time.time()
            destination = f" a {command_target}" if command_target else " a todos"
            self.statusBar().showMessage(
                f"Comando enviado{destination}. Cooldown: "
                f"{REMOTE_COMMAND_COOLDOWN} s.",
                5000,
            )
        meta = {
            "id": mid,
            "reply_to": reply,
            "expires_at": (time.time() + ttl) if ttl else None,
        }
        self._add_bubble("Tú", text, sent=True, meta=meta)
        self.txt_input.clear()
        self._clear_reply()

    def _status_text(self, sent: bool, read: bool = False) -> str:
        base = datetime.now().strftime("%H:%M")
        if sent:
            return f"{base} · {'Leído' if read else 'Enviado'}"
        return base

    def _format_message(self, text: str) -> str:
        safe = html.escape(text)
        safe = re.sub(
            r"(https?://[^\s<]+)",
            r'<a href="\1">\1</a>',
            safe,
        )
        safe = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", safe)
        safe = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"<i>\1</i>", safe)
        safe = re.sub(
            r"`([^`]+)`",
            r'<code style="font-family:Consolas,monospace;'
            r'background-color:rgba(127,127,127,0.18);">\1</code>',
            safe,
        )
        return safe.replace("\n", "<br>")

    def _open_link(self, url: str):
        if not url.startswith(("http://", "https://")):
            return
        resp = QMessageBox.question(
            self, "Abrir enlace",
            f"¿Abrir este enlace en el navegador?\n\n{url}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if resp == QMessageBox.StandardButton.Yes:
            QDesktopServices.openUrl(QUrl(url))

    def _maybe_add_preview(self, text: str, layout):
        match = re.search(
            r"https?://\S+?\.(?:png|jpe?g|gif|webp)(?:\?\S*)?",
            text,
            re.IGNORECASE,
        )
        if not match:
            return
        url = match.group(0).rstrip(").,;")
        label = QLabel("Cargando vista previa…")
        label.setObjectName("hint_chat")
        label.setMaximumWidth(300)
        layout.addWidget(label)

        reply = self._preview_manager.get(QNetworkRequest(QUrl(url)))

        def _finished():
            try:
                if reply.error() == QNetworkReply.NetworkError.NoError:
                    data = reply.readAll()
                    if data.size() <= 4 * 1024 * 1024:
                        pix = QPixmap()
                        if pix.loadFromData(data):
                            label.setPixmap(
                                pix.scaled(
                                    280, 180,
                                    Qt.AspectRatioMode.KeepAspectRatio,
                                    Qt.TransformationMode.SmoothTransformation,
                                )
                            )
                            label.setText("")
                            return
                label.setText("No se pudo cargar la vista previa")
            except Exception:
                try:
                    label.setText("No se pudo cargar la vista previa")
                except Exception:
                    pass
            finally:
                reply.deleteLater()

        reply.finished.connect(_finished)

    def _add_bubble(self, sender: str, text: str, sent: bool, meta: dict | None = None):
        meta = meta or {}
        mid = meta.get("id") or proto.new_id()
        if mid in self._seen_ids:
            return
        expires = meta.get("expires_at")
        if expires and expires <= time.time():
            return
        self._seen_ids.add(mid)

        self.empty_widget.hide()
        bar = self.chat_scroll.verticalScrollBar()
        at_bottom = bar.value() >= bar.maximum() - 48
        safe_text = self._soft_wrap(text)

        wrapper = QWidget()
        wrapper.setProperty("is_message", True)
        wrapper.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        wrapper._msg_id = mid
        wrapper._sender = sender
        wrapper._text = text
        wrapper._sent = sent
        h = QHBoxLayout(wrapper)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)

        bubble = QFrame()
        bubble.setObjectName("burbuja_der" if sent else "burbuja_izq")
        bubble.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)
        bl = QVBoxLayout(bubble)
        bl.setContentsMargins(14, 10, 14, 8)
        bl.setSpacing(3)

        reply_to = meta.get("reply_to")
        if reply_to:
            quote = QLabel(
                f"↪ {reply_to.get('sender', '')}: "
                f"{self._elide(reply_to.get('text', ''), 70)}"
            )
            quote.setObjectName("bubble_reply")
            quote.setWordWrap(True)
            quote.setStyleSheet("font-style: italic;")
            bl.addWidget(quote)

        sender_display = self._elide(sender, 28)
        fm = QFontMetrics(self.chat_area.font())
        longest = max(
            (fm.horizontalAdvance(line) for line in (safe_text.splitlines() or [""])),
            default=0,
        )
        if not sent:
            longest = max(longest, fm.horizontalAdvance(sender_display))
        width = max(170, min(440, longest + 60))
        bubble.setFixedWidth(width)

        if not sent:
            who = QLabel(sender_display)
            who.setObjectName("bubble_sender")
            who.setToolTip(sender)
            bl.addWidget(who)

        msg = QLabel()
        msg.setObjectName("bubble_text")
        msg.setWordWrap(True)
        msg.setTextFormat(Qt.TextFormat.RichText)
        msg.setOpenExternalLinks(False)
        msg.setText(self._format_message(safe_text))
        msg.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        msg.linkActivated.connect(self._open_link)
        if meta.get("color"):
            msg.setStyleSheet(f"color: {meta['color']}; font-weight: 600;")
        bl.addWidget(msg)

        self._maybe_add_preview(text, bl)

        reaction_label = QLabel("")
        reaction_label.setObjectName("hint_chat")
        reaction_label.setWordWrap(True)
        reaction_label.hide()
        bl.addWidget(reaction_label)

        stamp = QLabel(self._status_text(sent))
        stamp.setObjectName("bubble_time")
        stamp.setAlignment(Qt.AlignmentFlag.AlignRight)
        bl.addWidget(stamp)

        wrapper._status_label = stamp
        wrapper._reaction_label = reaction_label

        wrapper.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        wrapper.customContextMenuRequested.connect(
            lambda pos, w=wrapper: self._message_menu(w, pos)
        )

        if sent:
            h.addStretch(1)
            h.addWidget(bubble)
        else:
            h.addWidget(bubble)
            h.addStretch(1)

        self.chat_lay.insertWidget(self.chat_lay.count() - 1, wrapper)
        self._msg_widgets[mid] = wrapper
        self._render_reactions(mid)

        if expires:
            delay = max(0, int((expires - time.time()) * 1000))
            QTimer.singleShot(delay, lambda m=mid: self._remove_message(m))

        if not sent and self.settings.get("read_receipts", True) and mid:
            QTimer.singleShot(600, lambda m=mid: self._send_read(m))

        if at_bottom:
            QTimer.singleShot(50, self._scroll_bottom)

    def _message_menu(self, wrapper, pos):
        mid = getattr(wrapper, "_msg_id", None)
        text = getattr(wrapper, "_text", "")
        menu = QMenu(self)
        act_reply = menu.addAction("Responder")
        react_menu = menu.addMenu("Reaccionar")
        for emoji in ("👍", "❤️", "😂", "😮", "😢", "🎉"):
            action = react_menu.addAction(emoji)
            action.triggered.connect(
                lambda _=False, e=emoji, m=mid: self._send_reaction(m, e)
            )
        act_copy = menu.addAction("Copiar texto")
        act_delete = menu.addAction("Borrar del chat")
        chosen = menu.exec(wrapper.mapToGlobal(pos))
        if chosen == act_reply:
            self._start_reply(wrapper)
        elif chosen == act_copy:
            QApplication.clipboard().setText(text)
        elif chosen == act_delete:
            self._remove_message(mid)

    def _start_reply(self, wrapper):
        self._reply_to = {
            "id": getattr(wrapper, "_msg_id", ""),
            "sender": getattr(wrapper, "_sender", ""),
            "text": getattr(wrapper, "_text", ""),
        }
        preview = self._elide(self._reply_to["text"], 70)
        self.lbl_reply.setText(f"Respondiendo a {self._reply_to['sender']}: {preview}")
        self.reply_bar.show()
        self.txt_input.setFocus()

    def _clear_reply(self):
        self._reply_to = None
        self.reply_bar.hide()
        self.lbl_reply.setText("")

    def _remove_message(self, mid: str):
        wrapper = self._msg_widgets.pop(mid, None)
        self._seen_ids.discard(mid)
        self._reactions.pop(mid, None)
        if wrapper is not None:
            wrapper.deleteLater()
        if not self._msg_widgets:
            self.empty_widget.show()

    def _send_reaction(self, mid: str, emoji: str):
        if not mid:
            return
        if self.mode == "online" and self.supabase.is_connected:
            self.supabase.send_reaction(mid, emoji)
        elif self.network.is_connected:
            self.network.send_reaction(mid, emoji)
        self._add_reaction(mid, emoji, self.settings.get("username", "Tú"))

    def _add_reaction(self, mid: str, emoji: str, sender: str):
        items = self._reactions.setdefault(mid, [])
        if (emoji, sender) not in items:
            items.append((emoji, sender))
        self._render_reactions(mid)

    def _render_reactions(self, mid: str):
        wrapper = self._msg_widgets.get(mid)
        if wrapper is None:
            return
        label = getattr(wrapper, "_reaction_label", None)
        if label is None:
            return
        items = self._reactions.get(mid, [])
        if not items:
            label.setText("")
            label.hide()
            return
        counts = {}
        for emoji, _sender in items:
            counts[emoji] = counts.get(emoji, 0) + 1
        label.setText("   ".join(
            f"{emoji} {count}" if count > 1 else emoji
            for emoji, count in counts.items()
        ))
        label.show()

    def on_reaction_received(self, target: str, emoji: str, sender: str):
        self._add_reaction(target, emoji, sender)

    def _send_read(self, mid: str):
        if not self.settings.get("read_receipts", True):
            return
        if self.mode == "online" and self.supabase.is_connected:
            self.supabase.send_read(mid)
        elif self.network.is_connected:
            self.network.send_read(mid)

    def on_read_received(self, mid: str):
        wrapper = self._msg_widgets.get(mid)
        if wrapper is not None and getattr(wrapper, "_sent", False):
            status = getattr(wrapper, "_status_label", None)
            if status is not None:
                status.setText(self._status_text(True, read=True))

    def _request_latency(self):
        if self.mode == "online" and self.supabase.is_connected:
            self.supabase.send_ping()
        elif self.network.is_connected:
            self.network.send_ping()

    def on_latency(self, ms: float):
        self.lbl_latency.setText(f"{ms:.0f} ms")

    @staticmethod
    def _soft_wrap(text: str, limit: int = 26) -> str:
        """Rompe tokens larguísimos (emails, URLs) para que no desborden."""
        return re.sub(rf"(\S{{{limit}}})(?=\S)", "\\1\u200b", text)

    @staticmethod
    def _elide(text: str, limit: int = 18) -> str:
        if len(text) <= limit:
            return text
        return text[: limit - 1].rstrip() + "…"

    def _scroll_bottom(self):
        self.chat_lay.activate()
        bar = self.chat_scroll.verticalScrollBar()
        bar.setValue(bar.maximum())

    def on_message_received(self, sender: str, text: str, meta: dict | None = None):
        meta = meta or {}
        self._last_received = {
            "id": meta.get("id", ""),
            "sender": sender,
            "text": text,
        }
        self._notify_message(sender, text)
        self._add_bubble(sender, text, sent=False, meta=meta)

    def on_user_list(self, users: list):
        self.list_usuarios.clear()
        for u in users:
            item = QListWidgetItem(f"●  {self._elide(u, 24)}")
            item.setToolTip(u)
            item.setData(Qt.ItemDataRole.UserRole, u)
            self.list_usuarios.addItem(item)
        self.lbl_user_count.setText(str(len(users)))
        if not users:
            empty = QListWidgetItem("Sin usuarios conectados")
            empty.setFlags(Qt.ItemFlag.NoItemFlags)
            self.list_usuarios.addItem(empty)
        elif self.network.is_connected and self.network.remote_name:
            # El handshake LAN ya terminó: ahora sí conviene abrir el chat.
            if self.stack.currentIndex() != 1:
                self.show_screen("chat")

    def on_desconectar(self):
        self._searching = False
        self.network.disconnect()
        self.supabase.leave()
        self.online_connected = False
        self._found_servers = []
        self.tabla.setRowCount(0)
        self.list_usuarios.clear()
        self.lbl_user_count.setText("0")
        self.btn_host.setEnabled(True)
        self.btn_host.setText("Crear sala LAN")
        self.btn_buscar.setEnabled(self.mode != "online")
        self.btn_conectar.setEnabled(self.mode != "online")
        self.lbl_host.setText("Sin sala activa")
        self.lbl_online_status.setText("Sin conexión")
        self.btn_admin.hide()
        self._room_info = {}
        self._refresh_chat_enabled()
        self.show_screen("servidores")

    def on_system_message(self, text: str):
        self.statusBar().showMessage(text, 5000)

    def on_file_received(self, fname: str, path: str):
        self._notify_file("Remoto", fname)
        try:
            size = Path(path).stat().st_size
        except Exception:
            size = 0
        self._add_file_bubble("Remoto", {
            "id": proto.new_id(),
            "name": fname,
            "size": size,
            "mime": mimetypes.guess_type(fname)[0] or "application/octet-stream",
            "local_path": path,
        }, sent=False)

    def on_error(self, msg: str):
        self.statusBar().showMessage(msg, 6000)
        if any(
            text in msg
            for text in ("antes de autenticarse", "Handshake inválido", "Error enviando")
        ):
            return
        if "Secreto incorrecto" in msg and self.network.hosting:
            # El host no debe quedar bloqueado por cada intento fallido.
            return
        QMessageBox.critical(self, "Error", msg)

    def on_connection_status(self, connected: bool, info: str):
        if connected and not self.network.is_connected:
            return
        if not connected and self.network.is_connected:
            return
        if connected:
            self.mode = "lan"
            self._last_command_sent_at = 0.0
            self.btn_host.setEnabled(False)
            if self.network.hosting:
                self.btn_host.setText("Sala activa")
            self.btn_buscar.setEnabled(False)
            self.btn_conectar.setEnabled(False)
        elif self.mode == "lan":
            self.list_usuarios.clear()
            self.lbl_user_count.setText("0")
            if self.network.hosting:
                self.btn_host.setEnabled(False)
                self.btn_host.setText("Sala activa")
                self.btn_buscar.setEnabled(False)
                self.btn_conectar.setEnabled(False)
            else:
                self.btn_host.setEnabled(True)
                self.btn_host.setText("Crear sala LAN")
                self.lbl_host.setText("Sin sala activa")
                self.btn_buscar.setEnabled(True)
                self.btn_conectar.setEnabled(True)
        self._refresh_chat_enabled()
        self.statusBar().showMessage(info, 0 if connected else 4000)

    def _refresh_chat_enabled(self):
        self._set_chat_enabled(self.network.is_connected or self.supabase.is_connected)

    def _set_chat_enabled(self, enabled: bool):
        self.txt_input.setEnabled(enabled)
        self.btn_send.setEnabled(enabled)
        self.txt_input.setPlaceholderText(
            "Escribe un mensaje y pulsa Enter…"
            if enabled else "Conéctate a una sala para escribir…"
        )

    def _on_remote_policy_changed(self, _index: int):
        policy = self.combo_remote.currentData() or "allow"
        self.settings["remote_command_policy"] = policy
        self.settings["confirm_commands"] = policy == "ask"
        self.network.confirm_commands = policy == "ask"
        self.network.ignore_remote_commands = policy == "ignore"
        save_settings(self.settings)

    def _on_auth_mode_changed(self, value: str):
        self.network.auth_mode = value
        self.settings["auth_mode"] = value
        save_settings(self.settings)

    def _on_ttl_changed(self, _index: int):
        self.settings["ttl_seconds"] = int(self.combo_ttl.currentData() or 0)
        save_settings(self.settings)

    def _on_file_ttl_changed(self, _index: int):
        self.settings["file_ttl_days"] = int(self.combo_files.currentData() or 0)
        save_settings(self.settings)

    def _on_auto_delete_downloads_toggled(self, value: bool):
        self.settings["auto_delete_downloads"] = bool(value)
        save_settings(self.settings)

    def _on_notifications_toggled(self, value: bool):
        self.settings["native_notifications"] = bool(value)
        save_settings(self.settings)

    def _on_read_toggled(self, value: bool):
        self.settings["read_receipts"] = value
        save_settings(self.settings)

    def _on_capture_toggled(self, value: bool):
        self.settings["screenshot_protection"] = value
        save_settings(self.settings)
        self._apply_screenshot_protection()

    def _apply_screenshot_protection(self):
        try:
            hwnd = int(self.winId())
            ctypes.windll.user32.SetWindowDisplayAffinity(
                hwnd, 0x11 if self.settings.get("screenshot_protection") else 0x0
            )
        except Exception:
            pass

    def on_panic(self):
        resp = QMessageBox.question(
            self, "Borrar todo y cerrar",
            "Se borrará la conversación, se desconectará la sesión y se cerrará la app.\n"
            "¿Continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if resp != QMessageBox.StandardButton.Yes:
            return
        self.clear_chat()
        self.network.disconnect()
        self.supabase.stop()
        self.settings["shared_secret"] = ""
        save_settings(self.settings)
        self.close()

    def _wrap_selection(self, marker: str):
        text = self.txt_input.text()
        start = self.txt_input.selectionStart()
        selected = self.txt_input.selectedText()
        if selected:
            end = start + len(selected)
            self.txt_input.setText(
                text[:start] + marker + selected + marker + text[end:]
            )
            self.txt_input.setCursorPosition(end + len(marker) * 2)
        else:
            pos = self.txt_input.cursorPosition()
            self.txt_input.setText(text[:pos] + marker + marker + text[pos:])
            self.txt_input.setCursorPosition(pos + len(marker))
        self.txt_input.setFocus()

    def _show_emoji_picker(self):
        popup = QFrame(self, Qt.WindowType.Popup)
        popup.setObjectName("panel")
        grid = QGridLayout(popup)
        grid.setContentsMargins(8, 8, 8, 8)
        grid.setSpacing(4)
        for i, emoji in enumerate(EMOJIS):
            b = QPushButton(emoji)
            b.setObjectName("fmt_btn")
            b.setFixedSize(34, 30)
            b.setFont(QFont("Segoe UI Emoji", 12))
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setToolTip(f"Insertar {emoji}")
            b.clicked.connect(
                lambda _=False, e=emoji, p=popup: self._insert_emoji(e, p)
            )
            grid.addWidget(b, i // 8, i % 8)
        popup.adjustSize()
        pos = self.btn_emoji.mapToGlobal(QPoint(0, -popup.height() - 4))
        popup.move(pos)
        popup.show()
        self._emoji_popup = popup

    def _insert_emoji(self, emoji: str, popup):
        self.txt_input.insert(emoji)
        self.txt_input.setFocus()
        popup.close()

    def _attention(self):
        try:
            if self.isMinimized():
                self.showNormal()
            self.raise_()
            self.activateWindow()
            QApplication.alert(self, 0)
        except Exception:
            pass

    def on_command_requested(self, cmd: str):
        self._attention()
        action = "apagar este equipo" if cmd == "/off" else "mostrar una alerta falsa"
        resp = QMessageBox.question(
            self, "Comando remoto",
            f"El otro equipo solicita {action}.\n¿Permitir?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if resp == QMessageBox.StandardButton.Yes:
            self.network.execute_remote_command(cmd)

    def clear_chat(self):
        for i in reversed(range(self.chat_lay.count())):
            w = self.chat_lay.itemAt(i).widget()
            if w is not None and w.property("is_message"):
                w.deleteLater()
        self._msg_widgets.clear()
        self._seen_ids.clear()
        self._reactions.clear()
        self.empty_widget.show()
        self.statusBar().showMessage("Conversación limpiada.", 3000)

    # ══════════════════════════════════════════════════════════════════════════
    # IDENTIDAD / SCREAMER
    # ══════════════════════════════════════════════════════════════════════════
    def _update_identity(self):
        name = self.settings.get("username", "Usuario")
        self.lbl_nametag.setText(self._elide(name, 18))
        self.frame_nametag.setToolTip(f"Tú: {name}")
        self.lbl_avatar.setText(name[:1].upper() if name else "U")

    def _edit_nametag(self, event):
        new, ok = QInputDialog.getText(
            self, "Nombre de usuario", "Tu nombre:", text=self.lbl_nametag.text()
        )
        if ok and new.strip():
            self.settings["username"] = new.strip()
            self.network.username = new.strip()
            self.txt_username.setText(new.strip())
            save_settings(self.settings)
            self._update_identity()

    def on_save_username(self):
        new = self.txt_username.text().strip()
        if not new:
            return
        self.settings["username"] = new
        self.network.username = new
        save_settings(self.settings)
        self._update_identity()
        self.statusBar().showMessage("Nombre guardado.", 3000)

    def on_screamer(self):
        if self._screamer_win is not None:
            return
        w = QWidget()
        w.setWindowFlags(
            Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint
        )
        w.setStyleSheet("background: #7f0000;")
        lay = QVBoxLayout(w)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.setSpacing(18)

        title = QLabel("⚠  SISTEMA COMPROMETIDO  ⚠")
        title.setStyleSheet("color: white; font-size: 44px; font-weight: 900;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        sub = QLabel("Se ha detectado un virus en este equipo.")
        sub.setStyleSheet("color: white; font-size: 20px;")
        sub.setAlignment(Qt.AlignmentFlag.AlignCenter)

        close = QPushButton("CERRAR")
        close.setStyleSheet(
            "background: white; color: #7f0000; font-weight: 900; "
            "padding: 12px 40px; border-radius: 12px; font-size: 16px;"
        )
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.clicked.connect(w.close)

        lay.addWidget(title)
        lay.addWidget(sub)
        lay.addSpacing(10)
        lay.addWidget(close, alignment=Qt.AlignmentFlag.AlignCenter)

        self._screamer_win = w
        w.destroyed.connect(lambda: setattr(self, "_screamer_win", None))
        w.showFullScreen()
        QTimer.singleShot(15000, w.close)

    def closeEvent(self, event):
        try:
            self.settings["window_geometry"] = bytes(
                self.saveGeometry().toBase64()
            ).decode("ascii")
        except Exception:
            pass
        if getattr(self, "_tray", None) is not None:
            try:
                self._tray.hide()
            except Exception:
                pass
        self.network.disconnect()
        self.supabase.stop()
        save_settings(self.settings)
        event.accept()


# ══════════════════════════════════════════════════════════════════════════════
# PUNTO DE ENTRADA
# ══════════════════════════════════════════════════════════════════════════════
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setApplicationName(APP_NAME)
    app.setFont(QFont("Segoe UI", 10))

    socket = QLocalSocket()
    socket.connectToServer("ChatWiFiInstance")
    if socket.waitForConnected(300):
        socket.write(b"show")
        socket.flush()
        socket.waitForBytesWritten(300)
        return

    server = QLocalServer()
    QLocalServer.removeServer("ChatWiFiInstance")
    server.listen("ChatWiFiInstance")

    window = ChatWindow()

    def _show_existing():
        window.showNormal()
        window.raise_()
        window.activateWindow()

    server.newConnection.connect(_show_existing)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
