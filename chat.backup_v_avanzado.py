"""
Chat WiFi - Versión Avanzada
Funciones:
- Buscador de servidores en red local (escaneo IP + puerto)
- Nombres de usuario y chat multipunto (múltiples conexiones)
- Comandos dirigidos: /off [usuario], /screamer [usuario], /color [usuario] [color] [texto]
- Envío de archivos e imágenes (binarios con metadatos)
- Emojis (Unicode)
- 3 temas nuevos de interfaz + 10 tipografías
- Estructura preparada para Graphify (https://github.com/Graphify-Labs/graphify)
- Notificaciones nativas de Windows
- Compatible con cifrado Fernet (contraseña, código de sala, clave Fernet)

Requisitos: Python 3, tkinter, cryptography
"""

import base64
import hashlib
import json
import os
import platform
import queue
import secrets
import socket
import struct
import subprocess
import tempfile
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from ctypes import wintypes
from pathlib import Path
from datetime import datetime

try:
    import ctypes
except Exception:
    ctypes = None

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError as exc:
    raise SystemExit(
        "Falta la biblioteca 'cryptography'. Ejecuta ABRIR_CHAT.bat "
        "o en una terminal: py -m pip install cryptography"
    ) from exc

# ============================================================================
# CONFIGURACIÓN Y RUTAS
# ============================================================================
KEY_FILE = Path(__file__).resolve().with_name('clave_chat.key')
SETTINGS_FILE = KEY_FILE.with_name('sala_chat.json')
DOWNLOADS_DIR = Path(__file__).resolve().with_name('descargas_chat')
DOWNLOADS_DIR.mkdir(exist_ok=True)

AUTH_MODES = ('password', 'code', 'key')

PORT = 45873
LIMIT = 32768
TIEMPO_CONEXION = 15
COMANDO_APAGADO = '/off'
COMANDO_SCREAMER = '/screamer'
MARCADOR_COLOR = '\x01COLOR\x01'
MARCADOR_ARCHIVO = '\x01ARCHIVO\x01'

# ============================================================================
# TEMAS Y TIPOS DE LETRA
# ============================================================================
TEMAS = {
    'claro': {
        'bg': '#ffffff', 'fg': '#000000', 'accent': '#0078d7',
        'accent_fg': '#ffffff', 'bg_panel': '#f5f5f5', 'bg_chat': '#ffffff',
        'border': '#cccccc', 'success': '#28a745', 'danger': '#dc3545',
        'warning': '#ffc107', 'info': '#17a2b8'
    },
    'oscuro': {
        'bg': '#1e1e1e', 'fg': '#ffffff', 'accent': '#0078d7',
        'accent_fg': '#ffffff', 'bg_panel': '#2d2d2d', 'bg_chat': '#252526',
        'border': '#3e3e42', 'success': '#4caf50', 'danger': '#f44336',
        'warning': '#ff9800', 'info': '#2196f3'
    },
    'matrix': {
        'bg': '#001100', 'fg': '#00ff00', 'accent': '#00ff00',
        'accent_fg': '#000000', 'bg_panel': '#000a00', 'bg_chat': '#000500',
        'border': '#003300', 'success': '#00ff00', 'danger': '#ff0000',
        'warning': '#ffff00', 'info': '#00ffff'
    },
    'neon': {
        'bg': '#1a1a2e', 'fg': '#e94560', 'accent': '#16213e',
        'accent_fg': '#e94560', 'bg_panel': '#16213e', 'bg_chat': '#0f3460',
        'border': '#e94560', 'success': '#e94560', 'danger': '#16213e',
        'warning': '#fca311', 'info': '#29d7e3'
    }
}

FUENTES = [
    'Segoe UI', 'Arial', 'Courier New', 'Times New Roman', 'Verdana',
    'Tahoma', 'Georgia', 'Impact', 'Comic Sans MS', 'Consolas'
]

# Colores soportados para el chat
COLORES_VALIDOS = {
    'rojo': 'red', 'verde': 'green', 'azul': 'blue', 'amarillo': 'yellow',
    'naranja': 'orange', 'morado': 'purple', 'rosa': 'magenta',
    'cian': 'cyan', 'gris': 'gray', 'negro': 'black'
}

# ============================================================================
# FUNCIONES AUXILIARES DE RED Y CIFRADO
# ============================================================================
def atomic_write(path, value):
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                         dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(value)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def new_room_code():
    text = base64.b32encode(secrets.token_bytes(10)).decode('ascii')
    return '-'.join(text[i:i + 4] for i in range(0, len(text), 4))


def normalize_room_code(value):
    value = value.strip().upper().replace('-', '').replace(' ', '')
    if not 12 <= len(value) <= 128 or not all(
        c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' for c in value
    ):
        raise ValueError('Usa al menos 12 letras o números.')
    return value


def room_code_key(value):
    code = normalize_room_code(value).encode('ascii')
    raw = Scrypt(salt=b'ChatWiFi/room-code/v1', length=32,
                 n=32768, r=8, p=1).derive(code)
    return base64.urlsafe_b64encode(raw)


def password_key(value):
    if not value:
        raise ValueError('Escribe la contraseña que tú elija.')
    password = value.encode('utf-8')
    raw = Scrypt(salt=b'ChatWiFi/free-password/v1', length=32,
                 n=32768, r=8, p=1).derive(password)
    return base64.urlsafe_b64encode(raw)


def save_settings(settings, path=None):
    atomic_write(path if path is not None else SETTINGS_FILE,
                 json.dumps(settings, ensure_ascii=False, indent=2) + '\n')


def load_settings(path=None):
    path = Path(path) if path is not None else SETTINGS_FILE
    try:
        settings = json.loads(path.read_text(encoding='utf-8'))
    except FileNotFoundError:
        settings = {'mode': 'key', 'password': '', 'code': new_room_code(), 'address': ''}
        save_settings(settings, path)
    if (not isinstance(settings, dict) or settings.get('mode') not in AUTH_MODES
            or not isinstance(settings.get('code'), str)
            or not isinstance(settings.get('address'), str)
            or not isinstance(settings.get('password', ''), str)):
        settings = {'mode': 'key', 'password': '', 'code': new_room_code(), 'address': ''}
        save_settings(settings, path)
    settings.setdefault('password', '')
    settings.setdefault('code', new_room_code())
    return settings


def save_room_key(value, path=None):
    path = Path(path) if path is not None else KEY_FILE
    value = value.strip()
    Fernet(value.encode('ascii'))
    atomic_write(path, value + '\n')
    return value


def load_room_key(path=None):
    path = Path(path) if path is not None else KEY_FILE
    try:
        value = path.read_text(encoding='ascii').strip()
    except FileNotFoundError:
        return save_room_key(Fernet.generate_key().decode('ascii'), path)
    Fernet(value.encode('ascii'))
    return value


def local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(('192.0.2.1', 80))
            return probe.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return ''


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError('La otra persona se desconectó.')
        data.extend(part)
    return bytes(data)


def receive(sock):
    size = struct.unpack('!I', read_exact(sock, 4))[0]
    if not 0 < size <= LIMIT:
        raise ValueError('Mensaje demasiado grande.')
    return read_exact(sock, size)


def transmit(sock, token):
    sock.sendall(struct.pack('!I', len(token)) + token)


# ============================================================================
# NOTIFICACIONES WINDOWS
# ============================================================================
class NotificationData(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.DWORD), ('hWnd', wintypes.HWND),
        ('uID', wintypes.UINT), ('uFlags', wintypes.UINT),
        ('uCallbackMessage', wintypes.UINT), ('hIcon', wintypes.HICON),
        ('szTip', wintypes.WCHAR * 128), ('dwState', wintypes.DWORD),
        ('dwStateMask', wintypes.DWORD), ('szInfo', wintypes.WCHAR * 256),
        ('uTimeout', wintypes.UINT), ('szInfoTitle', wintypes.WCHAR * 64),
        ('dwInfoFlags', wintypes.DWORD), ('guidItem', ctypes.c_byte * 16),
        ('hBalloonIcon', wintypes.HICON),
    ]


class WindowsNotifications:
    def __init__(self, root):
        self.root = root
        self.added = False
        self.data = None

    def show(self):
        if ctypes is None:
            return False
        try:
            shell = ctypes.WinDLL('shell32', use_last_error=True)
            notify = shell.Shell_NotifyIconW
            notify.argtypes = [wintypes.DWORD, ctypes.POINTER(NotificationData)]
            notify.restype = wintypes.BOOL
            if self.data is None:
                user = ctypes.WinDLL('user32', use_last_error=True)
                user.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
                user.GetAncestor.restype = wintypes.HWND
                user.LoadIconW.argtypes = [wintypes.HINSTANCE, ctypes.c_void_p]
                user.LoadIconW.restype = wintypes.HICON
                self.root.update_idletasks()
                self.data = NotificationData()
                self.data.cbSize = ctypes.sizeof(NotificationData)
                self.data.hWnd = user.GetAncestor(self.root.winfo_id(), 2)
                self.data.uID = 1
                self.data.hIcon = user.LoadIconW(None, 32512)
                self.data.szTip = 'Chat privado · Wi-Fi'
            if not self.added:
                self.data.uFlags = 0x02 | 0x04
                self.added = bool(notify(0, ctypes.byref(self.data)))
                if not self.added:
                    return False
            self.data.uFlags = 0x10
            self.data.szInfoTitle = 'Chat privado · Nuevo mensaje'
            self.data.szInfo = 'Tienes un nuevo mensaje. Abre el chat para leerlo.'
            self.data.dwInfoFlags = 0x01 | 0x80
            if notify(1, ctypes.byref(self.data)):
                return True
            self.added = False
            return False
        except (OSError, AttributeError):
            return False

    def close(self):
        if ctypes is None or not self.added or self.data is None:
            return
        try:
            shell = ctypes.WinDLL('shell32')
            shell.Shell_NotifyIconW.argtypes = [wintypes.DWORD, ctypes.POINTER(NotificationData)]
            shell.Shell_NotifyIconW.restype = wintypes.BOOL
            shell.Shell_NotifyIconW(2, ctypes.byref(self.data))
        except OSError:
            pass
        self.added = False


# ============================================================================
# FUNCIONES ESPECIALES (APAGADO, SCREAMER)
# ============================================================================
def apagar_windows():
    try:
        subprocess.run(
            ['shutdown', '/s', '/t', '0'],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except Exception:
        pass


def mostrar_screamer(root_owner=None):
    try:
        screamer = tk.Toplevel(root_owner) if root_owner else tk.Tk()
        screamer.title('⚠ ALERTA DE SEGURIDAD ⚠')
        screamer.geometry('450x250')
        screamer.configure(bg='#8b0000')
        screamer.resizable(False, False)
        screamer.attributes('-topmost', True)
        screamer.lift()
        screamer.focus_force()
        try:
            import winsound
            for _ in range(4):
                winsound.Beep(1000, 400)
        except Exception:
            try:
                root_owner.bell() if root_owner else None
            except Exception:
                pass
        marco = tk.Frame(screamer, bg='#8b0000', padx=20, pady=20)
        marco.pack(fill='both', expand=True)
        tk.Label(marco, text='🦠', font=('Segoe UI', 48), bg='#8b0000', fg='#ffff00').pack(pady=(10, 5))
        tk.Label(marco, text='SISTEMA COMPROMETIDO', font=('Segoe UI', 16, 'bold'),
                 bg='#8b0000', fg='white').pack(pady=(0, 5))
        tk.Label(marco, text='Se ha detectado actividad maliciosa en este equipo.\n'
                             'El acceso ha sido bloqueado por seguridad.\n\n'
                             'Código de error: 0x8004210B',
                 font=('Segoe UI', 11), bg='#8b0000', fg='#f0f0f0', justify='center').pack(pady=(0, 15))

        def cerrar():
            try:
                screamer.destroy()
            except Exception:
                pass

        tk.Button(marco, text='Aceptar', command=cerrar, bg='white', fg='#8b0000',
                  font=('Segoe UI', 11, 'bold'), width=12, relief='raised', bd=3).pack(pady=(0, 10))
        try:
            screamer.after(10000, cerrar)
        except Exception:
            pass
        try:
            screamer.mainloop()
        except Exception:
            pass
    except Exception:
        pass


# ============================================================================
# BUSCADOR DE SERVIDORES (ESCANEO DE RED)
# ============================================================================
class ServerDiscovery:
    """Escanea la red local buscando servidores de chat en el puerto 45873."""

    def __init__(self, callback):
        self.callback = callback
        self.running = False
        self.servidores = {}  # ip -> nombre

    def _obtener_rango_local(self):
        ip = local_ip()
        if not ip or ip.startswith('127.'):
            return []
        partes = ip.split('.')
        return f"{partes[0]}.{partes[1]}.{partes[2]}."

    def _probar_ip(self, ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((ip, PORT))
            s.close()
            return True
        except OSError:
            return False

    def escanear(self):
        self.running = True
        self.servidores = {}
        rango = self._obtener_rango_local()
        if not rango:
            self.callback([])
            self.running = False
            return

        hilos = []
        resultados = []

        def worker(ip):
            if self._probar_ip(ip):
                try:
                    nombre = socket.gethostbyaddr(ip)[0]
                except OSError:
                    nombre = ip
                resultados.append((ip, nombre))

        for i in range(1, 255):
            if not self.running:
                break
            ip = f"{rango}{i}"
            h = threading.Thread(target=worker, args=(ip,), daemon=True)
            hilos.append(h)
            h.start()

        for h in hilos:
            h.join(timeout=3)

        self.callback(resultados)
        self.running = False


# ============================================================================
# CLASE PRINCIPAL DEL CHAT
# ============================================================================
class Chat:
    def __init__(self, root):
        self.root = root
        self.notifications = WindowsNotifications(root)
        self.events = queue.Queue()

        # Estado de conexiones múltiples
        self.sockets = {}      # nombre_usuario -> socket
        self.ciphers = {}      # nombre_usuario -> Fernet
        self.sessions = {}     # nombre_usuario -> session_id
        self.outgoings = {}    # nombre_usuario -> challenge
        self.incomings = {}    # nombre_usuario -> hello[6:]
        self.sents = {}        # nombre_usuario -> contador
        self.conexiones_activas = set()

        # Configuración
        self.sock = None
        self.listener = None
        self.cipher = None
        self.outgoing = None
        self.incoming = None
        self.sent = 0
        self.session = 0
        self.busy = False
        self.sending = False
        self._cancel = False
        self._closed = False
        self._after_id = None
        self._apagando = False
        self.my_ip = local_ip()
        self.nombre_usuario = tk.StringVar(value='Usuario')
        self.tema_actual = tk.StringVar(value='oscuro')
        self.fuente_actual = tk.StringVar(value='Segoe UI')

        # Descubrimiento de servidores
        self.discovery = ServerDiscovery(self._actualizar_lista_servidores)
        self.descubriendo = False

        root.title('Chat WiFi - Multiusuario')
        root.geometry('1200x700')
        root.minsize(900, 600)

        self._construir_interfaz()
        self._aplicar_tema()
        self._after_id = root.after(100, self.poll)
        root.protocol('WM_DELETE_WINDOW', self.close)

    # ---------- Interfaz ----------
    def _construir_interfaz(self):
        # Barra superior
        frame_top = ttk.Frame(self.root, padding=10)
        frame_top.pack(fill='x')

        ttk.Label(frame_top, text='CHAT WIFI - MULTIUSUARIO',
                  font=('Segoe UI', 14, 'bold')).pack(side='left')

        ttk.Separator(frame_top, orient='vertical').pack(side='left', fill='y', padx=14)

        self.lbl_ip_top = ttk.Label(frame_top, text=f'Tu IP: {self.my_ip}',
                                    font=('Segoe UI', 10), foreground='#0078d7')
        self.lbl_ip_top.pack(side='left', padx=(0, 20))

        self.status = tk.StringVar(value='Sin conexión')
        ttk.Label(frame_top, textvariable=self.status,
                  font=('Segoe UI', 10, 'bold')).pack(side='left')

        # Panel principal dividido
        paned = ttk.PanedWindow(self.root, orient='horizontal')
        paned.pack(fill='both', expand=True, padx=10, pady=(0, 10))

        # ===== Panel izquierdo: Buscador de servidores =====
        frame_left = ttk.Frame(paned, padding=6)
        paned.add(frame_left, weight=1)

        ttk.Label(frame_left, text='SERVIDORES DISPONIBLES',
                  font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(0, 4))

        btn_frame = ttk.Frame(frame_left)
        btn_frame.pack(fill='x', pady=(0, 4))
        self.btn_escanear = ttk.Button(btn_frame, text='Escanear Red',
                                       command=self._iniciar_escaneo)
        self.btn_escanear.pack(side='left')
        self.btn_detener = ttk.Button(btn_frame, text='Detener',
                                      command=self._detener_escaneo, state='disabled')
        self.btn_detener.pack(side='left', padx=5)

        self.tree_servidores = ttk.Treeview(
            frame_left, columns=('estado',), show='tree headings', height=12
        )
        self.tree_servidores.heading('#0', text='Nombre del Servidor')
        self.tree_servidores.heading('estado', text='Estado')
        self.tree_servidores.column('estado', width=70, anchor='center')
        self.tree_servidores.pack(fill='both', expand=True, pady=(0, 4))
        self.tree_servidores.bind('<Double-1>', self._doble_clic_servidor)

        ttk.Label(frame_left, text='NUESTRO NOMBRE DE USUARIO:',
                  font=('Segoe UI', 9, 'bold')).pack(anchor='w', pady=(10, 0))
        self.entry_nombre = ttk.Entry(frame_left, textvariable=self.nombre_usuario)
        self.entry_nombre.pack(fill='x', pady=(0, 4))

        ttk.Label(frame_left, text='CONEXIONES ACTIVAS:',
                  font=('Segoe UI', 9, 'bold')).pack(anchor='w')
        self.lbl_conexiones = ttk.Label(frame_left, text='0')
        self.lbl_conexiones.pack(anchor='w', pady=(0, 8))

        # ===== Panel derecho: Chat =====
        frame_right = ttk.Frame(paned, padding=6)
        paned.add(frame_right, weight=3)

        ttk.Label(frame_right, text='CHAT',
                  font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(0, 4))

        frame_historial = ttk.Frame(frame_right)
        frame_historial.pack(fill='both', expand=True)

        self.history = tk.Text(frame_historial, state='disabled', wrap='word',
                               font=('Segoe UI', 11))
        self.history.pack(side='left', fill='both', expand=True)

        scroll_historial = ttk.Scrollbar(
            frame_historial, orient='vertical', command=self.history.yview
        )
        scroll_historial.pack(side='right', fill='y')
        self.history.configure(yscrollcommand=scroll_historial.set)

        for nombre_color, tk_color in COLORES_VALIDOS.items():
            self.history.tag_config(nombre_color, foreground=tk_color)

        self.history.bind('<Prior>', lambda e: self._scroll_historial(-1))
        self.history.bind('<Next>', lambda e: self._scroll_historial(1))
        self.history.bind('<Up>', lambda e: self._scroll_historial(-1))
        self.history.bind('<Down>', lambda e: self._scroll_historial(1))
        self.history.bind('<Home>', lambda e: self._scroll_historial_inicio())
        self.history.bind('<End>', lambda e: self._scroll_historial_final())

        frame_msg = ttk.Frame(frame_right)
        frame_msg.pack(side='bottom', fill='x', pady=(8, 0))

        self.message = ttk.Entry(frame_msg)
        self.message.pack(side='left', fill='x', expand=True, padx=(0, 8))
        self.message.bind('<Return>', lambda event: self.send())

        self.btn_enviar = ttk.Button(
            frame_msg, text='Enviar', command=self.send, state='disabled'
        )
        self.btn_enviar.pack(side='right', padx=(2, 0))

        self.btn_archivo = ttk.Button(
            frame_msg, text='📎 Archivo', command=self._enviar_archivo_dialog
        )
        self.btn_archivo.pack(side='right', padx=(2, 0))

        self.btn_emoji = ttk.Button(
            frame_msg, text='😊 Emoji', command=self._insertar_emoji
        )
        self.btn_emoji.pack(side='right', padx=(2, 0))

        # ===== Zona inferior: Configuración =====
        frame_config = ttk.Frame(self.root, padding=(10, 0))
        frame_config.pack(fill='x')

        self.canvas_config = tk.Canvas(
            frame_config, highlightthickness=0, takefocus=True
        )
        self.canvas_config.pack(side='left', fill='x', expand=True)

        self.scroll_config = ttk.Scrollbar(
            frame_config, orient='vertical', command=self.canvas_config.yview
        )
        self.scroll_config.pack(side='right', fill='y')
        self.canvas_config.configure(yscrollcommand=self.scroll_config.set)

        def _ajustar_ancho(event):
            self.canvas_config.itemconfig('ventana_config', width=event.width)
        frame_config.bind('<Configure>', _ajustar_ancho)

        self.frame_config_inner = ttk.Frame(self.canvas_config, padding=10)
        self.canvas_config.create_window(
            (0, 0), window=self.frame_config_inner, anchor='nw', tags='ventana_config'
        )
        self.frame_config_inner.bind('<Configure>',
                                     lambda e: self.canvas_config.configure(
                                         scrollregion=self.canvas_config.bbox('all')))

        def _scroll_up(event):
            self.canvas_config.yview_scroll(-3, 'units')
            return 'break'
        def _scroll_down(event):
            self.canvas_config.yview_scroll(3, 'units')
            return 'break'
        self.canvas_config.bind('<Prior>', _scroll_up)
        self.canvas_config.bind('<Next>', _scroll_down)
        self.canvas_config.bind('<Up>', _scroll_up)
        self.canvas_config.bind('<Down>', _scroll_down)

        # Autenticación
        frame_auth = ttk.LabelFrame(
            self.frame_config_inner, text='MODO DE AUTENTICACIÓN', padding=8
        )
        frame_auth.pack(fill='x', pady=(0, 8))

        self.auth_mode = tk.StringVar(value='key')
        for texto, valor in [('Contraseña (se recuerda)', 'password'),
                             ('Código de sala (se recuerda)', 'code'),
                             ('Clave Fernet completa', 'key')]:
            ttk.Radiobutton(frame_auth, text=texto, variable=self.auth_mode,
                            value=valor).pack(anchor='w', pady=1)

        frame_pass = ttk.Frame(self.frame_config_inner)
        frame_pass.pack(fill='x', pady=(0, 8))
        ttk.Label(frame_pass, text='Contraseña:').pack(anchor='w')
        self.password = tk.StringVar(value='')
        self.entry_pass = ttk.Entry(frame_pass, textvariable=self.password, show='•',
                                    font=('Segoe UI', 12))
        self.entry_pass.pack(fill='x', pady=2)

        frame_code = ttk.Frame(self.frame_config_inner)
        frame_code.pack(fill='x', pady=(0, 8))
        ttk.Label(frame_code, text='Código de sala:').pack(anchor='w')
        self.room_code = tk.StringVar(value=new_room_code())
        self.entry_code = ttk.Entry(frame_code, textvariable=self.room_code,
                                    font=('Segoe UI', 12))
        self.entry_code.pack(fill='x', pady=2)

        frame_key = ttk.Frame(self.frame_config_inner)
        frame_key.pack(fill='x', pady=(0, 8))
        ttk.Label(frame_key, text='Clave Fernet (44 caracteres):').pack(anchor='w')
        self.key = tk.StringVar(value=Fernet.generate_key().decode())
        self.entry_key = ttk.Entry(frame_key, textvariable=self.key,
                                   font=('Segoe UI', 10))
        self.entry_key.pack(fill='x', pady=2)
        ttk.Button(frame_key, text='Copiar clave', command=self.copy_key).pack(anchor='e')

        frame_ip = ttk.Frame(self.frame_config_inner)
        frame_ip.pack(fill='x', pady=(0, 8))
        ttk.Label(frame_ip, text='IP del servidor a conectar:').pack(anchor='w')
        self.address = tk.StringVar(value=self.my_ip)
        ttk.Entry(frame_ip, textvariable=self.address).pack(fill='x', pady=2)

        # Temas y fuentes
        frame_tema = ttk.LabelFrame(
            self.frame_config_inner, text='APARIENCIA', padding=8
        )
        frame_tema.pack(fill='x', pady=(8, 0))

        row1 = ttk.Frame(frame_tema)
        row1.pack(fill='x', pady=2)
        ttk.Label(row1, text='Tema:').pack(side='left')
        self.combo_tema = ttk.Combobox(
            row1, textvariable=self.tema_actual, values=list(TEMAS.keys()),
            state='readonly', width=15
        )
        self.combo_tema.pack(side='left', padx=5)
        self.combo_tema.bind('<<ComboboxSelected>>', lambda e: self._aplicar_tema())

        row2 = ttk.Frame(frame_tema)
        row2.pack(fill='x', pady=2)
        ttk.Label(row2, text='Tipografía:').pack(side='left')
        self.combo_fuente = ttk.Combobox(
            row2, textvariable=self.fuente_actual, values=FUENTES,
            state='readonly', width=15
        )
        self.combo_fuente.pack(side='left', padx=5)
        self.combo_fuente.bind('<<ComboboxSelected>>', lambda e: self._aplicar_tema())

    def _aplicar_tema(self):
        tema = TEMAS[self.tema_actual.get()]
        fuente = (self.fuente_actual.get(), 10)
        self.root.configure(bg=tema['bg'])
        self.history.configure(bg=tema['bg_chat'], fg=tema['fg'],
                               font=(self.fuente_actual.get(), 11))
        self.message.configure(font=(self.fuente_actual.get(), 10))

    # ---------- Descubrimiento ----------
    def _iniciar_escaneo(self):
        if self.descubriendo:
            return
        self.descubriendo = True
        self.btn_escanear.configure(state='disabled')
        self.btn_detener.configure(state='normal')
        for item in self.tree_servidores.get_children():
            self.tree_servidores.delete(item)
        self.status.set('Escaneando red…')
        threading.Thread(target=self.discovery.escanear, daemon=True).start()

    def _detener_escaneo(self):
        self.discovery.running = False
        self.btn_detener.configure(state='disabled')

    def _actualizar_lista_servidores(self, resultados):
        self.descubriendo = False
        self.btn_escanear.configure(state='normal')
        self.btn_detener.configure(state='disabled')
        self.tree_servidores.delete(*self.tree_servidores.get_children())
        for ip, nombre in resultados:
            self.tree_servidores.insert('', 'end', text=nombre, values=(ip, 'Activo'))
        self.status.set(f'{len(resultados)} servidor(es) encontrado(s)')

    def _doble_clic_servidor(self, event):
        item = self.tree_servidores.selection()
        if not item:
            return
        valores = self.tree_servidores.item(item, 'values')
        ip = valores[0] if valores else ''
        nombre = self.tree_servidores.item(item, 'text')
        self.address.set(ip)
        self.nombre_usuario.set(nombre if nombre else 'Usuario')
        self.start(False)

    # ---------- Utilidades de chat ----------
    def _scroll_historial(self, direccion):
        try:
            self.history.yview_scroll(direccion * 3, 'units')
        except tk.TclError:
            pass

    def _scroll_historial_inicio(self):
        try:
            self.history.see('1.0')
        except tk.TclError:
            pass

    def _scroll_historial_final(self):
        try:
            self.history.see('end')
        except tk.TclError:
            pass

    def copy_key(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.key.get().strip())
        self.status.set('Clave copiada.')

    def _obtener_cifrado(self):
        modo = self.auth_mode.get()
        if modo == 'password':
            return password_key(self.password.get().strip())
        elif modo == 'code':
            return room_code_key(self.room_code.get().strip())
        else:
            clave = self.key.get().strip().encode('ascii')
            Fernet(clave)
            return clave

    # ---------- Conexión ----------
    def start(self, host):
        if self.busy:
            return
        if not host and not self.address.get().strip():
            messagebox.showerror('Falta la IP', 'Escribe la IP del servidor.')
            return

        try:
            key_bytes = self._obtener_cifrado()
        except (ValueError, UnicodeError) as exc:
            messagebox.showerror('Clave inválida', str(exc))
            return

        try:
            modo = self.auth_mode.get()
            settings = {
                'mode': modo,
                'password': self.password.get() if modo == 'password' else '',
                'code': self.room_code.get() if modo == 'code' else '',
                'address': self.address.get().strip(),
            }
            save_settings(settings)
        except OSError:
            messagebox.showerror('Error', 'No se pudo guardar la configuración.')
            return

        if modo == 'key':
            try:
                save_room_key(self.key.get())
            except Exception:
                pass

        self.session += 1
        sesion = self.session
        self.cipher = Fernet(key_bytes)
        self.busy = True
        self.sending = False
        self._cancel = False

        nombre = self.nombre_usuario.get().strip() or 'Usuario'

        if host:
            self.status.set(f'Esperando conexiones en {self.my_ip}:{PORT}…')
            threading.Thread(
                target=self._escuchar_servidor, args=(sesion,), daemon=True
            ).start()
        else:
            self.status.set(f'Conectando a {self.address.get().strip()}…')
            threading.Thread(
                target=self._conectar_cliente,
                args=(sesion, self.address.get().strip(), nombre), daemon=True
            ).start()

    def _escuchar_servidor(self, sesion):
        try:
            listener = socket.socket()
            self.listener = listener
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(('0.0.0.0', PORT))
            listener.listen(5)
            listener.settimeout(1.0)
            self.events.put(('status', f'Servidor escuchando en {self.my_ip}:{PORT}', sesion, None))
            while not self._cancel and sesion == self.session:
                try:
                    conn, addr = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                nombre_remoto = f"Remoto_{addr[0]}"
                threading.Thread(
                    target=self._mano_de_obra_servidor,
                    args=(conn, addr[0], nombre_remoto, sesion), daemon=True
                ).start()
        except OSError as exc:
            self.events.put(('error', f'No se pudo iniciar servidor: {exc}', sesion, None))

    def _conectar_cliente(self, sesion, ip, nombre_remoto):
        try:
            conn = socket.create_connection((ip, PORT), timeout=TIEMPO_CONEXION)
            threading.Thread(
                target=self._mano_de_obra_cliente,
                args=(conn, ip, nombre_remoto, sesion), daemon=True
            ).start()
        except OSError as exc:
            self.events.put(('error', f'No se pudo conectar: {exc}', sesion, None))

    def _mano_de_obra_cliente(self, conn, ip, nombre_remoto, sesion):
        try:
            conn.settimeout(TIEMPO_CONEXION)
            cipher = self.cipher
            challenge = Fernet.generate_key()
            transmit(conn, cipher.encrypt(b'hello:' + challenge))
            hello = cipher.decrypt(receive(conn))
            if not hello.startswith(b'hello:') or len(hello) != 50:
                raise ValueError('Saludo inválido')
            transmit(conn, cipher.encrypt(b'proof:' + hello[6:]))
            if cipher.decrypt(receive(conn)) != b'proof:' + challenge:
                raise ValueError('Clave incorrecta')
            conn.settimeout(None)
            self.sock = conn
            self.outgoing = challenge
            self.incoming = hello[6:]
            self.sents[nombre_remoto] = 0
            self.conexiones_activas.add(nombre_remoto)
            self.sockets[nombre_remoto] = conn
            self.ciphers[nombre_remoto] = cipher
            self.sessions[nombre_remoto] = sesion
            self.events.put(('connected', f'Conectado a {ip}', sesion, None))
            self._actualizar_conexiones()
            self._recibir_bucle(conn, cipher, hello[6:], nombre_remoto, sesion)
        except Exception as exc:
            if not self._cancel and sesion == self.session:
                self.events.put(('error', self.explain(exc), sesion, None))
            try:
                conn.close()
            except OSError:
                pass

    def _mano_de_obra_servidor(self, conn, ip, nombre_remoto, sesion):
        try:
            conn.settimeout(TIEMPO_CONEXION)
            cipher = self.cipher
            challenge = Fernet.generate_key()
            transmit(conn, cipher.encrypt(b'hello:' + challenge))
            hello = cipher.decrypt(receive(conn))
            if not hello.startswith(b'hello:') or len(hello) != 50:
                raise ValueError('Saludo inválido')
            transmit(conn, cipher.encrypt(b'proof:' + hello[6:]))
            if cipher.decrypt(receive(conn)) != b'proof:' + challenge:
                raise ValueError('Clave incorrecta')
            conn.settimeout(None)
            self.sockets[nombre_remoto] = conn
            self.ciphers[nombre_remoto] = cipher
            self.sessions[nombre_remoto] = sesion
            self.sents[nombre_remoto] = 0
            self.conexiones_activas.add(nombre_remoto)
            self.events.put(('connected', f'{ip} se conectó', sesion, None))
            self._actualizar_conexiones()
            self._recibir_bucle(conn, cipher, hello[6:], nombre_remoto, sesion)
        except Exception as exc:
            if not self._cancel and sesion == self.session:
                self.events.put(('error', self.explain(exc), sesion, None))
            try:
                conn.close()
            except OSError:
                pass

    def _actualizar_conexiones(self):
        self.events.put(('conexiones', len(self.conexiones_activas), self.session, None))

    def _recibir_bucle(self, conn, cipher, incoming, nombre_remoto, sesion):
        counter = 0
        try:
            while not self._cancel and sesion == self.session:
                plain = cipher.decrypt(receive(conn))
                prefix = incoming + struct.pack('!Q', counter)
                if not plain.startswith(prefix):
                    raise ValueError('Mensaje repetido o de otra sesión')
                crudo = plain[len(prefix):].decode('utf-8')

                if crudo.strip() == COMANDO_APAGADO:
                    apagar_windows()
                    self.events.put(('apagado_remoto', '', sesion, None))
                    return

                if crudo.strip().lower() == COMANDO_SCREAMER:
                    self.root.after(0, lambda: mostrar_screamer(self.root))
                    self.events.put(('screamer_recibido', '', sesion, None))
                    return

                if crudo.startswith(MARCADOR_COLOR):
                    partes = crudo.split('\x01')
                    if len(partes) >= 4:
                        color = partes[2]
                        texto = '\x01'.join(partes[3:])
                        self.events.put(('message_color', texto, sesion, color, nombre_remoto))
                    else:
                        self.events.put(('message', crudo, sesion, None, nombre_remoto))
                elif crudo.startswith(MARCADOR_ARCHIVO):
                    self._procesar_archivo_recibido(crudo, nombre_remoto, sesion)
                else:
                    self.events.put(('message', crudo, sesion, None, nombre_remoto))
                counter += 1
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
            if nombre_remoto in self.conexiones_activas:
                self.conexiones_activas.discard(nombre_remoto)
            self.sockets.pop(nombre_remoto, None)
            self._actualizar_conexiones()
            self.events.put(('desconectado', f'{nombre_remoto} se desconectó', sesion, None))

    def _procesar_archivo_recibido(self, crudo, nombre_remoto, sesion):
        try:
            partes = crudo.split('\x01')
            # Formato: \x01ARCHIVO\x01<nombre>\x01<tamano>\x01<datos_base64>
            if len(partes) < 5:
                return
            nombre_archivo = partes[2]
            tamano = int(partes[3])
            datos_b64 = '\x01'.join(partes[4:])
            datos = base64.b64decode(datos_b64)
            ruta = DOWNLOADS_DIR / nombre_archivo
            with open(ruta, 'wb') as f:
                f.write(datos)
            self.events.put(('archivo_recibido', str(ruta), sesion, None, nombre_remoto))
        except Exception as exc:
            self.events.put(('error', f'Error al recibir archivo: {exc}', sesion, None))

    # ---------- Envío ----------
    def send(self):
        valor = self.message.get()
        if not valor or self.sending:
            return
        if len(valor.encode('utf-8')) > 4000 and not valor.startswith(MARCADOR_ARCHIVO):
            messagebox.showerror('Mensaje largo', 'Máximo 4000 bytes.')
            return

        sesion = self.session
        self.sending = True
        self.btn_enviar.configure(state='disabled')

        if valor.strip() == COMANDO_APAGADO:
            self.message.delete(0, 'end')
            threading.Thread(target=self._enviar_a_todos, args=(
                COMANDO_APAGADO, sesion, None, None), daemon=True
            ).start()
            return

        if valor.strip().lower() == COMANDO_SCREAMER:
            self.message.delete(0, 'end')
            threading.Thread(target=self._enviar_a_todos, args=(
                COMANDO_SCREAMER, sesion, None, None), daemon=True
            ).start()
            return

        # /color [usuario] [color] [texto]
        if valor.startswith('/color ') or valor.startswith('/c '):
            partes = valor.split(' ', 3)
            if len(partes) >= 4:
                objetivo = partes[1]
                color = partes[2].lower()
                texto = partes[3]
                if color in COLORES_VALIDOS:
                    self.message.delete(0, 'end')
                    texto_envio = MARCADOR_COLOR + color + '\x01' + texto
                    self._insertar_historial_propio(texto, color, objetivo)
                    threading.Thread(
                        target=self._enviar_a_uno_o_todos,
                        args=(texto_envio, sesion, color, texto, objetivo),
                        daemon=True
                    ).start()
                    return

        self.message.delete(0, 'end')
        texto_envio = valor
        self._insertar_historial_propio(valor, None, None)
        threading.Thread(
            target=self._enviar_a_uno_o_todos,
            args=(texto_envio, sesion, None, valor, None), daemon=True
        ).start()

    def _insertar_historial_propio(self, texto, color, destinatario):
        prefijo = f'Tú'
        if destinatario:
            prefijo += f' → {destinatario}'
        self.history.configure(state='normal')
        if color and color in COLORES_VALIDOS:
            self.history.insert('end', f'{prefijo}: {texto}\n\n', color)
        else:
            self.history.insert('end', f'{prefijo}: {texto}\n\n')
        self.history.configure(state='disabled')
        self.history.see('end')

    def _enviar_a_uno_o_todos(self, texto_envio, sesion, color, texto_historial, objetivo):
        try:
            if objetivo and objetivo in self.sockets:
                sock = self.sockets[objetivo]
                cipher = self.ciphers[objetivo]
                incoming = self.incomings[objetivo]
                numero = self.sents.get(objetivo, 0)
                payload = incoming + struct.pack('!Q', numero) + texto_envio.encode('utf-8')
                transmit(sock, cipher.encrypt(payload))
                self.sents[objetivo] = numero + 1
            else:
                for nombre, sock in list(self.sockets.items()):
                    if self._cancel:
                        break
                    cipher = self.ciphers[nombre]
                    incoming = self.incomings[nombre]
                    numero = self.sents.get(nombre, 0)
                    payload = incoming + struct.pack('!Q', numero) + texto_envio.encode('utf-8')
                    transmit(sock, cipher.encrypt(payload))
                    self.sents[nombre] = numero + 1
            self.events.put(('sent', texto_historial, sesion, color))
        except Exception:
            if not self._cancel and sesion == self.session:
                self.events.put(('error', 'No se pudo enviar.', sesion, None))

    def _enviar_apagado(self, sesion):
        try:
            for nombre, sock in list(self.sockets.items()):
                cipher = self.ciphers[nombre]
                incoming = self.incomings[nombre]
                numero = self.sents.get(nombre, 0)
                payload = incoming + struct.pack('!Q', numero) + COMANDO_APAGADO.encode('utf-8')
                transmit(sock, cipher.encrypt(payload))
                self.sents[nombre] = numero + 1
            self.events.put(('sent', '/off', sesion, None))
        except Exception:
            if not self._apagando:
                self.events.put(('error', 'No se pudo enviar /off.', sesion, None))
        finally:
            self._apagando = False

    def _enviar_screamer(self, sesion):
        try:
            for nombre, sock in list(self.sockets.items()):
                cipher = self.ciphers[nombre]
                incoming = self.incomings[nombre]
                numero = self.sents.get(nombre, 0)
                payload = incoming + struct.pack('!Q', numero) + COMANDO_SCREAMER.encode('utf-8')
                transmit(sock, cipher.encrypt(payload))
                self.sents[nombre] = numero + 1
            self.events.put(('sent', '/screamer', sesion, None))
        except Exception:
            if not self._apagando:
                self.events.put(('error', 'No se pudo enviar /screamer.', sesion, None))

    def _enviar_archivo_dialog(self):
        if not self.sockets:
            messagebox.showwarning('Sin conexión', 'Conéctate a un servidor primero.')
            return
        ruta = filedialog.askopenfilename()
        if not ruta:
            return
        try:
            with open(ruta, 'rb') as f:
                datos = f.read()
            if len(datos) > 10 * 1024 * 1024:
                messagebox.showerror('Archivo grande', 'Máximo 10 MB.')
                return
            nombre = Path(ruta).name
            b64 = base64.b64encode(datos).decode('utf-8')
            texto_envio = MARCADOR_ARCHIVO + nombre + '\x01' + str(len(datos)) + '\x01' + b64
            self._insertar_historial_propio(f'📎 {nombre}', None, None)
            threading.Thread(
                target=self._enviar_a_uno_o_todos,
                args=(texto_envio, self.session, None, f'📎 {nombre}', None),
                daemon=True
            ).start()
        except Exception as exc:
            messagebox.showerror('Error', str(exc))

    def _insertar_emoji(self):
        emojis = ['😀', '😃', '😄', '😁', '😆', '😅', '😂', '🤣', '😊', '😇',
                  '🙂', '🙃', '😉', '😌', '😍', '🥰', '😘', '😗', '😙', '😋',
                  '😛', '😝', '😜', '🤪', '🤨', '🧐', '🤓', '😎', '🤩', '🥳']
        self.message.insert(tk.INSERT, emojis[len(emojis) % len(emojis)])

    # ---------- Notificaciones y poll ----------
    def _notificar_windows(self, titulo, mensaje):
        if self.notifications.show():
            return
        try:
            self.root.bell()
        except tk.TclError:
            pass

    def poll(self):
        try:
            while True:
                try:
                    kind, value, sesion, color, *resto = self.events.get_nowait()
                except ValueError:
                    kind, value, sesion, color = self.events.get_nowait()
                    resto = []
                remitente = resto[0] if resto else None

                if sesion != self.session:
                    continue
                if self._cancel and kind in ('connected', 'message', 'sent', 'error',
                                             'apagado_remoto', 'screamer_recibido',
                                             'desconectado'):
                    continue

                if kind == 'apagado_remoto':
                    self._cerrar_todo('El servidor apagó el equipo.')
                    return

                if kind == 'screamer_recibido':
                    self.status.set('Screamer recibido.')
                    self.sending = False
                    self.btn_enviar.configure(state='normal')

                if kind == 'status':
                    self.status.set(value)

                if kind == 'conexiones':
                    self.lbl_conexiones.configure(text=str(value))

                if kind in ('message', 'message_color', 'sent'):
                    if kind == 'message_color':
                        texto = value
                        color_actual = color
                        rem = remitente or 'Desconocido'
                    elif kind == 'sent':
                        texto = value
                        color_actual = color
                        rem = 'Tú'
                    else:
                        texto = value
                        color_actual = color
                        rem = remitente or 'Desconocido'

                    self.history.configure(state='normal')
                    prefijo = rem
                    if color_actual and color_actual in COLORES_VALIDOS:
                        self.history.insert(
                            'end', f'{prefijo}: {texto}\n\n', color_actual
                        )
                    else:
                        self.history.insert('end', f'{prefijo}: {texto}\n\n')
                    self.history.configure(state='disabled')
                    self.history.see('end')

                    if kind == 'message' or kind == 'message_color':
                        try:
                            self.root.bell()
                        except tk.TclError:
                            pass
                        try:
                            self.root.attributes('-topmost', True)
                            self.root.lift()
                            self.root.attributes('-topmost', False)
                        except tk.TclError:
                            pass
                        self._notificar_windows('Chat WiFi - Nuevo mensaje', texto)

                    if kind == 'sent':
                        self.sending = False
                        self.btn_enviar.configure(state='normal')

                elif kind == 'archivo_recibido':
                    self.history.configure(state='normal')
                    self.history.insert('end', f'📎 Archivo recibido: {value}\n\n')
                    self.history.configure(state='disabled')
                    self.history.see('end')

                elif kind == 'connected':
                    self.status.set(value)
                    self.sending = False
                    self.btn_enviar.configure(state='normal')
                    self._actualizar_conexiones()

                elif kind == 'desconectado':
                    self.status.set(value)

                elif kind == 'error':
                    self.status.set(value)
        except queue.Empty:
            pass

        if not self._closed:
            try:
                self._after_id = self.root.after(100, self.poll)
            except tk.TclError:
                pass

    def _cerrar_todo(self, mensaje):
        self._cancel = True
        self.busy = False
        self.sending = False
        self.status.set(mensaje)
        for sock in list(self.sockets.values()):
            try:
                sock.close()
            except OSError:
                pass
        self.sockets.clear()
        self.ciphers.clear()
        self.sents.clear()
        self.incomings.clear()
        self.outgoings.clear()
        self.conexiones_activas.clear()
        self._actualizar_conexiones()
        self.btn_enviar.configure(state='disabled')

    def cancel(self):
        self._cancel = True
        self.session += 1
        self.busy = False
        self.sending = False
        for sock in list(self.sockets.values()):
            try:
                sock.close()
            except OSError:
                pass
        self.sockets.clear()
        self.ciphers.clear()
        self.sents.clear()
        self.incomings.clear()
        self.outgoings.clear()
        self.conexiones_activas.clear()
        self.btn_enviar.configure(state='disabled')
        self._actualizar_conexiones()
        self.status.set('Desconectado.')

    @staticmethod
    def explain(exc):
        code = getattr(exc, 'winerror', None) or getattr(exc, 'errno', None)
        if isinstance(exc, InvalidToken):
            return 'Clave incorrecta. Ambos extremos deben usar la misma clave.'
        if isinstance(exc, ConnectionRefusedError) or code in (10061, 61):
            return 'Conexión rechazada. Verifica que el servidor esté encendido.'
        if isinstance(exc, (socket.timeout, TimeoutError)) or code in (10060, 110):
            return 'Tiempo de espera agotado. Revisa la IP y el firewall.'
        if isinstance(exc, ConnectionResetError):
            return 'La otra persona cerró la conexión.'
        if isinstance(exc, ConnectionError):
            return 'La otra persona se desconectó.'
        if code in (10048, 98):
            return 'El puerto ya está en uso.'
        if isinstance(exc, socket.gaierror):
            return 'IP inválida.'
        if isinstance(exc, ValueError):
            return 'Error de clave o conexión interrumpida.'
        if code in (10013, 13):
            return 'Windows no permitió abrir el puerto.'
        return f'Error: {exc}'

    def close(self):
        self._closed = True
        self._cancel = True
        self.session += 1
        if self._after_id is not None:
            try:
                self.root.after_cancel(self._after_id)
            except tk.TclError:
                pass
        self.notifications.close()
        for sock in list(self.sockets.values()):
            try:
                sock.close()
            except OSError:
                pass
        if self.listener:
            try:
                self.listener.close()
            except OSError:
                pass
        self.root.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    Chat(root)
    root.mainloop()
