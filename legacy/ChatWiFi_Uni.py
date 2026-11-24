"""
Chat WiFi Local - Aplicacion para PC
Permite enviarse mensajes entre dos computadoras conectadas a la misma red WiFi
(sin necesidad de internet). Una PC actua como servidor y la otra como cliente.

Requisitos: Python 3 (incluye tkinter y sockets por defecto)
Uso: python ChatWiFi_Uni.py
"""

import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, simpledialog

PUERTO_DEFECTO = 5000


class ChatWiFi:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat WiFi Local - Universidad")
        self.root.geometry("520x620")
        self.root.resizable(True, True)

        # Estado de conexion
        self.sock = None
        self.conn = None
        self.conectado = False
        self.es_servidor = False
        self.hilo_recepcion = None

        self._construir_interfaz()

    # ---------- Interfaz ----------
    def _construir_interfaz(self):
        # Panel superior: modo y conexion
        frame_top = ttk.Frame(self.root, padding=10)
        frame_top.pack(fill=tk.X)

        # Modo
        ttk.Label(frame_top, text="Modo:").grid(row=0, column=0, sticky=tk.W)
        self.var_modo = tk.StringVar(value="cliente")
        rb_servidor = ttk.Radiobutton(
            frame_top, text="Servidor (espera al compañero)",
            variable=self.var_modo, value="servidor", command=self._cambiar_modo
        )
        rb_cliente = ttk.Radiobutton(
            frame_top, text="Cliente (se conecta al compañero)",
            variable=self.var_modo, value="cliente", command=self._cambiar_modo
        )
        rb_servidor.grid(row=0, column=1, sticky=tk.W, padx=(10, 5))
        rb_cliente.grid(row=0, column=2, sticky=tk.W, padx=5)

        # IP
        ttk.Label(frame_top, text="IP:").grid(row=1, column=0, sticky=tk.W, pady=(8, 0))
        self.entry_ip = ttk.Entry(frame_top, width=20)
        self.entry_ip.insert(0, "127.0.0.1")
        self.entry_ip.grid(row=1, column=1, columnspan=2, sticky=tk.W, pady=(8, 0))

        # Puerto
        ttk.Label(frame_top, text="Puerto:").grid(row=2, column=0, sticky=tk.W, pady=(8, 0))
        self.entry_puerto = ttk.Entry(frame_top, width=10)
        self.entry_puerto.insert(0, str(PUERTO_DEFECTO))
        self.entry_puerto.grid(row=2, column=1, sticky=tk.W, pady=(8, 0))

        # Boton conectar / iniciar
        self.btn_conexion = ttk.Button(
            frame_top, text="Iniciar Servidor", command=self._alternar_conexion
        )
        self.btn_conexion.grid(row=3, column=0, columnspan=3, pady=(12, 0), sticky=tk.EW)

        # Estado
        self.lbl_estado = ttk.Label(
            frame_top, text="Desconectado", foreground="red"
        )
        self.lbl_estado.grid(row=4, column=0, columnspan=3, pady=(6, 0))

        for i in range(3):
            frame_top.columnconfigure(i, weight=1)

        # Panel medio: chat
        frame_chat = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        frame_chat.pack(fill=tk.BOTH, expand=True)

        self.txt_chat = scrolledtext.ScrolledText(
            frame_chat, wrap=tk.WORD, state="disabled", height=20, font=("Segoe UI", 10)
        )
        self.txt_chat.pack(fill=tk.BOTH, expand=True)

        # Panel inferior: escribir y enviar
        frame_bottom = ttk.Frame(self.root, padding=10)
        frame_bottom.pack(fill=tk.X)

        self.entry_msg = ttk.Entry(frame_bottom, font=("Segoe UI", 10))
        self.entry_msg.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.entry_msg.bind("<Return>", lambda e: self._enviar())

        self.btn_enviar = ttk.Button(
            frame_bottom, text="Enviar", command=self._enviar, state="disabled"
        )
        self.btn_enviar.pack(side=tk.RIGHT)

        # Barra de estado inferior
        self.lbl_info = ttk.Label(
            self.root, text="Consejo: ambos deben estar en la misma WiFi de la universidad",
            relief=tk.SUNKEN, anchor=tk.W, padding=(5, 3)
        )
        self.lbl_info.pack(fill=tk.X, side=tk.BOTTOM)

        # Inicializar modo
        self._cambiar_modo()

    def _cambiar_modo(self):
        modo = self.var_modo.get()
        if modo == "servidor":
            self.btn_conexion.config(text="Iniciar Servidor")
            self.entry_ip.config(state="normal")
            self.entry_ip.delete(0, tk.END)
            self.entry_ip.insert(0, self._obtener_ip_local())
        else:
            self.btn_conexion.config(text="Conectar")
            self.entry_ip.config(state="normal")
            self.entry_ip.delete(0, tk.END)
            self.entry_ip.insert(0, "127.0.0.1")

    # ---------- Red ----------
    def _obtener_ip_local(self):
        """Intenta obtener la IP local de la maquina en la red WiFi."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _alternar_conexion(self):
        if self.conectado:
            self._desconectar()
        else:
            self._conectar()

    def _conectar(self):
        ip = self.entry_ip.get().strip()
        puerto_txt = self.entry_puerto.get().strip()

        if not ip or not puerto_txt:
            messagebox.showerror("Error", "Ingresa IP y puerto.")
            return

        try:
            puerto = int(puerto_txt)
        except ValueError:
            messagebox.showerror("Error", "Puerto invalido.")
            return

        modo = self.var_modo.get()

        try:
            if modo == "servidor":
                self._iniciar_servidor(ip, puerto)
            else:
                self._iniciar_cliente(ip, puerto)
        except Exception as e:
            messagebox.showerror("Error de conexion", str(e))
            self._actualizar_estado("Error", "red")

    def _iniciar_servidor(self, ip, puerto):
        self.es_servidor = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((ip, puerto))
        self.sock.listen(1)

        self._escribir_chat("Sistema", f"Esperando conexion en {ip}:{puerto}...")
        self._actualizar_estado("Esperando compañero...", "amarillo")

        # Hilo para aceptar la conexion entrante (no bloquea la UI)
        self.hilo_recepcion = threading.Thread(target=self._aceptar_conexion, daemon=True)
        self.hilo_recepcion.start()

    def _aceptar_conexion(self):
        try:
            conn, addr = self.sock.accept()
            self._establecer_conexion(conn, addr[0])
            self.root.after(0, lambda: self._escribir_chat("Sistema", f"Compañero conectado desde {addr[0]}"))
            self.root.after(0, lambda: self._actualizar_estado("Conectado", "verde"))
            self.root.after(0, self._habilitar_envio)
            self._recibir_mensajes(conn)
        except Exception as e:
            self.root.after(0, lambda: self._escribir_chat("Sistema", f"Error al aceptar: {e}"))
            self.root.after(0, lambda: self._actualizar_estado("Error", "red"))

    def _iniciar_cliente(self, ip, puerto):
        self.es_servidor = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((ip, puerto))
        self._establecer_conexion(self.sock, ip)
        self._escribir_chat("Sistema", f"Conectado a {ip}:{puerto}")
        self._actualizar_estado("Conectado", "verde")
        self._habilitar_envio()
        self._recibir_mensajes(self.sock)

    def _establecer_conexion(self, conn, ip_remota):
        self.conn = conn
        self.conectado = True
        self.entry_ip.config(state="disabled")
        self.entry_puerto.config(state="disabled")
        self.btn_conexion.config(text="Desconectar")

    def _recibir_mensajes(self, conn):
        """Bucle de recepcion en hilo separado."""
        while self.conectado:
            try:
                datos = conn.recv(1024)
                if not datos:
                    break
                mensaje = datos.decode("utf-8")
                # Actualizar UI de forma segura desde el hilo principal
                self.root.after(0, lambda m=mensaje: self._escribir_chat("Compañero", m))
            except (OSError, ConnectionError):
                break
        self.root.after(0, self._desconectar)

    # ---------- UI ----------
    def _enviar(self):
        mensaje = self.entry_msg.get().strip()
        if not mensaje:
            return
        if not self.conectado or not self.conn:
            messagebox.showwarning("Sin conexión", "No hay conexión activa.")
            return

        try:
            self.conn.sendall(mensaje.encode("utf-8"))
            self._escribir_chat("Tú", mensaje)
            self.entry_msg.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error al enviar", str(e))
            self._desconectar()

    def _escribir_chat(self, remitente, texto):
        self.txt_chat.config(state="normal")
        self.txt_chat.insert(tk.END, f"{remitente}: {texto}\n")
        self.txt_chat.config(state="disabled")
        self.txt_chat.see(tk.END)

    def _habilitar_envio(self):
        self.btn_enviar.config(state="normal")
        self.entry_msg.focus_set()

    def _desconectar(self):
        self.conectado = False
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        self.conn = None
        self.sock = None

        self.entry_ip.config(state="normal")
        self.entry_puerto.config(state="normal")
        self.btn_conexion.config(text="Iniciar Servidor" if self.es_servidor else "Conectar")
        self.btn_enviar.config(state="disabled")
        self._actualizar_estado("Desconectado", "rojo")
        self._escribir_chat("Sistema", "Conexión finalizada.")

    def _actualizar_estado(self, texto, color):
        colores = {"rojo": "red", "verde": "green", "amarillo": "orange", "red": "red", "green": "green", "orange": "orange"}
        self.lbl_estado.config(text=texto, foreground=colores.get(color, "black"))

    def on_closing(self):
        self._desconectar()
        self.root.destroy()


def main():
    root = tk.Tk()
    app = ChatWiFi(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()