import socket
import struct
import threading
import queue
import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet

PORT = 45873
LIMIT = 32768


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


class Chat:
    def __init__(self, root):
        self.root = root
        self.events = queue.Queue()
        self.sock = None
        self.listener = None
        self.busy = False
        self.sending = False
        root.title('Chat privado · Wi-Fi')
        root.geometry('720x620')
        frame = ttk.Frame(root, padding=16)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Chat privado para dos', font=('Segoe UI', 18)).pack(anchor='w')
        ttk.Label(frame, text='Uno crea la sala y comparte la clave en persona con su amigo.').pack(anchor='w', pady=8)
        self.address = tk.StringVar(value='192.168.1.10')
        self.key = tk.StringVar(value=Fernet.generate_key().decode())
        ttk.Label(frame, text='IP del computador que crea la sala:').pack(anchor='w')
        ttk.Entry(frame, textvariable=self.address).pack(fill='x', pady=4)
        ttk.Label(frame, text='Clave secreta de la sala (compartan la clave completa):').pack(anchor='w')
        ttk.Entry(frame, textvariable=self.key).pack(fill='x', pady=4)
        buttons = ttk.Frame(frame)
        buttons.pack(fill='x', pady=8)
        self.host_button = ttk.Button(buttons, text='Crear sala', command=lambda: self.start(True))
        self.host_button.pack(side='left')
        self.join_button = ttk.Button(buttons, text='Conectarme', command=lambda: self.start(False))
        self.join_button.pack(side='left', padx=8)
        self.status = tk.StringVar(value='Sin conexión')
        ttk.Label(frame, textvariable=self.status, wraplength=660).pack(anchor='w', pady=5)
        self.history = tk.Text(frame, state='disabled', wrap='word', font=('Segoe UI', 11))
        self.history.pack(fill='both', expand=True)
        self.message = ttk.Entry(frame)
        self.message.pack(fill='x', pady=8)
        self.message.bind('<Return>', lambda event: self.send())
        self.send_button = ttk.Button(frame, text='Enviar', command=self.send, state='disabled')
        self.send_button.pack(anchor='e')
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.after(100, self.poll)

    def start(self, host):
        if self.busy:
            return
        try:
            self.cipher = Fernet(self.key.get().strip().encode('ascii'))
        except Exception:
            messagebox.showerror('Clave inválida', 'Copia la clave completa del computador que crea la sala.')
            return
        self.busy = True
        self.host_button.configure(state='disabled')
        self.join_button.configure(state='disabled')
        self.status.set('Esperando a tu amigo…' if host else 'Conectando…')
        address = self.address.get().strip()
        threading.Thread(target=self.connect, args=(host, address), daemon=True).start()

    def connect(self, host, address):
        conn = None
        try:
            if host:
                self.listener = socket.socket()
                self.listener.bind(('0.0.0.0', PORT))
                self.listener.listen(1)
                conn, _ = self.listener.accept()
                self.listener.close()
            else:
                conn = socket.create_connection((address, PORT), timeout=15)
            conn.settimeout(15)
            # Both peers must prove possession of the room key before chatting.
            challenge = Fernet.generate_key()
            transmit(conn, self.cipher.encrypt(b'hello:' + challenge))
            hello = self.cipher.decrypt(receive(conn))
            if not hello.startswith(b'hello:') or len(hello) != 50:
                raise ValueError('Saludo inválido')
            transmit(conn, self.cipher.encrypt(b'proof:' + hello[6:]))
            if self.cipher.decrypt(receive(conn)) != b'proof:' + challenge:
                raise ValueError('Clave incorrecta')
            # Bind each message to this connection and its sender.
            outgoing = challenge
            incoming = hello[6:]
            conn.settimeout(None)
            self.sock = conn
            self.outgoing = outgoing
            self.events.put(('connected', 'Conectado. Los mensajes no se guardan en archivos.'))
            counter = 0
            while True:
                plain = self.cipher.decrypt(receive(conn))
                prefix = incoming + struct.pack('!Q', counter)
                if not plain.startswith(prefix):
                    raise ValueError('Mensaje repetido o de otra sesión')
                self.events.put(('message', plain[len(prefix):].decode('utf-8')))
                counter += 1
        except Exception as exc:
            self.events.put(('error', 'Conexión cerrada. Comprueba la IP, el Wi-Fi y que ambos tengan la misma clave. ' + type(exc).__name__))
        finally:
            if conn:
                conn.close()
            if self.listener:
                self.listener.close()

    def send(self):
        value = self.message.get().strip()
        if not value or not self.sock or self.sending:
            return
        if len(value.encode('utf-8')) > 4000:
            messagebox.showerror('Mensaje largo', 'Usa como máximo 4000 bytes por mensaje.')
            return
        self.sending = True
        self.send_button.configure(state='disabled')
        self.message.delete(0, 'end')
        threading.Thread(target=self.send_worker, args=(value,), daemon=True).start()

    def send_worker(self, value):
        try:
            number = getattr(self, 'sent', 0)
            payload = self.outgoing + struct.pack('!Q', number) + value.encode('utf-8')
            transmit(self.sock, self.cipher.encrypt(payload))
            self.sent = number + 1
            self.events.put(('sent', value))
        except Exception:
            self.events.put(('error', 'No se pudo enviar el mensaje. Cierra y vuelve a abrir el chat.'))

    def poll(self):
        while not self.events.empty():
            kind, value = self.events.get()
            if kind in ('message', 'sent'):
                self.history.configure(state='normal')
                self.history.insert('end', ('Amigo: ' if kind == 'message' else 'Tú: ') + value + '\n\n')
                self.history.configure(state='disabled')
                self.history.see('end')
            else:
                self.status.set(value)
            if kind in ('connected', 'sent'):
                self.sending = False
                self.send_button.configure(state='normal')
            if kind == 'error':
                self.sock = None
                self.send_button.configure(state='disabled')
        self.root.after(100, self.poll)

    def close(self):
        if self.sock:
            self.sock.close()
        if self.listener:
            self.listener.close()
        self.root.destroy()


if __name__ == '__main__':
    window = tk.Tk()
    Chat(window)
    window.mainloop()
