"""Servidor local de la beta Android de Chat WiFi.

Sirve únicamente android_beta.html por HTTP y HTTPS en los puertos 8000 y 8443.
El HTTPS usa un certificado autofirmado para el caso de que Chrome fuerce
HTTPS; el teléfono pedirá aceptar la advertencia una vez.

Cada puerto detecta si la conexión es HTTP o TLS, así la misma URL funciona
con http:// y con https://.

Uso:
    python android_beta_server.py
"""

from __future__ import annotations

import functools
import http.server
import ipaddress
import socket
import ssl
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
BETA_FILE = ROOT / "android_beta.html"
HTTP_PORT = 8000
HTTPS_PORT = 8443
CERT_DIR = Path(tempfile.gettempdir()) / "chatwifi_beta_certs"
CERT_FILE = CERT_DIR / "beta_cert.pem"
KEY_FILE = CERT_DIR / "beta_key.pem"
IP_FILE = CERT_DIR / "beta_ip.txt"


def local_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        finally:
            sock.close()
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def ensure_certificate(ip: str) -> None:
    """Genera un certificado autofirmado para la IP actual."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    CERT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        saved_ip = IP_FILE.read_text(encoding="utf-8").strip()
    except Exception:
        saved_ip = ""

    if CERT_FILE.exists() and KEY_FILE.exists() and saved_ip == ip:
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Chat WiFi Beta"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Chat WiFi"),
    ])
    now = datetime.now(timezone.utc)
    san = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    try:
        san.append(x509.IPAddress(ipaddress.ip_address(ip)))
    except ValueError:
        san.append(x509.DNSName(ip))
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    KEY_FILE.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    CERT_FILE.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    IP_FILE.write_text(ip, encoding="utf-8")


class BetaHandler(http.server.SimpleHTTPRequestHandler):
    """Expone solo la beta, no el resto del proyecto."""

    def translate_path(self, path: str) -> str:
        clean = urlparse(path).path
        if clean in ("/", "/index.html", "/android_beta.html"):
            return str(BETA_FILE)
        return str(ROOT / "__archivo_no_disponible__")

    def log_message(self, fmt: str, *args) -> None:
        if args and isinstance(args[0], str) and args[0].startswith(("GET ", "HEAD ")):
            sys.stdout.write("%s - %s\n" % (self.address_string(), fmt % args))
            sys.stdout.flush()

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()


class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    ssl_context = None

    def get_request(self):
        """Acepta HTTP y HTTPS en el mismo puerto.

        Chrome Android a veces cambia http:// por https://. Si el primer byte
        es un ClientHello TLS (0x16), envolvemos el socket; si no, se atiende
        como HTTP normal.
        """
        sock, addr = self.socket.accept()
        if self.ssl_context is not None:
            try:
                first = sock.recv(1, socket.MSG_PEEK)
            except OSError:
                first = b""
            if first and first[0] == 0x16:
                try:
                    sock = self.ssl_context.wrap_socket(sock, server_side=True)
                except Exception as exc:
                    try:
                        sock.close()
                    except Exception:
                        pass
                    raise OSError("TLS handshake fallido") from exc
        return sock, addr


def serve(server: ThreadingHTTPServer, label: str) -> None:
    try:
        server.serve_forever(poll_interval=0.5)
    except Exception as exc:
        print(f"[{label}] detenido: {exc}", flush=True)


def main() -> int:
    if not BETA_FILE.exists():
        print(f"No se encontró {BETA_FILE}", flush=True)
        return 1

    ip = local_ip()
    handler = functools.partial(BetaHandler, directory=str(ROOT))

    try:
        httpd = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), handler)
    except OSError as exc:
        print(f"No se pudo abrir HTTP {HTTP_PORT}: {exc}", flush=True)
        return 1

    httpsd = None
    context = None
    try:
        ensure_certificate(ip)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    except Exception as exc:
        print(f"HTTPS no disponible: {exc}", flush=True)

    httpd.ssl_context = context
    try:
        httpsd = ThreadingHTTPServer(("0.0.0.0", HTTPS_PORT), handler)
        httpsd.ssl_context = context
    except Exception as exc:
        print(f"Puerto alternativo {HTTPS_PORT} no disponible: {exc}", flush=True)
        httpsd = None

    print()
    print("  Chat WiFi - Beta Android")
    print("  ========================")
    print()
    print("  Abre en Chrome del teléfono:")
    print(f"      http://{ip}:{HTTP_PORT}/android_beta.html")
    print()
    if context is not None:
        print("  Si Chrome cambia a HTTPS, esta misma dirección también sirve:")
        print(f"      https://{ip}:{HTTP_PORT}/android_beta.html")
        print("      Acepta la advertencia de certificado una vez.")
        if httpsd is not None:
            print(f"      https://{ip}:{HTTPS_PORT}/android_beta.html")
        print()
    print("  PC y teléfono: misma Wi-Fi. La beta necesita Internet para Supabase.")
    print("  Mantén esta ventana abierta. Ctrl+C para detener.")
    print()

    threads = [threading.Thread(target=serve, args=(httpd, "HTTP"), daemon=True)]
    if httpsd is not None:
        threads.append(threading.Thread(target=serve, args=(httpsd, "HTTPS"), daemon=True))
    for thread in threads:
        thread.start()

    try:
        while any(thread.is_alive() for thread in threads):
            threads[0].join(timeout=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        for server in (httpd, httpsd):
            if server is not None:
                try:
                    server.shutdown()
                except Exception:
                    pass
                try:
                    server.server_close()
                except Exception:
                    pass
        print("\nServidor detenido.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
