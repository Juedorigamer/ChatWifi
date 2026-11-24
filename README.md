# Chat WiFi

Chat de escritorio para Windows con dos modos:

- **LAN:** conexión directa entre PCs de la misma WiFi, sin Internet.
- **Online:** salas privadas con Supabase Realtime, desde cualquier red.

Los mensajes y archivos van cifrados de extremo a extremo (Fernet). Incluye
beta Android (página web) y actualizaciones automáticas desde GitHub Releases.

## Descargar

La última versión está en la pestaña **Releases** de este repositorio:

- `ChatWiFi_Setup_2.4.7.exe` — instalador.
- `latest.json` — manifiesto de actualizaciones.

No hace falta instalar Python: el instalador incluye todo.

## Reconstruir desde el código

Requisitos:

- Python 3.11 o superior.
- Windows 10/11 de 64 bits.

```powershell
python -m pip install -r requirements.txt
python -m PyInstaller ChatWiFi.spec --noconfirm
& "C:\Program Files\Inno Setup 7\ISCC.exe" installer\ChatWiFi.iss
```

El instalador queda en `dist\ChatWiFi_Setup_<versión>.exe`.

## Publicar una actualización

1. Sube `APP_VERSION` en `chat.py` y `MyAppVersion` en `installer\ChatWiFi.iss`.
2. Compila con PyInstaller e Inno Setup.
3. Publica:

```powershell
$env:GITHUB_TOKEN = "ghp_..."
.\publicar_actualizacion.ps1 -Notes "Novedades de la versión"
```

Sin token, el script genera `dist\latest.json` y muestra los pasos para subir
los archivos a mano.

## Seguridad

- La app usa solo la clave **publicable** de Supabase; nunca la `service_role`.
- El secreto de la sala no se guarda en disco.
- Los mensajes y archivos van cifrados con Fernet antes de salir del equipo.
- La seguridad real está en las políticas RLS de Supabase, no en esconder la URL.
- No subas nunca tokens, claves de servicio ni el archivo de ajustes local.

## Estructura

```text
chat.py                  App de escritorio (PyQt6)
supabase_realtime.py     Capa online (Supabase Realtime + Storage)
message_protocol.py      Sobre común de mensajes LAN/Online
estilos_chat.css         Temas y estilos
installer/ChatWiFi.iss   Instalador (Inno Setup)
android_beta.html        Beta móvil (se abre en Chrome)
android_beta_server.py   Servidor local de la beta Android
docs/                    Guías, capturas y análisis
requirements.txt         Dependencias
legacy/                  Versiones antiguas conservadas
```

## Notas

- El modo Online usa Supabase gratuito: 200 conexiones, 2 millones de
  mensajes/mes, 1 GB de Storage y 50 MB por archivo.
- El proyecto se pausa tras 7 días sin actividad.
- Sin firma digital, SmartScreen puede pedir “Más información → Ejecutar de
  todas formas”.
