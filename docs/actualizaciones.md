# Actualizaciones automáticas (GitHub Releases)

Chat WiFi 2.4.0 comprueba si hay una versión nueva al iniciar y desde
**Ajustes → Otros → Buscar actualizaciones**.

## Requisito: repositorio público

La app consulta esta URL sin autenticarse:

```text
https://github.com/Juedorigamer/ChatWifi/releases/latest/download/latest.json
```

Por eso el repositorio **debe ser público**. Si es privado, GitHub devuelve
404 y la app no puede actualizar a los amigos. Revisa:

```text
https://github.com/Juedorigamer/ChatWifi
```

Si no carga sin iniciar sesión, está privado. En GitHub:
**Settings → General → Danger Zone → Change visibility → Public**.

## Formato de latest.json

Cada release debe incluir un asset llamado exactamente `latest.json`:

```json
{
  "version": "2.4.1",
  "url": "https://github.com/Juedorigamer/ChatWifi/releases/download/v2.4.1/ChatWiFi_Setup_2.4.1.exe",
  "sha256": "hash_del_instalador_en_minusculas",
  "notes": "Corrige la reconexión Online y la búsqueda LAN.",
  "published": "2026-11-10"
}
```

- `version`: se compara con `APP_VERSION` de `chat.py`.
- `url`: descarga directa del instalador (HTTPS).
- `sha256`: obligatorio; la app rechaza el archivo si no coincide.
- `notes`: texto que verá el usuario.
- `published`: informativo.

## Publicar una versión

1. Sube `APP_VERSION` en `chat.py` y `MyAppVersion` en
   `installer/ChatWiFi.iss`.
2. Reconstruye:

   ```powershell
   python -m PyInstaller ChatWiFi.spec --noconfirm
   & "C:\Program Files\Inno Setup 7\ISCC.exe" installer\ChatWiFi.iss
   ```

3. Genera `latest.json` y publica:

   ```powershell
   .\publicar_actualizacion.ps1 -Notes "Novedades de esta versión"
   ```

   Sin `GITHUB_TOKEN`, el script solo genera `dist\latest.json` y muestra los
   pasos para subirlo a mano.

4. Con token (permiso **Contents: Read and write**):

   ```powershell
   $env:GITHUB_TOKEN = "ghp_..."
   .\publicar_actualizacion.ps1 -Notes "Novedades"
   ```

5. Verifica que la release no sea borrador ni prerelease. La URL
   `releases/latest/download/latest.json` debe abrir el JSON.

## Qué hace la app

1. Consulta `latest.json` a los 5 segundos de arrancar (si está activado).
2. Compara versiones numéricas.
3. Si hay una nueva, muestra las notas y pregunta.
4. Descarga a `%TEMP%`, verifica SHA-256 y ejecuta el instalador con
   `/SILENT /CLOSEAPPLICATIONS`.
5. La app se cierra; el instalador actualiza sobre la misma carpeta y la
   vuelve a abrir.

## Limitación de SmartScreen

El instalador no está firmado digitalmente. Aunque la app lo descargue y
verifique, Windows puede mostrar SmartScreen la primera vez:

**Más información → Ejecutar de todas formas**

Para una actualización totalmente silenciosa hace falta un certificado de
firma de código. No se debe incrustar un token de GitHub en la app.

## Probar el actualizador

1. Instala la versión 2.4.0.
2. Publica una release 2.4.1 con su `latest.json`.
3. Abre la app y pulsa **Ajustes → Otros → Buscar actualizaciones**.
4. Debe detectar 2.4.1, descargar, verificar y abrir el instalador.
