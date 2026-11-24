# Beta Android de Chat WiFi

Beta mÃ³vil para probar **conexiÃ³n y chat de texto** contra las mismas salas de
Supabase que usa la app de escritorio. No sustituye a Chat WiFi 2.4.0.

## Archivos

| Archivo | Uso |
|---|---|
| `android_beta.html` | Toda la beta: interfaz, cifrado Fernet, auth anÃ³nima, Realtime y chat. |
| `android_beta_server.py` | Servidor local que atiende HTTP y HTTPS en el mismo puerto. |
| `android_beta_server.cmd` | Arranca el servidor local y muestra la URL para el telÃ©fono. |
| `docs/android_beta.md` | Esta guÃ­a. |

No se instalÃ³ nada en el flujo de OpenCode, no se creÃ³ `AGENTS.md`, no se
ejecutÃ³ `graphify install` y no se modificÃ³ la app de escritorio.

## CÃ³mo abrirla en Android

1. Conecta la PC y el telÃ©fono a la misma Wi-Fi.
2. En la PC, ejecuta `android_beta_server.cmd`.
3. Abre en Chrome del telÃ©fono la URL que muestra la ventana negra, por ejemplo:

   ```text
   http://192.168.100.158:8000/android_beta.html
   ```

   La IP puede cambiar. El script la detecta al arrancar; si no, ejecuta
   `ipconfig` y usa la IPv4 de Wi-Fi/Ethernet.

   El servidor acepta **HTTP y HTTPS en el mismo puerto**. Si Chrome cambia
   automÃ¡ticamente a HTTPS, la misma URL con `https://` tambiÃ©n funciona:

   ```text
   https://192.168.100.158:8000/android_beta.html
   ```

   La primera vez Chrome mostrarÃ¡ una advertencia por el certificado
   autofirmado. Pulsa **Avanzado â†’ Continuar** (o â€œContinuar a â€¦â€). TambiÃ©n
   estÃ¡ disponible `https://192.168.100.158:8443/android_beta.html`.

   Importante: el puerto **8000** ahora acepta tanto `http://` como `https://`.
   El puerto **8443** queda como alternativa.

4. Opcional: Chrome â†’ menÃº â‹® â†’ **AÃ±adir a pantalla de inicio** para tener un
   acceso directo. No es un APK ni una PWA instalable completa.

El telÃ©fono necesita Internet porque Supabase estÃ¡ en la nube. El servidor
local solo entrega el HTML; los mensajes no pasan por la PC.

TambiÃ©n se puede abrir desde la propia PC con
`http://localhost:8000/android_beta.html`.

## Prueba con la app de escritorio

1. En la PC abre Chat WiFi 2.4.0.
2. **Servidores â†’ Online**.
3. Escribe el secreto y pulsa **Crear sala**.
4. Copia el cÃ³digo de 6 caracteres.
5. En el telÃ©fono escribe tu nombre, el mismo cÃ³digo y el mismo secreto.
6. Pulsa **Unirse a la sala**.
7. En la PC abre **ADMINISTRAR SALA** y aprueba al miembro.
8. La beta sale de â€œEsperando aprobaciÃ³nâ€ y entra al chat.
9. Prueba texto en ambos sentidos, presencia, salir y volver a entrar.

La beta muestra â€œEsperando aprobaciÃ³nâ€ y consulta cada 3 segundos, igual que el
escritorio.

## Crear una sala desde Android

El botÃ³n **Crear sala de prueba**:

- Genera un cÃ³digo de 6 caracteres con el alfabeto del escritorio.
- Crea la sala sin aprobaciÃ³n, para pruebas rÃ¡pidas entre telÃ©fonos.
- La sala caduca a las 24 horas.
- Muestra el cÃ³digo; al tocarlo se copia.
- Comparte tambiÃ©n el secreto para que la PC pueda entrar.

La PC puede unirse a esa sala con **Unirse** usando el cÃ³digo y el secreto.

## Alcance de la beta

Incluido:

- Nombre, cÃ³digo de sala y secreto.
- Login anÃ³nimo persistente.
- Unirse a salas del escritorio y crear salas de prueba.
- AprobaciÃ³n del administrador con sondeo cada 3 s.
- Canal privado de Supabase Realtime.
- Presencia y lista de usuarios.
- Mensajes de texto cifrados con Fernet, compatibles con Chat WiFi 2.4.0.
- Avisos de cierre de sala y expulsiÃ³n.
- Latido cada 30 s para detectar cierre, expiraciÃ³n o retirada de acceso.
- ReconexiÃ³n bÃ¡sica de Realtime y aviso de â€œSin Internetâ€.
- Copia del cÃ³digo de sala y ocultar/mostrar el secreto.

No incluido todavÃ­a:

- Archivos, miniaturas, enlaces firmados o descargas.
- AdministraciÃ³n desde el telÃ©fono (aprobar, expulsar, cerrar).
- Historial persistente, bÃºsqueda o exportaciÃ³n.
- Reacciones, respuestas citadas, TTL, leÃ­dos o â€œescribiendoâ€¦â€.
- Notificaciones, llamadas, QR o APK.
- Varias salas a la vez.

## Compatibilidad con el escritorio

La beta replica el protocolo de `supabase_realtime.py`:

- Auth anÃ³nima en `auth/v1/signup`.
- RPC `chat_join_room` / `chat_create_room`.
- Tema del canal:
  `chatwifi:` + primeros 24 hex de `SHA-256(cÃ³digo + ":" + secreto)`.
- Canal privado con `broadcast.self = false`, `ack = true` y presencia.
- Broadcast `message` con `{ from, data }`, donde `data` es base64 del token
  Fernet.
- Sobre JSON `{ v: 1, kind, id, ts, ... }`.
- Fernet: PBKDF2-HMAC-SHA256, sal `chatwifi_salt`, 100000 iteraciones, 32 bytes;
  AES-128-CBC + HMAC-SHA256.

Se usa CryptoJS en lugar de Web Crypto porque la beta se sirve por HTTP en la
LAN. `window.crypto.subtle` no existe en un contexto no seguro; CryptoJS sÃ­
funciona y se probÃ³ la interoperabilidad en ambos sentidos con Python. El
servidor tambiÃ©n ofrece HTTPS con certificado autofirmado para cuando Chrome
fuerza el esquema seguro.

## Seguridad

- Solo se usa la clave publicable de Supabase; nunca la `service_role`.
- El secreto no se guarda en `localStorage`; solo el nombre y el Ãºltimo cÃ³digo.
- El secreto sÃ­ queda en memoria mientras la pestaÃ±a estÃ¡ abierta, igual que en
  la app de escritorio.
- Los mensajes van cifrados de extremo a extremo con Fernet. Supabase ve el
  canal y el trÃ¡fico, no el texto.
- La beta no implementa anti-captura ni borrado remoto de mensajes.

## Pruebas realizadas

Fecha: 2026-11-08.

- Clave derivada idÃ©ntica a Python (`PBKDF2` con el mismo secreto).
- Token Fernet generado por Python â†’ descifrado correctamente en Chrome.
- Token generado en Chrome â†’ descifrado correctamente por Python.
- Sala creada con el protocolo del escritorio â†’ beta se une, ve presencia y
  recibe texto.
- Mensaje desde la beta â†’ cliente Python del protocolo del escritorio lo
  descifra y lo recibe.
- Sala con aprobaciÃ³n obligatoria â†’ beta espera, el administrador aprueba desde
  RPC y la beta entra automÃ¡ticamente.
- Crear sala desde la beta â†’ canal privado, presencia y envÃ­o funcionando.
- Origen `http://192.168.100.158:8000` (contexto no seguro) â†’ auth, RPC, canal y
  chat funcionando.
- Mismo puerto 8000 atendiendo HTTP y HTTPS, y 8443 como alternativa.
- Dos clientes en la misma sala â†’ lista de usuarios y mensajes en ambos.

Quedaron salas de prueba abiertas en Supabase (`TSTB23`, `TSTA24` y `MYRWGZ`).
No las usa la beta. Si quieres limpiarlas, ejecuta esto en Supabase â†’ SQL
Editor:

```sql
update public.chat_rooms
set closed = true
where code in ('TSTB23', 'TSTA24', 'MYRWGZ');

delete from public.chat_rooms
where code in ('TSTB23', 'TSTA24', 'MYRWGZ');
```

## Si no conecta

1. Revisa que la PC y el telÃ©fono estÃ©n en la misma red.
2. Comprueba la IP con `ipconfig`; cÃ¡mbiala en la URL si hace falta.
3. Abre los puertos 8000/8443 en el firewall. La regla creada se llama
   **Chat WiFi Beta 8000** y permite TCP 8000 y 8443 desde la subred local.
4. Prueba `http://IP:8000/android_beta.html` desde la PC.
5. Si Chrome Android intenta `https://`, usa
   `https://IP:8000/android_beta.html` y acepta el certificado autofirmado.
6. Si Supabase falla, revisa primero la Wi-Fi: los microcortes del adaptador
   MediaTek ya causaron timeouts anteriormente. El Visor de eventos â†’
   `Microsoft-Windows-WLAN-AutoConfig/Operational`, eventos 11004/11005.
7. Si la pÃ¡gina carga pero no hay estilos ni cifrado, el telÃ©fono no pudo bajar
   Supabase JS o CryptoJS desde el CDN. Comprueba Internet y recarga.

## Detener el servidor

Cierra la ventana de `android_beta_server.cmd` o pulsa `Ctrl+C`.

