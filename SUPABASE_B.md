# Lote B - Pasos exactos en Supabase

## 1. Activar login anónimo

Dashboard de Supabase:

**Authentication → Providers → Anonymous Sign-ins → Enable**

Sin esto, `auth.uid()` será nulo y las políticas RLS no dejarán entrar.

## 2. Ejecutar el SQL

1. Abre **SQL Editor** en el dashboard.
2. Pega todo el contenido de `supabase_setup.sql`.
3. Pulsa **Run**.

El script crea:

- `chat_rooms`: salas, administrador, caducidad y estado.
- `chat_members`: miembros, aprobados, bloqueados y rol.
- Funciones RPC:
  - `chat_create_room`
  - `chat_join_room`
  - `chat_approve_member`
  - `chat_kick_member`
  - `chat_close_room`
  - `chat_pending_members`
  - `chat_room_members`
  - `chat_heartbeat`
  - `chat_cleanup_expired`
- Políticas RLS para Realtime privado.
- Bucket privado `chatwifi` de Storage, límite 50 MB por archivo.
- Políticas de Storage para leer/escribir solo miembros aprobados.

## 3. Verificar

En **Table Editor** deben aparecer `chat_rooms` y `chat_members`.
En **Storage** debe aparecer el bucket `chatwifi` (privado).
En **Authentication → Users** aparecerán usuarios anónimos cuando la app se conecte.

## 4. Avisarme

Cuando el SQL esté ejecutado, dime **“SQL listo”**. Entonces implemento en la app:

- Login anónimo al abrir el modo Online.
- Canales privados de Realtime con `set_auth(token)`.
- Crear/unirse a salas mediante RPC (no inserciones directas).
- Aprobación de entrada por el administrador.
- Panel de administración: pendientes, aprobar, expulsar, cerrar sala.
- Caducidad de sala y heartbeat.
- Subida de archivos cifrados a Storage.
- Enlaces firmados con caducidad para descargar archivos.
- Borrado de archivos propios.

## 5. Límites del plan gratuito

- 200 conexiones concurrentes.
- 2 millones de mensajes Realtime al mes.
- 500 MB de base de datos.
- 1 GB de Storage.
- 50 MB máximo por archivo.
- Proyecto pausado tras 7 días sin actividad.

## 6. Seguridad

- La app usa solo la `sb_publishable_...`; nunca la `sb_secret_...`.
- Los archivos se cifran con Fernet **antes** de subirse.
- El bucket es privado; se accede con enlaces firmados.
- Las políticas RLS usan `auth.uid()` y `chat_members`.
- Expulsar a alguien impide que vuelva a entrar y hace que los clientes cooperativos salgan. Un cliente malicioso que ignore la orden podría seguir conectado hasta reconectar, porque Realtime cachea los permisos de la conexión. Para expulsión inmediata e infalible haría falta un backend que cierre la conexión o revoque el token.

## 7. Qué cambia en la app

- El modo LAN sigue igual.
- El modo Online pasa de canal público a canal privado.
- El código de sala no cambia.
- El secreto sigue cifrando los mensajes de extremo a extremo.
- La publishable key sigue siendo pública.
- Los mensajes, reacciones, leídos y TTL siguen funcionando por Broadcast.
- La moderación y el Storage usan Postgres/Storage con RLS.

## 8. Orden recomendado

1. Ejecutar SQL.
2. Activar Anonymous Sign-ins.
3. Probar desde el dashboard que `chat_create_room` responde.
4. Avisarme para conectar el cliente.
