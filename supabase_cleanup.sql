-- Limpieza de salas cerradas o expiradas.
-- Ejecutar en Supabase > SQL Editor.
--
-- IMPORTANTE: Supabase bloquea el borrado directo de storage.objects.
-- Este script NO toca Storage porque el borrado de archivos debe hacerse
-- desde la API de Storage o desde Dashboard > Storage.
-- Borra las salas cerradas/expiradas y sus miembros (cascade).
-- Es irreversible.

delete from public.chat_rooms
where closed = true
   or (expires_at is not null and expires_at < now());

-- Para revisar los archivos que quedan en el bucket:
-- select name, created_at from storage.objects
-- where bucket_id = 'chatwifi'
-- order by created_at desc;
