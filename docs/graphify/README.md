# Graphify - mapa de arquitectura

Generado el 2026-11-08 con `graphifyy 0.9.95`, usando solo AST local
(`GRAPHIFY_BACKEND=none`), sin LLM, sin hooks y sin instalar nada en el flujo
de OpenCode.

## Qué se indexó

- `chat.py`
- `supabase_realtime.py`
- `message_protocol.py`
- `supabase_setup.sql`
- `supabase_fix_join.sql`
- `supabase_cleanup.sql`
- `LEEME.txt` y `SUPABASE_B.md` (comunidad de documentación)

Excluidos: `chat.backup_v_avanzado.py`, `chat.original.py`, `build/`, `dist/`,
`__pycache__`. `estilos_chat.css` y `ChatWiFi.iss` no están soportados por
Graphify y quedaron fuera (2 archivos no clasificados).

## Resultado

- **284 nodos, 625 aristas, 9 comunidades**
- 92% relaciones extraídas, 8% inferidas
- 0 tokens de LLM

### God nodes

1. `ChatWindow` - 111 conexiones
2. `SupabaseRealtime` - 60
3. `NetworkManager` - 28
4. `save_settings()` - 13
5. `new_id()` - 12
6. `public.chat_members` - 11
7. `public.chat_join_room()` - 7

## Lectura

- `ChatWindow` tiene **cohesión 0.054**: es demasiado grande y mezcla chat,
  archivos, ajustes, administración y online.
- `SupabaseRealtime` tiene **cohesión 0.082**: mezcla auth, salas, archivos,
  moderación y transporte.
- `NetworkManager` tiene **cohesión 0.148**: menos urgente, pero también se
  puede separar en descubrimiento, archivos y protocolo.
- La comunidad SQL es la más cohesionada (0.15): `chat_join_room` lee
  `chat_rooms` y escribe `chat_members`.

## Orden sugerido para refactorizar

1. Extraer de `ChatWindow` el render de mensajes:
   `_add_bubble`, `_format_message`, reacciones, leídos y TTL.
2. Extraer archivos:
   `_add_file_bubble`, `_download_file`, `on_file_*`.
3. Extraer el panel de administración:
   `on_admin_*`, `_populate_admin`.
4. Extraer el ciclo de vida online:
   `on_online_*`, `on_waiting_approval`, `on_room_ready`.
5. Dejar `ChatWindow` como coordinador delgado.

En `SupabaseRealtime`, separar en `auth/session`, `rooms/admin`,
`files/storage` y `realtime transport`, manteniendo una fachada.

No hacer un refactor grande de golpe: extraer un grupo, probar LAN + Online,
y seguir. El grafo es una guía, no una prueba.

## Consultas útiles

```powershell
# Nodos más conectados
py -m graphify god-nodes --graph docs/graphify/graph.json --top 20

# Preguntas sobre el grafo
py -m graphify query "como se conecta ChatWindow con SupabaseRealtime" --graph docs/graphify/graph.json

# Explicar un nodo
py -m graphify explain "ChatWindow" --graph docs/graphify/graph.json

# Camino entre dos nodos
py -m graphify path "ChatWindow" "SupabaseRealtime" --graph docs/graphify/graph.json
```

El archivo `graph.html` es el mapa interactivo. `graph.json` es la estructura
consultable.

## Nota

No se ejecutó `graphify install`, no se creó `AGENTS.md` y no se instalaron
hooks. La generación se hizo en una copia limpia en
`%TEMP%\opencode\graphify_clean`; solo se copiaron los resultados a esta
carpeta de documentación.
