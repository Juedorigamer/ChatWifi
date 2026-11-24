# Graph Report - graphify_clean  (2026-11-08)

## Corpus Check
- 7 files · ~12,202 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 2 file(s) not represented in the graph (top: .css 1, .iss 1)

## Summary
- 284 nodes · 625 edges · 9 communities (5 shown, 4 thin omitted)
- Extraction: 92% EXTRACTED · 8% INFERRED · 0% AMBIGUOUS · INFERRED: 48 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- SupabaseRealtime
- chat.py
- NetworkManager
- ChatWindow
- supabase_setup.sql
- ._add_file_bubble
- Lote B - Pasos exactos en Supabase

## God Nodes (most connected - your core abstractions)
1. `ChatWindow` - 111 edges
2. `SupabaseRealtime` - 60 edges
3. `NetworkManager` - 28 edges
4. `save_settings()` - 13 edges
5. `new_id()` - 12 edges
6. `public.chat_members` - 11 edges
7. `Lote B - Pasos exactos en Supabase` - 9 edges
8. `public.chat_join_room()` - 7 edges
9. `encode()` - 6 edges
10. `decode()` - 6 edges

## Surprising Connections (you probably didn't know these)
- `ChatWindow` --uses--> `SupabaseRealtime`  [INFERRED]
  chat.py → supabase_realtime.py
- `public.chat_join_room()` --writes_to--> `public.chat_members`  [EXTRACTED]
  supabase_fix_join.sql → supabase_setup.sql
- `public.chat_join_room()` --reads_from--> `public.chat_rooms`  [EXTRACTED]
  supabase_fix_join.sql → supabase_setup.sql

## Import Cycles
- None detected.

## Communities (9 total, 4 thin omitted)

### Community 1 - "chat.py"
Cohesion: 0.07
Nodes (7): derive_key(), get_broadcast_ip(), get_local_ip(), main(), make_fernet(), derive_key(), make_fernet()

### Community 3 - "ChatWindow"
Cohesion: 0.05
Nodes (5): ChatWindow, filter_css_for_theme(), load_css(), load_settings(), save_settings()

### Community 4 - "supabase_setup.sql"
Cohesion: 0.15
Nodes (13): public.chat_join_room(), chat_members_room_idx, chat_members_user_idx, chat_rooms_topic_idx, public.chat_approve_member(), public.chat_close_room(), public.chat_is_admin(), public.chat_join_room() (+5 more)

### Community 7 - "._add_file_bubble"
Cohesion: 0.11
Nodes (4): app_base_dir(), decode(), encode(), new_id()

### Community 8 - "Lote B - Pasos exactos en Supabase"
Cohesion: 0.20
Nodes (9): 1. Activar login anónimo, 2. Ejecutar el SQL, 3. Verificar, 4. Avisarme, 5. Límites del plan gratuito, 6. Seguridad, 7. Qué cambia en la app, 8. Orden recomendado (+1 more)

## Knowledge Gaps
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ChatWindow` connect `ChatWindow` to `SupabaseRealtime`, `chat.py`, `NetworkManager`, `._add_bubble`, `._add_file_bubble`?**
  _High betweenness centrality (0.474) - this node is a cross-community bridge._
- **Should `SupabaseRealtime` be split into smaller, more focused modules?**
  _Cohesion score 0.08240794856808883 - nodes in this community are weakly interconnected._
- **Why does `SupabaseRealtime` connect `SupabaseRealtime` to `chat.py`, `ChatWindow`, `._add_bubble`?**
  _High betweenness centrality (0.276) - this node is a cross-community bridge._
- **Should `chat.py` be split into smaller, more focused modules?**
  _Cohesion score 0.07254623044096728 - nodes in this community are weakly interconnected._
- **Why does `NetworkManager` connect `NetworkManager` to `chat.py`, `ChatWindow`?**
  _High betweenness centrality (0.094) - this node is a cross-community bridge._
- **Should `NetworkManager` be split into smaller, more focused modules?**
  _Cohesion score 0.1476923076923077 - nodes in this community are weakly interconnected._
- **Should `ChatWindow` be split into smaller, more focused modules?**
  _Cohesion score 0.05432595573440644 - nodes in this community are weakly interconnected._