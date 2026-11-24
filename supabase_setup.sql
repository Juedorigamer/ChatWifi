-- ============================================================
-- CHAT WIFI 2.2 - ESQUEMA PARA SUPABASE (LOTE B)
-- Ejecutar completo en Supabase > SQL Editor.
-- Requiere: Authentication > Providers > Anonymous Sign-ins activado.
-- ============================================================

create extension if not exists pgcrypto;

-- ── Salas ────────────────────────────────────────────────────
create table if not exists public.chat_rooms (
    id uuid primary key default gen_random_uuid(),
    code text not null unique,
    topic text not null unique,
    admin_id uuid not null default auth.uid(),
    approval_required boolean not null default true,
    created_at timestamptz not null default now(),
    expires_at timestamptz,
    closed boolean not null default false
);

-- ── Miembros ─────────────────────────────────────────────────
create table if not exists public.chat_members (
    room_id uuid not null references public.chat_rooms(id) on delete cascade,
    user_id uuid not null default auth.uid(),
    display_name text not null,
    role text not null default 'member' check (role in ('admin', 'member')),
    approved boolean not null default false,
    banned boolean not null default false,
    joined_at timestamptz not null default now(),
    last_seen timestamptz not null default now(),
    primary key (room_id, user_id)
);

create index if not exists chat_members_room_idx on public.chat_members(room_id);
create index if not exists chat_members_user_idx on public.chat_members(user_id);
create index if not exists chat_rooms_topic_idx on public.chat_rooms(topic);

-- ── Helpers ──────────────────────────────────────────────────
create or replace function public.chat_is_admin(p_room_id uuid)
returns boolean
language sql stable security definer set search_path = public as $$
    select exists (
        select 1 from public.chat_members
        where room_id = p_room_id
          and user_id = auth.uid()
          and role = 'admin'
          and approved
          and not banned
    );
$$;

create or replace function public.chat_member_ok(p_room_id uuid)
returns boolean
language sql stable security definer set search_path = public as $$
    select exists (
        select 1 from public.chat_members
        where room_id = p_room_id
          and user_id = auth.uid()
          and approved
          and not banned
    );
$$;

-- ── Crear sala ───────────────────────────────────────────────
create or replace function public.chat_create_room(
    p_code text,
    p_topic text,
    p_name text,
    p_expires_at timestamptz default null,
    p_approval_required boolean default true
)
returns table (room_id uuid, topic text)
language plpgsql security definer set search_path = public as $$
declare
    v_room uuid;
begin
    if auth.uid() is null then
        raise exception 'Debes iniciar sesión (anónimo) en Supabase.';
    end if;

    insert into public.chat_rooms (code, topic, admin_id, expires_at, approval_required)
    values (upper(trim(p_code)), p_topic, auth.uid(), p_expires_at, p_approval_required)
    returning id into v_room;

    insert into public.chat_members (room_id, user_id, display_name, role, approved)
    values (v_room, auth.uid(), p_name, 'admin', true);

    return query select v_room, p_topic;
end;
$$;

-- ── Unirse a una sala ────────────────────────────────────────
drop function if exists public.chat_join_room(text, text);

create or replace function public.chat_join_room(p_code text, p_name text)
returns table (
    out_room_id uuid,
    out_topic text,
    out_approved boolean,
    out_closed boolean,
    out_expires_at timestamptz
)
language plpgsql security definer set search_path = public as $$
declare
    v_room public.chat_rooms;
    v_approved boolean;
    v_banned boolean;
begin
    if auth.uid() is null then
        raise exception 'Debes iniciar sesión (anónimo) en Supabase.';
    end if;

    select * into v_room
    from public.chat_rooms
    where code = upper(trim(p_code));

    if not found then
        raise exception 'La sala no existe.';
    end if;
    if v_room.closed then
        raise exception 'La sala está cerrada.';
    end if;
    if v_room.expires_at is not null and v_room.expires_at <= now() then
        raise exception 'La sala expiró.';
    end if;

    select cm.banned into v_banned
    from public.chat_members cm
    where cm.room_id = v_room.id and cm.user_id = auth.uid();

    if coalesce(v_banned, false) then
        raise exception 'Estás bloqueado en esta sala.';
    end if;

    insert into public.chat_members (room_id, user_id, display_name, role, approved, banned, last_seen)
    values (
        v_room.id, auth.uid(), p_name, 'member',
        not v_room.approval_required, false, now()
    )
    on conflict (room_id, user_id) do update
        set display_name = excluded.display_name,
            last_seen = now()
    returning approved into v_approved;

    return query
    select v_room.id, v_room.topic, v_approved, v_room.closed, v_room.expires_at;
end;
$$;

-- ── Aprobar / rechazar / expulsar ────────────────────────────
create or replace function public.chat_approve_member(
    p_room_id uuid, p_user_id uuid, p_approve boolean
)
returns void
language plpgsql security definer set search_path = public as $$
begin
    if not public.chat_is_admin(p_room_id) then
        raise exception 'Solo el administrador puede aprobar miembros.';
    end if;

    update public.chat_members
    set approved = p_approve,
        banned = case when p_approve then false else banned end
    where room_id = p_room_id and user_id = p_user_id and role <> 'admin';
end;
$$;

create or replace function public.chat_kick_member(p_room_id uuid, p_user_id uuid)
returns void
language plpgsql security definer set search_path = public as $$
begin
    if not public.chat_is_admin(p_room_id) then
        raise exception 'Solo el administrador puede expulsar.';
    end if;

    update public.chat_members
    set approved = false, banned = true
    where room_id = p_room_id and user_id = p_user_id and role <> 'admin';
end;
$$;

create or replace function public.chat_close_room(p_room_id uuid)
returns void
language plpgsql security definer set search_path = public as $$
begin
    if not public.chat_is_admin(p_room_id) then
        raise exception 'Solo el administrador puede cerrar la sala.';
    end if;
    update public.chat_rooms set closed = true where id = p_room_id;
end;
$$;

-- ── Consultas de miembros ────────────────────────────────────
create or replace function public.chat_pending_members(p_room_id uuid)
returns table (user_id uuid, display_name text, joined_at timestamptz)
language plpgsql security definer set search_path = public as $$
begin
    if not public.chat_is_admin(p_room_id) then
        raise exception 'Solo el administrador puede ver pendientes.';
    end if;

    return query
    select m.user_id, m.display_name, m.joined_at
    from public.chat_members m
    where m.room_id = p_room_id and not m.approved and not m.banned
    order by m.joined_at;
end;
$$;

create or replace function public.chat_room_members(p_room_id uuid)
returns table (user_id uuid, display_name text, role text, approved boolean, banned boolean)
language plpgsql security definer set search_path = public as $$
begin
    if not public.chat_member_ok(p_room_id) and not public.chat_is_admin(p_room_id) then
        raise exception 'No perteneces a esta sala.';
    end if;

    return query
    select m.user_id, m.display_name, m.role, m.approved, m.banned
    from public.chat_members m
    where m.room_id = p_room_id
    order by m.role desc, m.display_name;
end;
$$;

create or replace function public.chat_heartbeat(p_room_id uuid)
returns void
language sql security definer set search_path = public as $$
    update public.chat_members
    set last_seen = now()
    where room_id = p_room_id and user_id = auth.uid();
$$;

-- ── Limpieza de salas ────────────────────────────────────────
create or replace function public.chat_cleanup_expired()
returns void
language sql security definer set search_path = public as $$
    delete from public.chat_rooms
    where (expires_at is not null and expires_at < now() - interval '1 day')
       or (closed and created_at < now() - interval '1 day');
$$;

-- ── RLS de las tablas ────────────────────────────────────────
alter table public.chat_rooms enable row level security;
alter table public.chat_members enable row level security;

revoke insert, update, delete on public.chat_rooms from anon, authenticated;
revoke insert, update, delete on public.chat_members from anon, authenticated;
grant select on public.chat_rooms, public.chat_members to authenticated;

drop policy if exists chat_rooms_read on public.chat_rooms;
create policy chat_rooms_read on public.chat_rooms
for select to authenticated
using (public.chat_member_ok(id) or public.chat_is_admin(id));

drop policy if exists chat_members_read on public.chat_members;
create policy chat_members_read on public.chat_members
for select to authenticated
using (public.chat_member_ok(room_id) or public.chat_is_admin(room_id));

-- ── Realtime: canales privados ───────────────────────────────
do $$
begin
    execute 'alter table realtime.messages enable row level security';
exception when others then
    null; -- ya estaba habilitado o no tenemos permiso
end $$;

drop policy if exists chat_realtime_read on realtime.messages;
create policy chat_realtime_read on realtime.messages
for select to authenticated
using (
    realtime.messages.extension in ('broadcast', 'presence')
    and exists (
        select 1
        from public.chat_members m
        join public.chat_rooms r on r.id = m.room_id
        where r.topic = realtime.topic()
          and m.user_id = auth.uid()
          and m.approved
          and not m.banned
          and not r.closed
          and (r.expires_at is null or r.expires_at > now())
    )
);

drop policy if exists chat_realtime_write on realtime.messages;
create policy chat_realtime_write on realtime.messages
for insert to authenticated
with check (
    realtime.messages.extension in ('broadcast', 'presence')
    and exists (
        select 1
        from public.chat_members m
        join public.chat_rooms r on r.id = m.room_id
        where r.topic = realtime.topic()
          and m.user_id = auth.uid()
          and m.approved
          and not m.banned
          and not r.closed
          and (r.expires_at is null or r.expires_at > now())
    )
);

-- ── Storage: bucket privado ──────────────────────────────────
insert into storage.buckets (id, name, public, file_size_limit)
values ('chatwifi', 'chatwifi', false, 52428800)
on conflict (id) do update
    set public = false,
        file_size_limit = 52428800;

drop policy if exists chat_files_read on storage.objects;
create policy chat_files_read on storage.objects
for select to authenticated
using (
    bucket_id = 'chatwifi'
    and (storage.foldername(name))[1] = 'rooms'
    and exists (
        select 1
        from public.chat_members m
        where m.room_id = ((storage.foldername(name))[2])::uuid
          and m.user_id = auth.uid()
          and m.approved
          and not m.banned
    )
);

drop policy if exists chat_files_write on storage.objects;
create policy chat_files_write on storage.objects
for insert to authenticated
with check (
    bucket_id = 'chatwifi'
    and (storage.foldername(name))[1] = 'rooms'
    and exists (
        select 1
        from public.chat_members m
        where m.room_id = ((storage.foldername(name))[2])::uuid
          and m.user_id = auth.uid()
          and m.approved
          and not m.banned
    )
);

drop policy if exists chat_files_delete on storage.objects;
create policy chat_files_delete on storage.objects
for delete to authenticated
using (bucket_id = 'chatwifi' and owner = auth.uid());

-- ── Permisos de funciones ────────────────────────────────────
revoke all on function public.chat_create_room(text, text, text, timestamptz, boolean) from public;
revoke all on function public.chat_join_room(text, text) from public;
revoke all on function public.chat_approve_member(uuid, uuid, boolean) from public;
revoke all on function public.chat_kick_member(uuid, uuid) from public;
revoke all on function public.chat_close_room(uuid) from public;
revoke all on function public.chat_pending_members(uuid) from public;
revoke all on function public.chat_room_members(uuid) from public;
revoke all on function public.chat_heartbeat(uuid) from public;
revoke all on function public.chat_cleanup_expired() from public;
revoke all on function public.chat_is_admin(uuid) from public;
revoke all on function public.chat_member_ok(uuid) from public;

grant execute on function public.chat_create_room(text, text, text, timestamptz, boolean) to authenticated;
grant execute on function public.chat_join_room(text, text) to authenticated;
grant execute on function public.chat_approve_member(uuid, uuid, boolean) to authenticated;
grant execute on function public.chat_kick_member(uuid, uuid) to authenticated;
grant execute on function public.chat_close_room(uuid) to authenticated;
grant execute on function public.chat_pending_members(uuid) to authenticated;
grant execute on function public.chat_room_members(uuid) to authenticated;
grant execute on function public.chat_heartbeat(uuid) to authenticated;
grant execute on function public.chat_cleanup_expired() to service_role;
grant execute on function public.chat_is_admin(uuid) to authenticated;
grant execute on function public.chat_member_ok(uuid) to authenticated;

-- ── Limpieza automática diaria (opcional) ────────────────────
-- Requiere la extensión pg_cron habilitada en Database > Extensions.
-- select cron.schedule(
--     'chat-cleanup-expired',
--     '0 4 * * *',
--     $$select public.chat_cleanup_expired();$$
-- );
