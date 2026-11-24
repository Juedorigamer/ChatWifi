-- Corrige definitivamente chat_join_room.
-- Los nombres de salida ahora son out_* para no chocar con las columnas.
-- Ejecutar en Supabase > SQL Editor > Run.

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

revoke all on function public.chat_join_room(text, text) from public;
grant execute on function public.chat_join_room(text, text) to authenticated;
