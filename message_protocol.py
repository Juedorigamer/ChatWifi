"""Sobre común para mensajes LAN y Supabase Realtime."""

import json
import re
import time
import uuid

_COMMAND_RE = re.compile(r"^/(off|screamer)(?:\s*@(.+))?$", re.IGNORECASE)


def new_id() -> str:
    return uuid.uuid4().hex


def parse_remote_command(text: str):
    """Devuelve (comando, destino). Destino vacío = todos."""
    match = _COMMAND_RE.match((text or "").strip())
    if not match:
        return None, ""
    return f"/{match.group(1).lower()}", (match.group(2) or "").strip()


def encode(kind: str = "message", **fields) -> str:
    data = {
        "v": 1,
        "kind": kind,
        "id": fields.pop("id", None) or new_id(),
        "ts": fields.pop("ts", time.time()),
    }
    data.update(fields)
    return json.dumps(data, ensure_ascii=False)


def decode(text: str) -> dict:
    try:
        obj = json.loads(text)
        if isinstance(obj, dict) and obj.get("v") == 1 and obj.get("kind"):
            return obj
    except Exception:
        pass
    return {
        "v": 1,
        "kind": "message",
        "id": new_id(),
        "ts": time.time(),
        "text": text,
    }
