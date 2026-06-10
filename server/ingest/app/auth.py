"""Bearer-token authentication and device ownership helpers."""
import hashlib
import secrets
from dataclasses import dataclass
from uuid import UUID

import psycopg
from fastapi import Depends, Header, HTTPException

from .config import load_config


@dataclass(frozen=True)
class AuthContext:
    is_admin: bool
    user_id: UUID | None = None
    name: str | None = None
    email: str | None = None


def hash_api_token(token: str) -> str:
    """Return the deterministic digest used to look up high-entropy API tokens."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_prefix(token: str, length: int = 10) -> str:
    return token[:length]


def _bearer_token(authorization: str) -> str:
    scheme, separator, token = authorization.partition(" ")
    if separator != " " or scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="unauthorized")
    return token


def require_auth(authorization: str = Header(default="")) -> AuthContext:
    token = _bearer_token(authorization)
    cfg = load_config()
    if secrets.compare_digest(token, cfg.api_key):
        return AuthContext(is_admin=True)

    digest = hash_api_token(token)
    with psycopg.connect(cfg.db_dsn) as conn:
        row = conn.execute(
            """SELECT u.id, u.name, u.email
               FROM api_tokens t
               JOIN users u ON u.id = t.user_id
               WHERE t.token_hash = %s AND t.revoked_at IS NULL""",
            (digest,),
        ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="unauthorized")
    return AuthContext(is_admin=False, user_id=row[0], name=row[1], email=row[2])


def require_admin_auth(auth: AuthContext = Depends(require_auth)) -> AuthContext:
    if not auth.is_admin:
        raise HTTPException(status_code=403, detail="admin token required")
    return auth


def authorize_device(
    conn: psycopg.Connection,
    auth: AuthContext,
    device_id: str,
    *,
    auto_bind: bool,
) -> None:
    """Allow admins; otherwise verify or atomically create exclusive ownership."""
    if auth.is_admin:
        return
    if auth.user_id is None:
        raise HTTPException(status_code=401, detail="unauthorized")

    # ensure_device() is called first by ingest routes. Locking that row
    # serializes concurrent first uploads for the same physical device.
    conn.execute("SELECT device_id FROM devices WHERE device_id = %s FOR UPDATE", (device_id,))
    owner = conn.execute(
        "SELECT user_id FROM device_owners WHERE device_id = %s",
        (device_id,),
    ).fetchone()
    if owner is None:
        if not auto_bind:
            raise HTTPException(status_code=403, detail="device is not owned by this user")
        conn.execute(
            """INSERT INTO device_owners (device_id, user_id, display_name)
               VALUES (%s, %s, NULL)""",
            (device_id, auth.user_id),
        )
        return
    if owner[0] != auth.user_id:
        raise HTTPException(status_code=403, detail="device is owned by another user")
