"""MySQL models for multi-tenant ParkAccess."""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

from itsdangerous import BadSignature, URLSafeSerializer
from werkzeug.security import check_password_hash, generate_password_hash

import config
from auth import ROLE_ADMIN, ROLE_MANAGER
from db import SCHEMA_STATEMENTS, ensure_database, get_connection, migrate_schema
from db import IntegrityError  # noqa: F401 — used by app.py


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.replace(microsecond=0).isoformat()
    return str(value)


def _serializer() -> URLSafeSerializer:
    return URLSafeSerializer(config.SECRET_KEY, salt="parkaccess-ttlock")


def encrypt_secret(value: str) -> str:
    return _serializer().dumps(value)


def decrypt_secret(token: str | None) -> str:
    if not token:
        return ""
    try:
        return str(_serializer().loads(token))
    except BadSignature:
        return ""


@contextmanager
def get_cursor():
    with get_connection() as conn:
        with conn.cursor() as cur:
            yield cur


def init_db() -> None:
    ensure_database()
    with get_cursor() as cur:
        for statement in SCHEMA_STATEMENTS:
            cur.execute(statement)
    migrate_schema()
    seed_admin()


def seed_admin() -> None:
    existing = get_user_by_username(config.ADMIN_USERNAME)
    now = utc_now()
    if existing is None:
        with get_cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (
                    username, password_hash, role, status, display_name,
                    email, company_name, ttlock_username, ttlock_password_enc,
                    created_at, updated_at, approved_at
                ) VALUES (%s, %s, %s, 'approved', 'Platform Admin', '', '', '', '', %s, %s, %s)
                """,
                (
                    config.ADMIN_USERNAME,
                    generate_password_hash(config.ADMIN_PASSWORD),
                    ROLE_ADMIN,
                    now,
                    now,
                    now,
                ),
            )
        return

    with get_cursor() as cur:
        cur.execute(
            """
            UPDATE parking_spaces SET owner_id = %s WHERE owner_id IS NULL
            """,
            (existing["id"],),
        )


def row_to_user(row: dict[str, Any] | None, *, include_secrets: bool = False) -> dict[str, Any] | None:
    if row is None:
        return None
    data = {
        "id": row["id"],
        "username": row["username"],
        "role": row["role"],
        "status": row["status"],
        "displayName": row["display_name"] or "",
        "email": row["email"] or "",
        "companyName": row["company_name"] or "",
        "ttlockUsername": row["ttlock_username"] or "",
        "ttlockConfigured": bool(row["ttlock_username"] and row["ttlock_password_enc"]),
        "pmsConfigured": bool((row.get("pms_token") or "").strip()),
        "pmsRefreshConfigured": bool((row.get("pms_refresh_token") or "").strip()),
        "pmsTokenPreview": _mask_token(row.get("pms_token") or ""),
        "createdAt": _iso(row["created_at"]),
        "updatedAt": _iso(row["updated_at"]),
        "approvedAt": _iso(row["approved_at"]),
    }
    if include_secrets:
        data["ttlockPassword"] = decrypt_secret(row["ttlock_password_enc"])
        data["pmsToken"] = row.get("pms_token") or ""
        data["pmsRefreshToken"] = row.get("pms_refresh_token") or ""
        data["pmsTokenRefreshedAt"] = _iso(row.get("pms_token_refreshed_at"))
    return data


def _mask_token(token: str) -> str:
    token = (token or "").strip()
    if len(token) <= 8:
        return "••••" if token else ""
    return token[:4] + "…" + token[-4:]


def get_user(user_id: int, *, include_secrets: bool = False) -> dict[str, Any] | None:
    with get_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
    return row_to_user(row, include_secrets=include_secrets)


def get_user_by_username(username: str, *, include_secrets: bool = False) -> dict[str, Any] | None:
    with get_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = %s", (username.strip(),))
        row = cur.fetchone()
    return row_to_user(row, include_secrets=include_secrets)


def authenticate_user(username: str, password: str) -> dict[str, Any] | None:
    with get_cursor() as cur:
        cur.execute("SELECT * FROM users WHERE username = %s", (username.strip(),))
        row = cur.fetchone()
    if row is None:
        return None
    if not check_password_hash(row["password_hash"], password):
        return None
    return row_to_user(row)


def create_manager(
    *,
    username: str,
    password: str,
    display_name: str = "",
    email: str = "",
    company_name: str = "",
) -> dict[str, Any]:
    now = utc_now()
    with get_cursor() as cur:
        cur.execute(
            """
            INSERT INTO users (
                username, password_hash, role, status, display_name, email, company_name,
                ttlock_username, ttlock_password_enc, created_at, updated_at
            ) VALUES (%s, %s, %s, 'pending', %s, %s, %s, '', '', %s, %s)
            """,
            (
                username.strip(),
                generate_password_hash(password),
                ROLE_MANAGER,
                display_name.strip(),
                email.strip(),
                company_name.strip(),
                now,
                now,
            ),
        )
        user_id = cur.lastrowid
    return get_user(user_id)


def list_users(role: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
    query = "SELECT * FROM users WHERE 1=1"
    params: list[Any] = []
    if role:
        query += " AND role = %s"
        params.append(role)
    if status:
        query += " AND status = %s"
        params.append(status)
    query += " ORDER BY created_at DESC"
    with get_cursor() as cur:
        cur.execute(query, params)
        rows = cur.fetchall()
    return [row_to_user(row) for row in rows]


def update_user_status(user_id: int, status: str, approved_by: int | None = None) -> dict[str, Any] | None:
    user = get_user(user_id)
    if user is None:
        return None
    now = utc_now()
    approved_at = now if status == "approved" else None
    with get_cursor() as cur:
        cur.execute(
            """
            UPDATE users
            SET status = %s, approved_at = %s, approved_by = %s, updated_at = %s
            WHERE id = %s
            """,
            (status, approved_at, approved_by, now, user_id),
        )
    return get_user(user_id)


def update_user_password(user_id: int, password: str) -> None:
    with get_cursor() as cur:
        cur.execute(
            "UPDATE users SET password_hash = %s, updated_at = %s WHERE id = %s",
            (generate_password_hash(password), utc_now(), user_id),
        )


def update_user_profile(user_id: int, **fields: Any) -> dict[str, Any] | None:
    user = get_user(user_id)
    if user is None:
        return None
    display_name = fields.get("displayName", user["displayName"])
    email = fields.get("email", user["email"])
    company_name = fields.get("companyName", user["companyName"])
    with get_cursor() as cur:
        cur.execute(
            """
            UPDATE users
            SET display_name = %s, email = %s, company_name = %s, updated_at = %s
            WHERE id = %s
            """,
            (display_name, email, company_name, utc_now(), user_id),
        )
    return get_user(user_id)


def set_ttlock_credentials(user_id: int, username: str, password: str) -> dict[str, Any] | None:
    user = get_user(user_id)
    if user is None:
        return None
    enc = encrypt_secret(password) if password else ""
    with get_cursor() as cur:
        cur.execute(
            """
            UPDATE users
            SET ttlock_username = %s, ttlock_password_enc = %s, updated_at = %s
            WHERE id = %s
            """,
            (username.strip(), enc, utc_now(), user_id),
        )
    return get_user(user_id)


def clear_ttlock_credentials(user_id: int) -> dict[str, Any] | None:
    with get_cursor() as cur:
        cur.execute(
            """
            UPDATE users
            SET ttlock_username = '', ttlock_password_enc = '', updated_at = %s
            WHERE id = %s
            """,
            (utc_now(), user_id),
        )
    return get_user(user_id)


def delete_user(user_id: int) -> bool:
    with get_cursor() as cur:
        cur.execute("DELETE FROM users WHERE id = %s AND role != %s", (user_id, ROLE_ADMIN))
        return cur.rowcount > 0


SPACE_SELECT = """
SELECT s.*, h.hotel_id AS hotel_public_id, h.name AS hotel_name
FROM parking_spaces s
LEFT JOIN hotels h ON h.id = s.hotel_id
"""


def row_to_space(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "id": row["id"],
        "ownerId": row["owner_id"],
        "hotelId": row.get("hotel_id"),
        "hotelPublicId": row.get("hotel_public_id") or "",
        "hotelName": row.get("hotel_name") or "",
        "name": row["name"],
        "lockId": row["lock_id"],
        "pin": row["pin"] or "",
        "bookingId": row.get("booking_id"),
        "keyboardPwdId": row.get("keyboard_pwd_id"),
        "enabled": bool(row["enabled"]),
        "notes": row["notes"] or "",
        "createdAt": _iso(row["created_at"]),
        "updatedAt": _iso(row["updated_at"]),
    }


def list_spaces(owner_id: int | None = None, hotel_id: int | None = None) -> list[dict[str, Any]]:
    with get_cursor() as cur:
        query = SPACE_SELECT + " WHERE 1=1"
        params: list[Any] = []
        if owner_id is not None:
            query += " AND s.owner_id = %s"
            params.append(owner_id)
        if hotel_id is not None:
            query += " AND s.hotel_id = %s"
            params.append(hotel_id)
        query += " ORDER BY s.id ASC"
        cur.execute(query, params)
        rows = cur.fetchall()
    return [row_to_space(row) for row in rows]


def get_space(space_id: int) -> dict[str, Any] | None:
    with get_cursor() as cur:
        cur.execute(SPACE_SELECT + " WHERE s.id = %s", (space_id,))
        row = cur.fetchone()
    return row_to_space(row)


def get_space_by_pin(pin: str, hotel_public_id: str | None = None) -> dict[str, Any] | None:
    with get_cursor() as cur:
        if hotel_public_id:
            cur.execute(
                SPACE_SELECT + " WHERE h.hotel_id = %s AND s.pin = %s",
                (str(hotel_public_id).strip(), pin),
            )
        else:
            cur.execute(SPACE_SELECT + " WHERE s.pin = %s", (pin,))
        row = cur.fetchone()
    return row_to_space(row)


def create_space(
    *,
    owner_id: int,
    name: str,
    lock_id: str,
    pin: str | None = None,
    enabled: bool = True,
    notes: str = "",
    hotel_id: int | None = None,
) -> dict[str, Any]:
    now = utc_now()
    pin_value = pin.strip() if pin and str(pin).strip() else None
    with get_cursor() as cur:
        cur.execute(
            """
            INSERT INTO parking_spaces (
                owner_id, hotel_id, name, lock_id, pin, enabled, notes, created_at, updated_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (owner_id, hotel_id, name, lock_id, pin_value, 1 if enabled else 0, notes, now, now),
        )
        space_id = cur.lastrowid
    return get_space(space_id)


def update_space(space_id: int, **fields: Any) -> dict[str, Any] | None:
    existing = get_space(space_id)
    if existing is None:
        return None

    name = fields.get("name", existing["name"])
    lock_id = fields.get("lockId", existing["lockId"])
    pin = fields.get("pin", existing["pin"])
    if pin == "":
        pin = None
    hotel_id = fields.get("hotelId", existing.get("hotelId"))
    booking_id = fields.get("bookingId", existing.get("bookingId"))
    keyboard_pwd_id = fields.get("keyboardPwdId", existing.get("keyboardPwdId"))
    enabled = fields.get("enabled", existing["enabled"])
    notes = fields.get("notes", existing["notes"])
    now = utc_now()

    with get_cursor() as cur:
        cur.execute(
            """
            UPDATE parking_spaces
            SET name = %s, lock_id = %s, pin = %s, enabled = %s, notes = %s,
                hotel_id = %s, booking_id = %s, keyboard_pwd_id = %s, updated_at = %s
            WHERE id = %s
            """,
            (
                name,
                lock_id,
                pin,
                1 if enabled else 0,
                notes,
                hotel_id,
                booking_id,
                keyboard_pwd_id,
                now,
                space_id,
            ),
        )
    return get_space(space_id)


def delete_space(space_id: int) -> bool:
    with get_cursor() as cur:
        cur.execute("DELETE FROM parking_spaces WHERE id = %s", (space_id,))
        return cur.rowcount > 0


def add_log(
    *,
    action: str,
    owner_id: int | None = None,
    actor_user_id: int | None = None,
    parking_space_id: int | None = None,
    parking_space_name: str | None = None,
    lock_id: str | None = None,
    pin: str | None = None,
    success: bool = False,
    message: str = "",
    request_payload: Any = None,
    response_payload: Any = None,
) -> dict[str, Any]:
    now = utc_now()
    req = json.dumps(request_payload) if request_payload is not None else None
    res = json.dumps(response_payload) if response_payload is not None else None

    with get_cursor() as cur:
        cur.execute(
            """
            INSERT INTO api_logs (
                owner_id, actor_user_id, action, parking_space_id, parking_space_name, lock_id, pin,
                success, message, request_payload, response_payload, created_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                owner_id,
                actor_user_id,
                action,
                parking_space_id,
                parking_space_name,
                lock_id,
                pin,
                1 if success else 0,
                message,
                req,
                res,
                now,
            ),
        )
        log_id = cur.lastrowid
        cur.execute("SELECT * FROM api_logs WHERE id = %s", (log_id,))
        row = cur.fetchone()

    return row_to_log(row)


def row_to_log(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None

    def parse_json(value: Any):
        if value is None or value == "":
            return None
        if isinstance(value, (dict, list)):
            return value
        try:
            return json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return value

    return {
        "id": row["id"],
        "ownerId": row.get("owner_id"),
        "actorUserId": row.get("actor_user_id"),
        "action": row["action"],
        "parkingSpaceId": row["parking_space_id"],
        "parkingSpaceName": row["parking_space_name"],
        "lockId": row["lock_id"],
        "pin": row["pin"],
        "success": bool(row["success"]),
        "message": row["message"] or "",
        "requestPayload": parse_json(row["request_payload"]),
        "responsePayload": parse_json(row["response_payload"]),
        "createdAt": _iso(row["created_at"]),
    }


def list_logs(limit: int = 100, owner_id: int | None = None) -> list[dict[str, Any]]:
    with get_cursor() as cur:
        if owner_id is None:
            cur.execute("SELECT * FROM api_logs ORDER BY id DESC LIMIT %s", (limit,))
        else:
            cur.execute(
                "SELECT * FROM api_logs WHERE owner_id = %s ORDER BY id DESC LIMIT %s",
                (owner_id, limit),
            )
        rows = cur.fetchall()
    return [row_to_log(row) for row in rows]


def clear_logs(owner_id: int | None = None) -> int:
    with get_cursor() as cur:
        if owner_id is None:
            cur.execute("DELETE FROM api_logs")
        else:
            cur.execute("DELETE FROM api_logs WHERE owner_id = %s", (owner_id,))
        return cur.rowcount


def get_dashboard_stats(owner_id: int | None = None) -> dict[str, Any]:
    with get_cursor() as cur:
        if owner_id is None:
            cur.execute("SELECT COUNT(*) AS c FROM parking_spaces")
            total_spaces = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) AS c FROM parking_spaces WHERE enabled = 1")
            enabled_spaces = cur.fetchone()["c"]
            cur.execute(
                "SELECT COUNT(*) AS c FROM users WHERE role = %s AND status = 'pending'",
                (ROLE_MANAGER,),
            )
            pending_managers = cur.fetchone()["c"]
            cur.execute(
                "SELECT COUNT(*) AS c FROM users WHERE role = %s",
                (ROLE_MANAGER,),
            )
            managers = cur.fetchone()["c"]
            cur.execute(
                """
                SELECT COUNT(*) AS c FROM api_logs
                WHERE action IN ('unlock_pin', 'lock_pin', 'manual_unlock', 'manual_lock') AND success = 1
                """
            )
            unlock_ok = cur.fetchone()["c"]
            cur.execute(
                """
                SELECT COUNT(*) AS c FROM api_logs
                WHERE action IN ('unlock_pin', 'lock_pin', 'manual_unlock', 'manual_lock') AND success = 0
                """
            )
            unlock_fail = cur.fetchone()["c"]
            cur.execute(
                """
                SELECT * FROM api_logs
                WHERE action IN ('unlock_pin', 'lock_pin', 'manual_unlock', 'manual_lock')
                ORDER BY id DESC LIMIT 8
                """
            )
            recent = cur.fetchall()
        else:
            pending_managers = 0
            managers = 0
            cur.execute(
                "SELECT COUNT(*) AS c FROM parking_spaces WHERE owner_id = %s",
                (owner_id,),
            )
            total_spaces = cur.fetchone()["c"]
            cur.execute(
                "SELECT COUNT(*) AS c FROM parking_spaces WHERE owner_id = %s AND enabled = 1",
                (owner_id,),
            )
            enabled_spaces = cur.fetchone()["c"]
            cur.execute(
                """
                SELECT COUNT(*) AS c FROM api_logs
                WHERE owner_id = %s AND action IN ('unlock_pin', 'lock_pin', 'manual_unlock', 'manual_lock')
                  AND success = 1
                """,
                (owner_id,),
            )
            unlock_ok = cur.fetchone()["c"]
            cur.execute(
                """
                SELECT COUNT(*) AS c FROM api_logs
                WHERE owner_id = %s AND action IN ('unlock_pin', 'lock_pin', 'manual_unlock', 'manual_lock')
                  AND success = 0
                """,
                (owner_id,),
            )
            unlock_fail = cur.fetchone()["c"]
            cur.execute(
                """
                SELECT * FROM api_logs
                WHERE owner_id = %s AND action IN ('unlock_pin', 'lock_pin', 'manual_unlock', 'manual_lock')
                ORDER BY id DESC LIMIT 8
                """,
                (owner_id,),
            )
            recent = cur.fetchall()

        if owner_id is None:
            cur.execute("SELECT COUNT(*) AS c FROM hotels")
            hotels = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) AS c FROM bookings WHERE status = 'active'")
            active_bookings = cur.fetchone()["c"]
            cur.execute(
                "SELECT COUNT(*) AS c FROM parking_spaces WHERE enabled = 1 AND (pin IS NULL OR pin = '')"
            )
            free_spaces = cur.fetchone()["c"]
        else:
            cur.execute("SELECT COUNT(*) AS c FROM hotels WHERE owner_id = %s", (owner_id,))
            hotels = cur.fetchone()["c"]
            cur.execute(
                "SELECT COUNT(*) AS c FROM bookings WHERE owner_id = %s AND status = 'active'",
                (owner_id,),
            )
            active_bookings = cur.fetchone()["c"]
            cur.execute(
                """
                SELECT COUNT(*) AS c FROM parking_spaces
                WHERE owner_id = %s AND enabled = 1 AND (pin IS NULL OR pin = '')
                """,
                (owner_id,),
            )
            free_spaces = cur.fetchone()["c"]

    return {
        "totalSpaces": total_spaces,
        "enabledSpaces": enabled_spaces,
        "freeSpaces": free_spaces,
        "hotels": hotels,
        "activeBookings": active_bookings,
        "pendingManagers": pending_managers,
        "managers": managers,
        "unlockSuccess": unlock_ok,
        "unlockFailed": unlock_fail,
        "recentUnlocks": [row_to_log(row) for row in recent],
    }


def set_pms_credentials(user_id: int, token: str, refresh_token: str = "") -> dict[str, Any] | None:
    now = utc_now()
    with get_cursor() as cur:
        cur.execute(
            """
            UPDATE users
            SET pms_token = %s, pms_refresh_token = %s, pms_token_refreshed_at = %s, updated_at = %s
            WHERE id = %s
            """,
            (token.strip(), refresh_token.strip(), now, now, user_id),
        )
    return get_user(user_id)


def clear_pms_credentials(user_id: int) -> dict[str, Any] | None:
    with get_cursor() as cur:
        cur.execute(
            """
            UPDATE users
            SET pms_token = '', pms_refresh_token = '', pms_token_refreshed_at = NULL, updated_at = %s
            WHERE id = %s
            """,
            (utc_now(), user_id),
        )
    return get_user(user_id)


def list_users_with_pms() -> list[dict[str, Any]]:
    with get_cursor() as cur:
        cur.execute(
            """
            SELECT * FROM users
            WHERE pms_token != '' AND status = 'approved'
            ORDER BY id ASC
            """
        )
        rows = cur.fetchall()
    return [row_to_user(row, include_secrets=True) for row in rows]


def row_to_hotel(row: dict[str, Any] | None, *, include_secrets: bool = False) -> dict[str, Any] | None:
    if row is None:
        return None
    data = {
        "id": row["id"],
        "ownerId": row["owner_id"],
        "hotelId": row["hotel_id"],
        "name": row["name"] or "",
        "checkInStart": row["check_in_start"] or "14:00",
        "checkOutEnd": row["check_out_end"] or "10:00",
        "ttlockUsername": row["ttlock_username"] or "",
        "ttlockConfigured": bool(row["ttlock_username"] and row["ttlock_password_enc"]),
        "spaceCount": int(row.get("space_count") or 0),
        "availableSpaces": int(row.get("available_spaces") or 0),
        "createdAt": _iso(row["created_at"]),
        "updatedAt": _iso(row["updated_at"]),
    }
    if include_secrets:
        data["ttlockPassword"] = decrypt_secret(row["ttlock_password_enc"])
    return data


HOTEL_SELECT = """
SELECT h.*,
  COUNT(s.id) AS space_count,
  SUM(CASE WHEN s.enabled = 1 AND (s.pin IS NULL OR s.pin = '') THEN 1 ELSE 0 END) AS available_spaces
FROM hotels h
LEFT JOIN parking_spaces s ON s.hotel_id = h.id
"""


def list_hotels(owner_id: int | None = None) -> list[dict[str, Any]]:
    with get_cursor() as cur:
        if owner_id is None:
            cur.execute(HOTEL_SELECT + " GROUP BY h.id ORDER BY h.name ASC")
        else:
            cur.execute(
                HOTEL_SELECT + " WHERE h.owner_id = %s GROUP BY h.id ORDER BY h.name ASC",
                (owner_id,),
            )
        rows = cur.fetchall()
    return [row_to_hotel(row) for row in rows]


def get_hotel(hotel_pk: int, *, include_secrets: bool = False) -> dict[str, Any] | None:
    with get_cursor() as cur:
        cur.execute(HOTEL_SELECT + " WHERE h.id = %s GROUP BY h.id", (hotel_pk,))
        row = cur.fetchone()
    return row_to_hotel(row, include_secrets=include_secrets)


def get_hotel_by_public_id(hotel_id: str, owner_id: int | None = None, *, include_secrets: bool = False) -> dict[str, Any] | None:
    with get_cursor() as cur:
        if owner_id is None:
            cur.execute("SELECT * FROM hotels WHERE hotel_id = %s", (str(hotel_id),))
        else:
            cur.execute(
                "SELECT * FROM hotels WHERE hotel_id = %s AND owner_id = %s",
                (str(hotel_id), owner_id),
            )
        row = cur.fetchone()
    return row_to_hotel(row, include_secrets=include_secrets)


def upsert_hotel(
    *,
    owner_id: int,
    hotel_id: str,
    name: str,
    check_in_start: str = "14:00",
    check_out_end: str = "10:00",
) -> dict[str, Any]:
    existing = get_hotel_by_public_id(hotel_id, owner_id)
    now = utc_now()
    if existing:
        with get_cursor() as cur:
            cur.execute(
                """
                UPDATE hotels
                SET name = %s, check_in_start = %s, check_out_end = %s, updated_at = %s
                WHERE id = %s
                """,
                (name, check_in_start, check_out_end, now, existing["id"]),
            )
        return get_hotel(existing["id"])
    with get_cursor() as cur:
        cur.execute(
            """
            INSERT INTO hotels (
                owner_id, hotel_id, name, check_in_start, check_out_end,
                ttlock_username, ttlock_password_enc, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, '', '', %s, %s)
            """,
            (owner_id, str(hotel_id), name, check_in_start, check_out_end, now, now),
        )
        pk = cur.lastrowid
    return get_hotel(pk)


def set_hotel_ttlock(hotel_pk: int, username: str, password: str) -> dict[str, Any] | None:
    enc = encrypt_secret(password) if password else ""
    with get_cursor() as cur:
        cur.execute(
            """
            UPDATE hotels
            SET ttlock_username = %s, ttlock_password_enc = %s, updated_at = %s
            WHERE id = %s
            """,
            (username.strip(), enc, utc_now(), hotel_pk),
        )
    return get_hotel(hotel_pk)


def clear_hotel_ttlock(hotel_pk: int) -> dict[str, Any] | None:
    with get_cursor() as cur:
        cur.execute(
            """
            UPDATE hotels
            SET ttlock_username = '', ttlock_password_enc = '', updated_at = %s
            WHERE id = %s
            """,
            (utc_now(), hotel_pk),
        )
    return get_hotel(hotel_pk)


def find_available_space(hotel_pk: int) -> dict[str, Any] | None:
    with get_cursor() as cur:
        cur.execute(
            SPACE_SELECT
            + """
            WHERE s.hotel_id = %s AND s.enabled = 1 AND (s.pin IS NULL OR s.pin = '')
            ORDER BY s.id ASC
            LIMIT 1
            """,
            (hotel_pk,),
        )
        row = cur.fetchone()
    return row_to_space(row)


BOOKING_SELECT = """
SELECT b.*, h.hotel_id AS hotel_public_id, h.name AS hotel_name, s.name AS space_name
FROM bookings b
LEFT JOIN hotels h ON h.id = b.hotel_id
LEFT JOIN parking_spaces s ON s.id = b.parking_space_id
"""


def row_to_booking(row: dict[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        "id": row["id"],
        "ownerId": row["owner_id"],
        "hotelId": row["hotel_id"],
        "hotelPublicId": row.get("hotel_public_id") or "",
        "hotelName": row.get("hotel_name") or "",
        "bookingId": row["booking_id"],
        "guestName": row["guest_name"] or "",
        "arrival": row["arrival"],
        "departure": row["departure"],
        "status": row["status"],
        "pin": row["pin"] or "",
        "parkingSpaceId": row["parking_space_id"],
        "parkingSpaceName": row.get("space_name") or "",
        "keyboardPwdId": row["keyboard_pwd_id"],
        "createdAt": _iso(row["created_at"]),
        "updatedAt": _iso(row["updated_at"]),
    }


def get_booking_by_pms_id(owner_id: int, booking_id: str) -> dict[str, Any] | None:
    with get_cursor() as cur:
        cur.execute(
            BOOKING_SELECT + " WHERE b.owner_id = %s AND b.booking_id = %s",
            (owner_id, str(booking_id)),
        )
        row = cur.fetchone()
    return row_to_booking(row)


def list_bookings(owner_id: int | None = None, hotel_id: int | None = None, limit: int = 100) -> list[dict[str, Any]]:
    query = BOOKING_SELECT + " WHERE 1=1"
    params: list[Any] = []
    if owner_id is not None:
        query += " AND b.owner_id = %s"
        params.append(owner_id)
    if hotel_id is not None:
        query += " AND b.hotel_id = %s"
        params.append(hotel_id)
    query += " ORDER BY b.id DESC LIMIT %s"
    params.append(limit)
    with get_cursor() as cur:
        cur.execute(query, params)
        rows = cur.fetchall()
    return [row_to_booking(row) for row in rows]


def upsert_booking(
    *,
    owner_id: int,
    hotel_id: int,
    booking_id: str,
    guest_name: str = "",
    arrival: str | None = None,
    departure: str | None = None,
    status: str = "active",
    pin: str | None = None,
    parking_space_id: int | None = None,
    keyboard_pwd_id: str | None = None,
    raw_payload: Any = None,
) -> dict[str, Any]:
    now = utc_now()
    payload = json.dumps(raw_payload) if raw_payload is not None else None
    existing = get_booking_by_pms_id(owner_id, booking_id)
    if existing:
        with get_cursor() as cur:
            cur.execute(
                """
                UPDATE bookings
                SET guest_name = %s, arrival = %s, departure = %s, status = %s,
                    pin = %s, parking_space_id = %s, keyboard_pwd_id = %s,
                    raw_payload = %s, updated_at = %s
                WHERE id = %s
                """,
                (
                    guest_name,
                    arrival,
                    departure,
                    status,
                    pin,
                    parking_space_id,
                    keyboard_pwd_id,
                    payload,
                    now,
                    existing["id"],
                ),
            )
        return get_booking_by_pms_id(owner_id, booking_id)
    with get_cursor() as cur:
        cur.execute(
            """
            INSERT INTO bookings (
                owner_id, hotel_id, booking_id, guest_name, arrival, departure, status,
                pin, parking_space_id, keyboard_pwd_id, raw_payload, created_at, updated_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                owner_id,
                hotel_id,
                str(booking_id),
                guest_name,
                arrival,
                departure,
                status,
                pin,
                parking_space_id,
                keyboard_pwd_id,
                payload,
                now,
                now,
            ),
        )
    return get_booking_by_pms_id(owner_id, booking_id)


def list_active_bookings_for_owner(owner_id: int) -> list[dict[str, Any]]:
    with get_cursor() as cur:
        cur.execute(
            BOOKING_SELECT + " WHERE b.owner_id = %s AND b.status = 'active'",
            (owner_id,),
        )
        rows = cur.fetchall()
    return [row_to_booking(row) for row in rows]
