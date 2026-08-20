"""ParkAccess multi-tenant API: Admin, Parking Managers, Customers."""

from __future__ import annotations

from datetime import timedelta
import os

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

import config
from auth import (
    ROLE_ADMIN,
    ROLE_MANAGER,
    current_role,
    current_user_id,
    is_authenticated,
    login_user,
    logout_user,
    require_admin,
    require_manager,
    require_roles,
)
from beds24 import Beds24Error
from models import (
    IntegrityError,
    add_log,
    authenticate_user,
    clear_hotel_ttlock,
    clear_logs,
    clear_pms_credentials,
    clear_ttlock_credentials,
    create_manager,
    create_space,
    delete_user,
    get_booking_by_pms_id,
    get_dashboard_stats,
    get_hotel,
    get_space,
    get_space_by_pin,
    get_user,
    init_db,
    list_bookings,
    list_hotels,
    list_logs,
    list_spaces,
    list_users,
    set_hotel_pin_assign_mode,
    set_hotel_ttlock,
    set_pms_credentials,
    set_ttlock_credentials,
    update_space,
    update_user_profile,
    update_user_status,
    upsert_booking,
)
from rate_limit import AttemptLimiter
from scheduler import start_scheduler
from ttlock_service import TTLockClient, TTLockError, client_for_hotel, client_for_owner, client_for_space

app = Flask(__name__, static_folder=None)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = config.SECRET_KEY
app.permanent_session_lifetime = timedelta(days=7)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=config.COOKIE_SAMESITE,
    SESSION_COOKIE_SECURE=config.COOKIE_SECURE,
)

CORS(app, origins=config.CORS_ORIGINS, supports_credentials=True)

init_db()
unlock_limiter = AttemptLimiter(config.UNLOCK_MAX_ATTEMPTS, config.UNLOCK_WINDOW_SECONDS)
if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not config.DEBUG:
    start_scheduler()


def error(message: str, status: int = 400, **extra):
    return jsonify({"ok": False, "error": message, **extra}), status


def client_key() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def session_user() -> dict | None:
    uid = current_user_id()
    if uid is None:
        return None
    return get_user(uid)


def ensure_space_access(space: dict | None):
    if space is None:
        return error("Parking space not found", 404)
    role = current_role()
    if role == ROLE_ADMIN:
        return None
    if role == ROLE_MANAGER and space.get("ownerId") == current_user_id():
        return None
    return error("Permission denied", 403)


def ensure_hotel_access(hotel: dict | None):
    if hotel is None:
        return error("Hotel not found", 404)
    role = current_role()
    if role == ROLE_ADMIN:
        return None
    if role == ROLE_MANAGER and hotel.get("ownerId") == current_user_id():
        return None
    return error("Permission denied", 403)


def owner_scope() -> int | None:
    """None = all (admin). Manager = own id."""
    if current_role() == ROLE_ADMIN:
        return None
    return current_user_id()


def _valid_manual_pin(pin: str) -> str | None:
    pin = (pin or "").strip()
    if not pin:
        return None
    if not pin.isdigit() or len(pin) != 6:
        raise ValueError("Manual PIN must be 6 digits")
    return pin


def _sync_space_keyboard_pin(space: dict, pin: str | None) -> str | None:
    pin = (pin or "").strip() or None
    old_pin = (space.get("pin") or "").strip() or None
    old_id = space.get("keyboardPwdId")
    client = client_for_space(space)
    can_talk = client.configured or client.mock_mode

    if old_id and pin != old_pin and can_talk:
        try:
            client.delete_keyboard_pin(space["lockId"], old_id)
        except TTLockError:
            pass
        old_id = None

    if not pin:
        return None
    if pin == old_pin and old_id:
        return old_id
    if not can_talk:
        return old_id

    try:
        result = client.add_keyboard_pin(
            space["lockId"],
            pin,
            name=(space.get("name") or "Manual")[:50],
        )
        if result.get("success"):
            return result.get("keyboardPwdId") or old_id
    except TTLockError:
        pass
    return old_id


# ─── Public / auth ───────────────────────────────────────────────


@app.get("/api/health")
def health():
    return jsonify(
        {
            "ok": True,
            "app": config.APP_NAME,
            "ttlockAppConfigured": bool(config.TTLOCK_CLIENT_ID and config.TTLOCK_CLIENT_SECRET),
            "mockMode": config.TTLOCK_MOCK,
            "baseUrl": config.TTLOCK_BASE_URL,
            "authenticated": is_authenticated(),
            "role": current_role(),
        }
    )


@app.post("/api/auth/register")
def auth_register():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    display_name = str(data.get("displayName", "")).strip()
    email = str(data.get("email", "")).strip()
    company_name = str(data.get("companyName", "")).strip()

    if len(username) < 3:
        return error("Username must be at least 3 characters")
    if len(password) < 6:
        return error("Password must be at least 6 characters")

    try:
        user = create_manager(
            username=username,
            password=password,
            display_name=display_name or username,
            email=email,
            company_name=company_name,
        )
    except IntegrityError:
        return error("Username already exists", 409)

    return jsonify(
        {
            "ok": True,
            "message": "Registration submitted. An administrator must approve your account before you can sign in.",
            "user": user,
        }
    ), 201


@app.post("/api/auth/login")
def auth_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    user = authenticate_user(username, password)
    if user is None:
        return error("Invalid username or password", 401)

    if user["role"] == ROLE_MANAGER and user["status"] != "approved":
        return error(
            f"Account is {user['status']}. Please wait for administrator approval.",
            403,
            accountStatus=user["status"],
        )

    if user["status"] == "disabled":
        return error("Account is disabled", 403)

    login_user(user)
    return jsonify({"ok": True, "authenticated": True, "user": user, "app": config.APP_NAME})


@app.post("/api/auth/logout")
def auth_logout():
    logout_user()
    return jsonify({"ok": True, "authenticated": False})


@app.get("/api/auth/me")
def auth_me():
    user = session_user()
    return jsonify(
        {
            "ok": True,
            "authenticated": user is not None,
            "user": user,
            "app": config.APP_NAME,
        }
    )


# ─── Admin: user management ──────────────────────────────────────


@app.get("/api/admin/users")
@require_admin
def admin_list_users():
    status = request.args.get("status")
    role = request.args.get("role")
    return jsonify({"ok": True, "users": list_users(role=role, status=status)})


@app.post("/api/admin/users/<int:user_id>/approve")
@require_admin
def admin_approve_user(user_id: int):
    user = get_user(user_id)
    if user is None:
        return error("User not found", 404)
    if user["role"] != ROLE_MANAGER:
        return error("Only parking manager accounts require approval")
    updated = update_user_status(user_id, "approved", approved_by=current_user_id())
    return jsonify({"ok": True, "user": updated})


@app.post("/api/admin/users/<int:user_id>/reject")
@require_admin
def admin_reject_user(user_id: int):
    user = get_user(user_id)
    if user is None:
        return error("User not found", 404)
    updated = update_user_status(user_id, "rejected", approved_by=current_user_id())
    return jsonify({"ok": True, "user": updated})


@app.post("/api/admin/users/<int:user_id>/disable")
@require_admin
def admin_disable_user(user_id: int):
    user = get_user(user_id)
    if user is None:
        return error("User not found", 404)
    if user["role"] == ROLE_ADMIN:
        return error("Cannot disable the platform admin")
    updated = update_user_status(user_id, "disabled", approved_by=current_user_id())
    return jsonify({"ok": True, "user": updated})


@app.delete("/api/admin/users/<int:user_id>")
@require_admin
def admin_delete_user(user_id: int):
    if not delete_user(user_id):
        return error("User not found or cannot be deleted", 404)
    return jsonify({"ok": True})


# ─── Manager profile + TTLock credentials ────────────────────────


@app.put("/api/me/profile")
@require_roles(ROLE_MANAGER, ROLE_ADMIN)
def update_profile():
    data = request.get_json(silent=True) or {}
    user = update_user_profile(
        current_user_id(),
        displayName=str(data.get("displayName", "")).strip(),
        email=str(data.get("email", "")).strip(),
        companyName=str(data.get("companyName", "")).strip(),
    )
    return jsonify({"ok": True, "user": user})


@app.put("/api/me/ttlock")
@require_manager
def update_ttlock_credentials():
    """Parking managers store their own TTLock username/password to load region gateways."""
    if current_role() == ROLE_ADMIN:
        # Admin may set credentials for themselves for testing, or for a target manager via query
        target_id = request.args.get("userId", type=int) or current_user_id()
    else:
        target_id = current_user_id()

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    if data.get("clear"):
        user = clear_ttlock_credentials(target_id)
        return jsonify({"ok": True, "user": user, "message": "TTLock credentials cleared"})

    if not username or not password:
        return error("TTLock username and password are required")

    # Verify against TTLock before saving
    client = TTLockClient(username=username, password=password)
    try:
        verify = client.verify_credentials()
    except TTLockError as exc:
        return error(f"TTLock login failed: {exc}", 400, ttlock=exc.response)

    user = set_ttlock_credentials(target_id, username, password)
    return jsonify({"ok": True, "user": user, "verify": verify})


@app.get("/api/me/ttlock")
@require_manager
def get_ttlock_credentials():
    user = session_user()
    if current_role() == ROLE_ADMIN and request.args.get("userId"):
        user = get_user(request.args.get("userId", type=int))
    if user is None:
        return error("User not found", 404)
    return jsonify(
        {
            "ok": True,
            "ttlockUsername": user.get("ttlockUsername") or "",
            "ttlockConfigured": user.get("ttlockConfigured", False),
        }
    )


# ─── PMS (Beds24) ────────────────────────────────────────────────


@app.get("/api/me/pms")
@require_manager
def get_pms_credentials():
    user = session_user()
    if user is None:
        return error("User not found", 404)
    return jsonify(
        {
            "ok": True,
            "pmsConfigured": user.get("pmsConfigured", False),
            "pmsRefreshConfigured": user.get("pmsRefreshConfigured", False),
            "pmsTokenPreview": user.get("pmsTokenPreview") or "",
        }
    )


@app.put("/api/me/pms")
@require_manager
def update_pms_credentials():
    import beds24
    from booking_sync import sync_hotels_for_user

    data = request.get_json(silent=True) or {}
    if data.get("clear"):
        user = clear_pms_credentials(current_user_id())
        return jsonify({"ok": True, "user": user, "message": "PMS credentials cleared"})

    invite_code = str(data.get("inviteCode") or data.get("code") or "").strip()
    token = str(data.get("token") or data.get("accessToken") or "").strip()
    refresh_token = str(data.get("refreshToken") or "").strip()

    if invite_code:
        try:
            setup = beds24.setup_from_invite(invite_code)
        except Beds24Error as exc:
            return error(str(exc), 400, beds24=exc.response)
        token = setup["token"]
        refresh_token = setup.get("refreshToken") or refresh_token

    existing = get_user(current_user_id(), include_secrets=True)
    if not refresh_token and existing:
        refresh_token = (existing.get("pmsRefreshToken") or "").strip()

    if not token:
        return error("Beds24 access token or invite code is required")
    if not refresh_token:
        return error(
            "A Beds24 refresh token (or invite code) is required so ParkAccess can renew the access token automatically."
        )

    try:
        beds24.get_properties(token)
    except Beds24Error as exc:
        return error(f"Beds24 token failed: {exc}", 400, beds24=exc.response)

    user = set_pms_credentials(current_user_id(), token, refresh_token)
    secret_user = get_user(current_user_id(), include_secrets=True)
    hotels = []
    try:
        hotels = sync_hotels_for_user(secret_user)
    except Beds24Error as exc:
        return jsonify(
            {
                "ok": True,
                "user": user,
                "hotels": [],
                "message": f"PMS connected, but hotel sync failed: {exc}",
            }
        )

    return jsonify(
        {
            "ok": True,
            "user": user,
            "hotels": hotels,
            "count": len(hotels),
            "message": f"PMS connected. Imported {len(hotels)} hotel(s). Bookings will sync every minute in the background.",
        }
    )


@app.post("/api/me/pms/sync-hotels")
@require_manager
def sync_pms_hotels():
    from booking_sync import sync_hotels_for_user

    user = get_user(current_user_id(), include_secrets=True)
    if not user or not user.get("pmsConfigured"):
        return error("Save a Beds24 access token first", 400)
    try:
        hotels = sync_hotels_for_user(user)
    except Beds24Error as exc:
        return error(str(exc), 502, beds24=exc.response)
    return jsonify({"ok": True, "hotels": hotels, "count": len(hotels)})


@app.post("/api/me/pms/sync-bookings")
@require_manager
def sync_pms_bookings():
    from booking_sync import sync_bookings_for_user, sync_hotels_for_user, sync_locks_for_user

    user = get_user(current_user_id(), include_secrets=True)
    if not user or not user.get("pmsConfigured"):
        return error("Save a Beds24 access token first", 400)
    try:
        sync_hotels_for_user(user)
        sync_locks_for_user(user)
        result = sync_bookings_for_user(user)
    except Beds24Error as exc:
        return error(str(exc), 502)
    return jsonify({"ok": True, **result})


# ─── Hotels ──────────────────────────────────────────────────────


@app.get("/api/hotels")
@require_manager
def get_hotels():
    return jsonify({"ok": True, "hotels": list_hotels(owner_id=owner_scope())})


@app.put("/api/hotels/<int:hotel_pk>/ttlock")
@require_manager
def update_hotel_ttlock(hotel_pk: int):
    hotel = get_hotel(hotel_pk)
    denied = ensure_hotel_access(hotel)
    if denied:
        return denied

    data = request.get_json(silent=True) or {}
    if data.get("clear"):
        updated = clear_hotel_ttlock(hotel_pk)
        return jsonify({"ok": True, "hotel": updated, "message": "Hotel TTLock credentials cleared"})

    username = str(data.get("username") or data.get("clientId") or "").strip()
    password = str(data.get("password") or "")
    if not username or not password:
        return error("TTLock username and password are required")

    client = TTLockClient(username=username, password=password)
    try:
        verify = client.verify_credentials()
    except TTLockError as exc:
        return error(f"TTLock login failed: {exc}", 400, ttlock=exc.response)

    updated = set_hotel_ttlock(hotel_pk, username, password)
    from booking_sync import sync_locks_for_hotel

    lock_sync = sync_locks_for_hotel(updated)
    return jsonify(
        {
            "ok": True,
            "hotel": get_hotel(hotel_pk),
            "verify": verify,
            "lockSync": lock_sync,
            "message": (
                f"TTLock connected. Auto-imported {lock_sync.get('added', 0)} parking lock(s); "
                f"{lock_sync.get('count', 0)} total for this hotel."
            ),
        }
    )


@app.put("/api/hotels/<int:hotel_pk>")
@require_manager
def update_hotel_settings(hotel_pk: int):
    hotel = get_hotel(hotel_pk)
    denied = ensure_hotel_access(hotel)
    if denied:
        return denied

    data = request.get_json(silent=True) or {}
    if "pinAssignMode" in data:
        try:
            hotel = set_hotel_pin_assign_mode(hotel_pk, str(data.get("pinAssignMode") or ""))
        except ValueError as exc:
            return error(str(exc))
    return jsonify(
        {
            "ok": True,
            "hotel": hotel,
            "message": (
                "Auto mode: PIN goes on the TTLock whose name matches the booking parking info. "
                "Random mode: PIN goes on any free lock."
                if (hotel or {}).get("pinAssignMode") == "auto"
                else "Random mode: PIN goes on any free parking lock."
            ),
        }
    )


@app.get("/api/hotels/<int:hotel_pk>/gateways")
@require_manager
def get_hotel_gateways(hotel_pk: int):
    hotel = get_hotel(hotel_pk, include_secrets=True)
    denied = ensure_hotel_access(hotel)
    if denied:
        return denied

    client = client_for_hotel(hotel)
    if not client.configured and not client.mock_mode:
        return error("Save TTLock username and password for this hotel first.", 400)

    include_locks = request.args.get("includeLocks", "1") != "0"
    try:
        result = client.list_gateways(include_locks=include_locks)
    except TTLockError as exc:
        add_log(
            action="list_gateways",
            owner_id=hotel.get("ownerId"),
            actor_user_id=current_user_id(),
            success=False,
            message=str(exc),
            response_payload=exc.response,
        )
        return error(str(exc), 502, ttlock=exc.response)

    add_log(
        action="list_gateways",
        owner_id=hotel.get("ownerId"),
        actor_user_id=current_user_id(),
        success=True,
        message=f"Hotel {hotel.get('hotelId')}: {len(result['gateways'])} gateway(s)",
        response_payload={"count": len(result["gateways"]), "hotelId": hotel.get("hotelId")},
    )

    from booking_sync import sync_locks_for_hotel

    lock_sync = sync_locks_for_hotel(hotel, gateways=result.get("gateways") or [])
    hotel_spaces = list_spaces(owner_id=hotel.get("ownerId"), hotel_id=hotel_pk)
    return jsonify(
        {
            "ok": True,
            "mock": result["mock"],
            "hotel": get_hotel(hotel_pk),
            "gateways": result["gateways"],
            "spaces": hotel_spaces,
            "lockSync": lock_sync,
        }
    )


@app.get("/api/bookings")
@require_manager
def get_bookings():
    hotel_id = request.args.get("hotelId", type=int)
    return jsonify({"ok": True, "bookings": list_bookings(owner_id=owner_scope(), hotel_id=hotel_id)})


# ─── Dashboard / gateways / spaces ───────────────────────────────


@app.get("/api/dashboard")
@require_manager
def dashboard():
    scope = owner_scope()
    stats = get_dashboard_stats(owner_id=scope)
    hotels = list_hotels(owner_id=scope)
    configured = sum(1 for hotel in hotels if hotel.get("ttlockConfigured"))
    return jsonify(
        {
            "ok": True,
            "stats": stats,
            "gateways": {
                "configured": configured > 0,
                "hotelsWithTtlock": configured,
                "hotelCount": len(hotels),
            },
        }
    )


@app.get("/api/gateways")
@require_manager
def get_gateways():
    include_locks = request.args.get("includeLocks", "1") != "0"
    target_id = current_user_id()
    if current_role() == ROLE_ADMIN and request.args.get("userId"):
        target_id = request.args.get("userId", type=int)

    client = client_for_owner(target_id)
    if not client.configured and not client.mock_mode:
        return error(
            "Add your TTLock username and password in Settings to load gateways for your region.",
            400,
        )

    try:
        result = client.list_gateways(include_locks=include_locks)
    except TTLockError as exc:
        add_log(
            action="list_gateways",
            owner_id=target_id,
            actor_user_id=current_user_id(),
            success=False,
            message=str(exc),
            response_payload=exc.response,
        )
        return error(str(exc), 502, ttlock=exc.response)

    add_log(
        action="list_gateways",
        owner_id=target_id,
        actor_user_id=current_user_id(),
        success=True,
        message=f"Found {len(result['gateways'])} gateway(s)",
        response_payload={"count": len(result["gateways"]), "mock": result["mock"]},
    )
    return jsonify({"ok": True, "mock": result["mock"], "gateways": result["gateways"]})


@app.get("/api/parking-spaces")
@require_manager
def get_parking_spaces():
    hotel_id = request.args.get("hotelId", type=int)
    return jsonify({"ok": True, "spaces": list_spaces(owner_id=owner_scope(), hotel_id=hotel_id)})


@app.post("/api/parking-spaces")
@require_manager
def post_parking_space():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    lock_id = str(data.get("lockId", "")).strip()
    pin = str(data.get("pin", "")).strip()
    notes = str(data.get("notes", "")).strip()
    enabled = bool(data.get("enabled", True))
    hotel_pk = data.get("hotelId")

    owner_id = current_user_id()
    if current_role() == ROLE_ADMIN and data.get("ownerId"):
        owner_id = int(data["ownerId"])

    if not name:
        return error("Name is required")
    if not lock_id:
        return error("TTLock lockId is required")
    if not hotel_pk:
        return error("Select a hotel before assigning a parking lock")
    hotel = get_hotel(int(hotel_pk))
    denied = ensure_hotel_access(hotel)
    if denied:
        return denied
    if pin:
        try:
            pin = _valid_manual_pin(pin)
        except ValueError as exc:
            return error(str(exc))

    try:
        space = create_space(
            owner_id=owner_id,
            name=name,
            lock_id=lock_id,
            pin=pin,
            enabled=enabled,
            notes=notes,
            hotel_id=hotel["id"],
        )
    except IntegrityError:
        return error("This lock is already assigned, or the PIN is already used at this hotel", 409)

    if pin:
        keyboard_id = _sync_space_keyboard_pin(space, pin)
        if keyboard_id != space.get("keyboardPwdId"):
            space = update_space(space["id"], keyboardPwdId=keyboard_id)

    return jsonify({"ok": True, "space": space}), 201


@app.put("/api/parking-spaces/<int:space_id>")
@require_manager
def put_parking_space(space_id: int):
    space = get_space(space_id)
    denied = ensure_space_access(space)
    if denied:
        return denied

    data = request.get_json(silent=True) or {}
    fields = {}
    if "name" in data:
        name = str(data["name"]).strip()
        if not name:
            return error("Name cannot be empty")
        fields["name"] = name
    if "lockId" in data:
        lock_id = str(data["lockId"]).strip()
        if not lock_id:
            return error("lockId cannot be empty")
        fields["lockId"] = lock_id
    if "pin" in data:
        try:
            pin = _valid_manual_pin(str(data.get("pin") or ""))
        except ValueError as exc:
            return error(str(exc))
        fields["pin"] = pin or ""
    if "hotelId" in data:
        hotel_pk = data.get("hotelId")
        if not hotel_pk:
            return error("Hotel is required")
        hotel = get_hotel(int(hotel_pk))
        denied = ensure_hotel_access(hotel)
        if denied:
            return denied
        fields["hotelId"] = hotel["id"]
    if "enabled" in data:
        fields["enabled"] = bool(data["enabled"])
    if "notes" in data:
        fields["notes"] = str(data["notes"]).strip()

    try:
        updated = update_space(space_id, **fields)
    except IntegrityError:
        return error("PIN already exists at this hotel, or this lockId is already assigned", 409)

    if "pin" in fields:
        keyboard_id = _sync_space_keyboard_pin(space, fields.get("pin") or "")
        if keyboard_id != updated.get("keyboardPwdId"):
            updated = update_space(space_id, keyboardPwdId=keyboard_id)

    return jsonify({"ok": True, "space": updated})


@app.delete("/api/parking-spaces/<int:space_id>")
@require_manager
def remove_parking_space(space_id: int):
    """Free a parking lock: clear PIN on TTLock + DB, keep the space row as Available."""
    space = get_space(space_id)
    denied = ensure_space_access(space)
    if denied:
        return denied

    # Remove keyboard PIN from the physical TTLock.
    if space.get("keyboardPwdId") or space.get("pin"):
        _sync_space_keyboard_pin(space, "")

    freed_booking_id = space.get("bookingId")
    if freed_booking_id and space.get("ownerId"):
        booking = get_booking_by_pms_id(space["ownerId"], freed_booking_id)
        if booking and booking.get("status") in ("active", "unassigned"):
            # Keep booking as unassigned so it can take the next free lock — but not this one
            # until another lock is free (same request will not re-pin this space).
            upsert_booking(
                owner_id=space["ownerId"],
                hotel_id=booking["hotelId"],
                booking_id=booking["bookingId"],
                guest_name=booking.get("guestName") or "",
                arrival=booking.get("arrival"),
                departure=booking.get("departure"),
                status="unassigned",
                pin=booking.get("pin") or pin_from_booking_safe(booking["bookingId"]),
                parking_space_id=None,
                keyboard_pwd_id=None,
            )

    update_space(
        space_id,
        pin=None,
        bookingId=None,
        keyboardPwdId=None,
        enabled=True,
    )
    freed = get_space(space_id)

    add_log(
        action="space_free",
        owner_id=space.get("ownerId"),
        actor_user_id=current_user_id(),
        parking_space_id=space["id"],
        parking_space_name=space.get("name"),
        lock_id=space.get("lockId"),
        pin=space.get("pin"),
        success=True,
        message=f"Freed parking lock {space.get('name')} — now Available",
    )

    hotel_pk = space.get("hotelId")
    # Retry other waiting bookings on remaining free locks (this lock stays free for the UI).
    if hotel_pk and space.get("ownerId"):
        from booking_sync import _assign_pin, _booking_payload_from_row
        from models import get_user, list_unassigned_bookings_for_owner

        hotel = get_hotel(hotel_pk, include_secrets=True)
        owner = get_user(space["ownerId"], include_secrets=True)
        if hotel and hotel.get("ttlockConfigured") and owner:
            for waiting in list_unassigned_bookings_for_owner(space["ownerId"], hotel_pk):
                if freed_booking_id and str(waiting.get("bookingId")) == str(freed_booking_id):
                    continue  # don't immediately put the same booking back on this lock
                try:
                    _assign_pin(owner, hotel, _booking_payload_from_row(waiting))
                except Exception:
                    pass

    return jsonify(
        {
            "ok": True,
            "space": freed,
            "spaces": list_spaces(owner_id=space.get("ownerId"), hotel_id=hotel_pk) if hotel_pk else list_spaces(owner_id=space.get("ownerId")),
            "message": f"{space.get('name')} is Available again.",
        }
    )


def pin_from_booking_safe(booking_id: str) -> str:
    digits = "".join(c for c in str(booking_id) if c.isdigit()) or "0"
    return digits[-6:].rjust(6, "0")



def _pin_command(action: str):
    data = request.get_json(silent=True) or {}
    hotel_id = str(data.get("hotelId") or data.get("hotel_id") or "").strip()
    pin = str(data.get("pin", "")).strip()
    key = f"{client_key()}:{action}"

    if unlock_limiter.is_blocked(key):
        retry = unlock_limiter.retry_after_seconds(key)
        return error(f"Too many attempts. Try again in {retry}s.", 429, retryAfter=retry)

    if not hotel_id:
        unlock_limiter.register_failure(key)
        add_log(action=f"{action}_pin", success=False, message="Missing hotel ID")
        return error("Enter the hotel ID")
    if not pin or not pin.isdigit() or len(pin) != 6:
        unlock_limiter.register_failure(key)
        add_log(action=f"{action}_pin", pin=pin, success=False, message="Invalid PIN format")
        return error("Enter the 6-digit parking PIN")

    space = get_space_by_pin(pin, hotel_public_id=hotel_id)
    if space is None:
        unlock_limiter.register_failure(key)
        add_log(action=f"{action}_pin", pin=pin, success=False, message="Hotel ID or PIN not found")
        return error("Invalid hotel ID or PIN", 404)

    if not space["enabled"]:
        unlock_limiter.register_failure(key)
        add_log(
            action=f"{action}_pin",
            owner_id=space.get("ownerId"),
            parking_space_id=space["id"],
            parking_space_name=space["name"],
            lock_id=space["lockId"],
            pin=pin,
            success=False,
            message="Parking space is disabled",
        )
        return error("This parking space is currently unavailable", 403)

    owner_id = space.get("ownerId")
    client = client_for_space(space)
    try:
        result = client.unlock(space["lockId"]) if action == "unlock" else client.lock(space["lockId"])
    except TTLockError as exc:
        add_log(
            action=f"{action}_pin",
            owner_id=owner_id,
            parking_space_id=space["id"],
            parking_space_name=space["name"],
            lock_id=space["lockId"],
            pin=pin,
            success=False,
            message=str(exc),
            response_payload=exc.response,
        )
        return error("Unable to reach the parking lock. Please try again.", 502)

    add_log(
        action=f"{action}_pin",
        owner_id=owner_id,
        parking_space_id=space["id"],
        parking_space_name=space["name"],
        lock_id=space["lockId"],
        pin=pin,
        success=result["success"],
        message=result["message"],
        request_payload=result["request"],
        response_payload=result["response"],
    )

    if result["success"]:
        unlock_limiter.clear(key)
        return jsonify(
            {
                "ok": True,
                "message": "Barrier opened" if action == "unlock" else "Barrier locked",
                "spaceName": space["name"],
                "hotelId": space.get("hotelPublicId") or hotel_id,
                "action": action,
            }
        )

    return error(f"{action.title()} failed. Please try again.", 502)


@app.post("/api/unlock")
def unlock_by_pin():
    """Customer flow: hotel ID + 6-digit PIN → open."""
    return _pin_command("unlock")


@app.post("/api/lock")
def lock_by_pin():
    """Customer flow: hotel ID + 6-digit PIN → lock."""
    return _pin_command("lock")


@app.post("/api/parking-spaces/<int:space_id>/<action>")
@require_manager
def admin_space_command(space_id: int, action: str):
    if action not in {"unlock", "lock", "test"}:
        return error("Unknown action", 404)
    if action == "test":
        action = "unlock"

    space = get_space(space_id)
    denied = ensure_space_access(space)
    if denied:
        return denied

    client = client_for_space(space)
    try:
        result = client.unlock(space["lockId"]) if action == "unlock" else client.lock(space["lockId"])
    except TTLockError as exc:
        add_log(
            action=f"manual_{action}",
            owner_id=space.get("ownerId"),
            actor_user_id=current_user_id(),
            parking_space_id=space["id"],
            parking_space_name=space["name"],
            lock_id=space["lockId"],
            pin=space["pin"],
            success=False,
            message=str(exc),
            response_payload=exc.response,
        )
        return error(str(exc), 502, ttlock=exc.response)

    add_log(
        action=f"manual_{action}",
        owner_id=space.get("ownerId"),
        actor_user_id=current_user_id(),
        parking_space_id=space["id"],
        parking_space_name=space["name"],
        lock_id=space["lockId"],
        pin=space["pin"],
        success=result["success"],
        message=result["message"],
        request_payload=result["request"],
        response_payload=result["response"],
    )

    if not result["success"]:
        return error(result["message"], 502, space=space, ttlock=result["response"])

    return jsonify(
        {
            "ok": True,
            "message": result["message"],
            "mock": result["mock"],
            "space": space,
            "ttlock": result["response"],
        }
    )


@app.get("/api/logs")
@require_manager
def get_logs():
    limit = request.args.get("limit", 100, type=int)
    limit = max(1, min(limit, 500))
    return jsonify({"ok": True, "logs": list_logs(limit=limit, owner_id=owner_scope())})


@app.delete("/api/logs")
@require_manager
def delete_logs():
    count = clear_logs(owner_id=owner_scope())
    return jsonify({"ok": True, "deleted": count})


# ─── SPA ─────────────────────────────────────────────────────────


@app.get("/", defaults={"path": ""})
@app.get("/<path:path>")
def spa(path: str):
    if path.startswith("api/"):
        return error("Not found", 404)

    dist = config.FRONTEND_DIST
    if dist.is_dir():
        if path:
            candidate = dist / path
            if candidate.is_file():
                return send_from_directory(dist, path)
        index = dist / "index.html"
        if index.is_file():
            return send_from_directory(dist, "index.html")

    return jsonify(
        {
            "ok": True,
            "app": config.APP_NAME,
            "message": "API is running. Start the Vite frontend or build frontend/dist.",
        }
    )


if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
