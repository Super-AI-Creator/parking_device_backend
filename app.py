"""ParkAccess multi-tenant API: Admin, Parking Managers, Customers."""

from __future__ import annotations

from datetime import timedelta

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
from models import (
    IntegrityError,
    add_log,
    authenticate_user,
    clear_logs,
    clear_ttlock_credentials,
    create_manager,
    create_space,
    delete_space,
    delete_user,
    get_dashboard_stats,
    get_space,
    get_space_by_pin,
    get_user,
    init_db,
    list_logs,
    list_spaces,
    list_users,
    set_ttlock_credentials,
    update_space,
    update_user_profile,
    update_user_status,
)
from rate_limit import AttemptLimiter
from ttlock_service import TTLockClient, TTLockError, client_for_owner

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


def owner_scope() -> int | None:
    """None = all (admin). Manager = own id."""
    if current_role() == ROLE_ADMIN:
        return None
    return current_user_id()


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


# ─── Dashboard / gateways / spaces ───────────────────────────────


@app.get("/api/dashboard")
@require_manager
def dashboard():
    scope = owner_scope()
    stats = get_dashboard_stats(owner_id=scope)
    gateway_summary = {"count": 0, "online": 0, "configured": False}

    me = get_user(current_user_id(), include_secrets=True)
    target_id = current_user_id() if current_role() == ROLE_MANAGER else current_user_id()
    if me and me.get("ttlockConfigured"):
        client = client_for_owner(target_id)
        gateway_summary["configured"] = client.configured
        if client.configured or client.mock_mode:
            try:
                result = client.list_gateways(include_locks=False)
                gateways = result.get("gateways") or []
                gateway_summary.update(
                    {
                        "count": len(gateways),
                        "online": sum(1 for g in gateways if g.get("isOnline")),
                        "mock": result.get("mock", False),
                    }
                )
            except TTLockError:
                gateway_summary["error"] = "Unable to reach TTLock gateway list"
    elif current_role() == ROLE_ADMIN:
        gateway_summary["note"] = "Save TTLock credentials under My TTLock to browse gateways as admin."

    return jsonify({"ok": True, "stats": stats, "gateways": gateway_summary})


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
    return jsonify({"ok": True, "spaces": list_spaces(owner_id=owner_scope())})


@app.post("/api/parking-spaces")
@require_manager
def post_parking_space():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()
    lock_id = str(data.get("lockId", "")).strip()
    pin = str(data.get("pin", "")).strip()
    notes = str(data.get("notes", "")).strip()
    enabled = bool(data.get("enabled", True))

    owner_id = current_user_id()
    if current_role() == ROLE_ADMIN and data.get("ownerId"):
        owner_id = int(data["ownerId"])

    if not name:
        return error("Name is required")
    if not lock_id:
        return error("TTLock lockId is required")
    if not pin or not pin.isdigit() or len(pin) < 4:
        return error("PIN must be at least 4 digits")

    try:
        space = create_space(
            owner_id=owner_id,
            name=name,
            lock_id=lock_id,
            pin=pin,
            enabled=enabled,
            notes=notes,
        )
    except IntegrityError:
        return error("PIN already exists, or this lockId is already assigned to you", 409)

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
        pin = str(data["pin"]).strip()
        if not pin or not pin.isdigit() or len(pin) < 4:
            return error("PIN must be at least 4 digits")
        fields["pin"] = pin
    if "enabled" in data:
        fields["enabled"] = bool(data["enabled"])
    if "notes" in data:
        fields["notes"] = str(data["notes"]).strip()

    try:
        updated = update_space(space_id, **fields)
    except IntegrityError:
        return error("PIN already exists, or this lockId is already assigned", 409)

    return jsonify({"ok": True, "space": updated})


@app.delete("/api/parking-spaces/<int:space_id>")
@require_manager
def remove_parking_space(space_id: int):
    space = get_space(space_id)
    denied = ensure_space_access(space)
    if denied:
        return denied
    delete_space(space_id)
    return jsonify({"ok": True})


def _pin_command(action: str):
    data = request.get_json(silent=True) or {}
    pin = str(data.get("pin", "")).strip()
    key = f"{client_key()}:{action}"

    if unlock_limiter.is_blocked(key):
        retry = unlock_limiter.retry_after_seconds(key)
        return error(f"Too many attempts. Try again in {retry}s.", 429, retryAfter=retry)

    if not pin or not pin.isdigit():
        unlock_limiter.register_failure(key)
        add_log(action=f"{action}_pin", success=False, message="Invalid PIN format")
        return error("Enter a valid numeric PIN")

    space = get_space_by_pin(pin)
    if space is None:
        unlock_limiter.register_failure(key)
        add_log(action=f"{action}_pin", pin=pin, success=False, message="PIN not found")
        return error("Invalid PIN", 404)

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
    client = client_for_owner(owner_id) if owner_id else TTLockClient()
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
                "action": action,
            }
        )

    return error(f"{action.title()} failed. Please try again.", 502)


@app.post("/api/unlock")
def unlock_by_pin():
    """Customer flow: PIN → open."""
    return _pin_command("unlock")


@app.post("/api/lock")
def lock_by_pin():
    """Customer flow: PIN → lock/raise."""
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

    client = client_for_owner(space["ownerId"]) if space.get("ownerId") else TTLockClient()
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
