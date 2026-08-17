"""Session auth with roles: admin, manager, customer."""

from __future__ import annotations

from functools import wraps
from typing import Any

from flask import jsonify, session

ROLE_ADMIN = "admin"
ROLE_MANAGER = "manager"
ROLE_CUSTOMER = "customer"


def login_user(user: dict[str, Any]) -> None:
    session.clear()
    session["user_id"] = user["id"]
    session["role"] = user["role"]
    session["username"] = user["username"]
    session.permanent = True


def logout_user() -> None:
    session.clear()


def current_user_id() -> int | None:
    value = session.get("user_id")
    return int(value) if value is not None else None


def current_role() -> str | None:
    return session.get("role")


def is_authenticated() -> bool:
    return current_user_id() is not None


def require_roles(*roles: str):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not is_authenticated():
                return jsonify({"ok": False, "error": "Authentication required"}), 401
            if roles and current_role() not in roles:
                return jsonify({"ok": False, "error": "Permission denied"}), 403
            return view(*args, **kwargs)

        return wrapped

    return decorator


require_admin = require_roles(ROLE_ADMIN)
require_manager = require_roles(ROLE_MANAGER, ROLE_ADMIN)
