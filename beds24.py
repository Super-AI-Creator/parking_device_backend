"""Beds24 PMS API v2 client. Token stays on the backend."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import requests

BEDS24_AUTH_URL = "https://beds24.com/api/v2"
BEDS24_API_URL = "https://api.beds24.com/v2"


class Beds24Error(Exception):
    def __init__(self, message: str, response: dict[str, Any] | None = None, *, auth_failed: bool = False):
        super().__init__(message)
        self.response = response or {}
        self.auth_failed = auth_failed or _looks_like_auth_error(message, self.response)


def _looks_like_auth_error(message: str, data: dict[str, Any]) -> bool:
    text = f"{message} {data}".lower()
    err = data.get("error") if isinstance(data, dict) else {}
    code = str(err.get("code") if isinstance(err, dict) else data.get("code") or "")
    return (
        "unauthor" in text
        or "invalid token" in text
        or "expired" in text
        or "not authenticated" in text
        or code in {"401", "unauthorized", "invalid_token"}
    )


def _headers(token: str) -> dict[str, str]:
    return {"accept": "application/json", "token": token}


def _get(url: str, token: str, params: dict[str, Any] | None = None) -> Any:
    response = requests.get(url, headers=_headers(token), params=params or {}, timeout=45)
    try:
        data = response.json()
    except Exception as exc:
        raise Beds24Error(f"Beds24 returned invalid JSON ({response.status_code})") from exc
    if response.status_code >= 400 or "data" not in data:
        err = data.get("error") if isinstance(data, dict) else None
        if isinstance(err, dict):
            message = err.get("message") or str(err)
        else:
            message = str(err or data.get("message") or f"Beds24 HTTP {response.status_code}")
        raise Beds24Error(
            message,
            response=data if isinstance(data, dict) else {},
            auth_failed=response.status_code in {401, 403},
        )
    return data["data"]


def setup_from_invite(invite_code: str) -> dict[str, Any]:
    response = requests.get(
        f"{BEDS24_AUTH_URL}/authentication/setup",
        headers={"accept": "application/json", "code": invite_code.strip()},
        timeout=30,
    )
    data = response.json() if response.content else {}
    if response.status_code != 200 or "token" not in data:
        err = data.get("error") if isinstance(data, dict) else None
        message = err.get("message") if isinstance(err, dict) else (err or "Invalid invite code")
        raise Beds24Error(str(message), response=data)
    return {"token": data["token"], "refreshToken": data.get("refreshToken") or ""}


def refresh_access_token(refresh_token: str) -> dict[str, str]:
    response = requests.get(
        f"{BEDS24_AUTH_URL}/authentication/token",
        headers={"accept": "application/json", "refreshToken": refresh_token.strip()},
        timeout=30,
    )
    data = response.json() if response.content else {}
    if response.status_code != 200 or "token" not in data:
        raise Beds24Error("Failed to refresh Beds24 token", response=data, auth_failed=True)
    return {
        "token": data["token"],
        "refreshToken": data.get("refreshToken") or refresh_token.strip(),
    }


def get_properties(token: str) -> list[dict[str, Any]]:
    data = _get(
        f"{BEDS24_AUTH_URL}/properties",
        token,
        {"includeUnitDetails": "true", "includeAllRooms": "true"},
    )
    return data if isinstance(data, list) else []


def get_new_bookings(token: str) -> list[dict[str, Any]]:
    data = _get(f"{BEDS24_API_URL}/bookings", token, {"filter": "new"})
    return data if isinstance(data, list) else []


def get_modified_bookings(token: str) -> list[dict[str, Any]]:
    yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
    tomorrow = (datetime.utcnow() + timedelta(days=1)).strftime("%Y-%m-%d")
    data = _get(
        f"{BEDS24_API_URL}/bookings",
        token,
        {"modifiedFrom": yesterday, "modifiedTo": tomorrow},
    )
    return data if isinstance(data, list) else []


def get_departed_bookings(token: str) -> list[dict[str, Any]]:
    yesterday = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
    data = _get(f"{BEDS24_API_URL}/bookings", token, {"departureTo": yesterday})
    return data if isinstance(data, list) else []
