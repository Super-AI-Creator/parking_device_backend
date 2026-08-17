"""TTLock Cloud API client — platform app credentials + per-manager TTLock user."""

from __future__ import annotations

import hashlib
import logging
import time
from typing import Any

import requests

import config

logger = logging.getLogger(__name__)


class TTLockError(Exception):
    def __init__(self, message: str, response: dict[str, Any] | None = None):
        super().__init__(message)
        self.response = response or {}


class TTLockClient:
    """
    clientId/clientSecret come from the ParkAccess Open Platform app (.env).
    username/password are the TTLock account that owns gateways/locks (per manager).
    """

    def __init__(self, username: str = "", password: str = "") -> None:
        self.username = (username or "").strip()
        self.password = password or ""
        self._access_token: str | None = None
        self._token_expires_at: float = 0

    @classmethod
    def for_manager(cls, user: dict[str, Any]) -> "TTLockClient":
        return cls(
            username=user.get("ttlockUsername") or "",
            password=user.get("ttlockPassword") or "",
        )

    @property
    def app_configured(self) -> bool:
        return bool(config.TTLOCK_CLIENT_ID and config.TTLOCK_CLIENT_SECRET)

    @property
    def configured(self) -> bool:
        return self.app_configured and bool(self.username and self.password)

    @property
    def mock_mode(self) -> bool:
        return config.TTLOCK_MOCK or not self.configured

    def _password_md5(self) -> str:
        password = self.password
        if len(password) == 32 and all(c in "0123456789abcdef" for c in password.lower()):
            return password.lower()
        return hashlib.md5(password.encode("utf-8")).hexdigest()

    def _get_access_token(self) -> str:
        if self._access_token and time.time() < self._token_expires_at - 60:
            return self._access_token

        if not self.configured:
            raise TTLockError("TTLock credentials are not configured for this account")

        url = f"{config.TTLOCK_BASE_URL}/oauth2/token"
        payload = {
            "client_id": config.TTLOCK_CLIENT_ID,
            "client_secret": config.TTLOCK_CLIENT_SECRET,
            "username": self.username,
            "password": self._password_md5(),
            "grant_type": "password",
        }

        response = requests.post(
            url,
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        data = response.json() if response.content else {}

        if response.status_code >= 400 or "access_token" not in data:
            raise TTLockError(
                data.get("errmsg") or data.get("description") or "Failed to obtain TTLock access token",
                response=data,
            )

        self._access_token = data["access_token"]
        expires_in = int(data.get("expires_in", 7776000))
        self._token_expires_at = time.time() + expires_in
        return self._access_token

    def _api_post(self, path: str, extra: dict[str, Any], timeout: int = 45) -> dict[str, Any]:
        access_token = self._get_access_token()
        url = f"{config.TTLOCK_BASE_URL}{path}"
        form = {
            "clientId": config.TTLOCK_CLIENT_ID,
            "accessToken": access_token,
            "date": str(int(time.time() * 1000)),
            **{key: str(value) for key, value in extra.items()},
        }
        response = requests.post(
            url,
            data=form,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
        )
        data = response.json() if response.content else {}
        if response.status_code >= 400:
            raise TTLockError(
                data.get("errmsg") or data.get("description") or f"TTLock HTTP {response.status_code}",
                response=data,
            )
        return data

    def verify_credentials(self) -> dict[str, Any]:
        if self.mock_mode and not self.configured:
            return {"ok": True, "mock": True, "message": "Mock mode — credentials not verified live"}
        token = self._get_access_token()
        return {"ok": True, "mock": False, "message": "TTLock credentials verified", "tokenLength": len(token)}

    @staticmethod
    def _gateway_version_label(version: Any) -> str:
        mapping = {1: "G1", 2: "G2", 3: "G3", 4: "G4"}
        try:
            return mapping.get(int(version), f"v{version}")
        except (TypeError, ValueError):
            return "unknown"

    def list_gateways(self, *, include_locks: bool = True) -> dict[str, Any]:
        if self.mock_mode:
            gateways = [
                {
                    "gatewayId": 900001,
                    "gatewayMac": "AA:BB:CC:DD:EE:FF",
                    "gatewayVersion": 2,
                    "gatewayVersionLabel": "G2",
                    "gatewayName": "Mock G2",
                    "networkName": "Mock-WiFi",
                    "lockNum": 2,
                    "isOnline": True,
                    "locks": [
                        {
                            "lockId": 10001,
                            "lockName": "Mock Lock 1",
                            "lockAlias": "Parking Space 1",
                            "lockMac": "11:22:33:44:55:01",
                            "rssi": -70,
                        },
                        {
                            "lockId": 10002,
                            "lockName": "Mock Lock 2",
                            "lockAlias": "Parking Space 2",
                            "lockMac": "11:22:33:44:55:02",
                            "rssi": -82,
                        },
                    ],
                }
            ]
            return {"success": True, "mock": True, "gateways": gateways, "raw": {"list": gateways}}

        data = self._api_post("/v3/gateway/list", {"pageNo": 1, "pageSize": 100})
        if data.get("errcode") not in (None, 0):
            raise TTLockError(
                data.get("errmsg") or data.get("description") or "Failed to list gateways",
                response=data,
            )

        gateways = []
        for item in data.get("list") or []:
            gateway_id = item.get("gatewayId")
            entry = {
                "gatewayId": gateway_id,
                "gatewayMac": item.get("gatewayMac"),
                "gatewayName": item.get("gatewayName"),
                "gatewayVersion": item.get("gatewayVersion"),
                "gatewayVersionLabel": self._gateway_version_label(item.get("gatewayVersion")),
                "networkName": item.get("networkName"),
                "lockNum": item.get("lockNum", 0),
                "isOnline": bool(item.get("isOnline")),
                "locks": [],
            }
            if include_locks and gateway_id is not None:
                try:
                    entry["locks"] = self.list_gateway_locks(gateway_id)
                except TTLockError as exc:
                    logger.warning("Failed to list locks for gateway %s: %s", gateway_id, exc)
                    entry["locksError"] = str(exc)
            gateways.append(entry)

        return {"success": True, "mock": False, "gateways": gateways, "raw": data}

    def list_gateway_locks(self, gateway_id: int | str) -> list[dict[str, Any]]:
        data = self._api_post("/v3/gateway/listLock", {"gatewayId": gateway_id})
        if data.get("errcode") not in (None, 0) and "list" not in data:
            raise TTLockError(
                data.get("errmsg") or data.get("description") or "Failed to list gateway locks",
                response=data,
            )
        locks = []
        for item in data.get("list") or []:
            locks.append(
                {
                    "lockId": item.get("lockId"),
                    "lockMac": item.get("lockMac"),
                    "lockName": item.get("lockName"),
                    "lockAlias": item.get("lockAlias"),
                    "rssi": item.get("rssi"),
                    "updateDate": item.get("updateDate"),
                }
            )
        return locks

    def _lock_command(self, lock_id: str | int, action: str) -> dict[str, Any]:
        path = f"/v3/lock/{action}"
        request_payload = {
            "clientId": config.TTLOCK_CLIENT_ID or "(mock)",
            "lockId": str(lock_id),
            "date": int(time.time() * 1000),
            "endpoint": f"{config.TTLOCK_BASE_URL}{path}",
            "action": action,
        }

        if self.mock_mode:
            response_payload = {
                "errcode": 0,
                "errmsg": "none error message",
                "description": f"MOCK {action} success",
                "mock": True,
            }
            return {
                "success": True,
                "mock": True,
                "message": f"Mock {action} succeeded for lockId {lock_id}",
                "request": request_payload,
                "response": response_payload,
            }

        request_payload["accessToken"] = "***redacted***"
        data = self._api_post(path, {"lockId": lock_id}, timeout=45)
        errcode = data.get("errcode", 0)
        success = errcode == 0
        message = data.get("errmsg") or data.get("description") or (
            f"{action.title()} succeeded" if success else f"{action.title()} failed"
        )
        if not success:
            logger.warning("TTLock %s failed for lockId=%s: %s", action, lock_id, data)
        return {
            "success": success,
            "mock": False,
            "message": message,
            "request": request_payload,
            "response": data,
        }

    def unlock(self, lock_id: str | int) -> dict[str, Any]:
        return self._lock_command(lock_id, "unlock")

    def lock(self, lock_id: str | int) -> dict[str, Any]:
        return self._lock_command(lock_id, "lock")


def client_for_owner(owner_id: int) -> TTLockClient:
    from models import get_user

    user = get_user(owner_id, include_secrets=True)
    if user is None:
        return TTLockClient()
    return TTLockClient.for_manager(user)
