"""TTLock Cloud API client — platform app credentials + per-manager TTLock user."""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

import config

logger = logging.getLogger(__name__)

_token_lock = threading.Lock()
_TOKEN_CACHE: dict[str, tuple[str, float]] = {}


def clear_cached_token(username: str = "") -> None:
    with _token_lock:
        if username:
            _TOKEN_CACHE.pop(username.strip().lower(), None)
        else:
            _TOKEN_CACHE.clear()


class TTLockError(Exception):
    def __init__(self, message: str, response: dict[str, Any] | None = None):
        super().__init__(message)
        self.response = response or {}


class TTLockClient:
    """
    clientId/clientSecret come from the ParkAccess Open Platform app (.env).
    username/password are the TTLock account that owns gateways/locks (per manager).
    """

    # TTLock parking locks (BM series): lockVersion.scene 2 or 7.
    PARKING_SCENES = {2, 7}

    def __init__(self, username: str = "", password: str = "") -> None:
        self.username = (username or "").strip()
        self.password = password or ""
        self._access_token: str | None = None
        self._token_expires_at: float = 0
        self._lock_detail_cache: dict[str, dict[str, Any]] = {}

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

        cache_key = self.username.lower()
        with _token_lock:
            cached = _TOKEN_CACHE.get(cache_key)
            if cached and time.time() < cached[1] - 60:
                self._access_token, self._token_expires_at = cached
                return self._access_token

        if not self.configured:
            raise TTLockError("HHS Lock credentials are not configured for this account")

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
            timeout=15,
        )
        data = response.json() if response.content else {}

        if response.status_code >= 400 or "access_token" not in data:
            raise TTLockError(
                data.get("errmsg") or data.get("description") or "Failed to obtain HHS Lock access token",
                response=data,
            )

        self._access_token = data["access_token"]
        expires_in = int(data.get("expires_in", 7776000))
        self._token_expires_at = time.time() + expires_in
        with _token_lock:
            _TOKEN_CACHE[cache_key] = (self._access_token, self._token_expires_at)
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
                data.get("errmsg") or data.get("description") or f"HHS Lock HTTP {response.status_code}",
                response=data,
            )
        return data

    def verify_credentials(self) -> dict[str, Any]:
        if self.mock_mode and not self.configured:
            return {"ok": True, "mock": True, "message": "Mock mode — credentials not verified live"}
        token = self._get_access_token()
        return {"ok": True, "mock": False, "message": "HHS Lock credentials verified", "tokenLength": len(token)}

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
            gateways.append(entry)

        if include_locks:
            def _load_locks(entry: dict[str, Any]) -> None:
                gateway_id = entry.get("gatewayId")
                if gateway_id is None:
                    return
                try:
                    entry["locks"] = self.list_gateway_locks(gateway_id)
                except TTLockError as exc:
                    logger.warning("Failed to list locks for gateway %s: %s", gateway_id, exc)
                    entry["locksError"] = str(exc)

            with ThreadPoolExecutor(max_workers=min(8, max(1, len(gateways)))) as pool:
                list(pool.map(_load_locks, gateways))

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

    def list_locks(self, page_no: int = 1, page_size: int = 100) -> list[dict[str, Any]]:
        """All locks on this TTLock account (not only those currently listed under a gateway)."""
        if self.mock_mode:
            return [
                {
                    "lockId": 10001,
                    "lockName": "Mock Lock 1",
                    "lockAlias": "Parking Space 1",
                    "lockMac": "11:22:33:44:55:01",
                },
                {
                    "lockId": 10002,
                    "lockName": "Mock Lock 2",
                    "lockAlias": "Parking Space 2",
                    "lockMac": "11:22:33:44:55:02",
                },
            ]
        data = self._api_post("/v3/lock/list", {"pageNo": page_no, "pageSize": page_size})
        if data.get("errcode") not in (None, 0) and "list" not in data:
            raise TTLockError(
                data.get("errmsg") or data.get("description") or "Failed to list locks",
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

    def get_lock_detail(self, lock_id: str | int) -> dict[str, Any]:
        key = str(lock_id)
        cached = self._lock_detail_cache.get(key)
        if cached:
            return cached
        if self.mock_mode:
            detail = {
                "lockId": lock_id,
                "lockVersion": {"scene": 2},
                "modelNum": "MOCK-PARK",
                "errcode": 0,
            }
        else:
            detail = self._api_post("/v3/lock/detail", {"lockId": lock_id})
        self._lock_detail_cache[key] = detail
        return detail

    def query_open_state(self, lock_id: str | int) -> dict[str, Any]:
        if self.mock_mode:
            return {"state": 0, "electricQuantity": 100, "mock": True}
        return self._api_post("/v3/lock/queryOpenState", {"lockId": lock_id})

    def is_parking_lock(self, lock_id: str | int) -> bool:
        try:
            detail = self.get_lock_detail(lock_id)
        except TTLockError:
            return True
        scene = (detail.get("lockVersion") or {}).get("scene")
        try:
            scene = int(scene)
        except (TypeError, ValueError):
            scene = None
        model = str(detail.get("modelNum") or detail.get("lockName") or "").upper()
        return scene in self.PARKING_SCENES or model.startswith("BM") or "SN9194" in model

    def _lock_command(
        self,
        lock_id: str | int,
        action: str,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        path = f"/v3/lock/{action}"
        payload = {"lockId": lock_id, "type": 2, **(extra or {})}
        request_payload = {
            "clientId": config.TTLOCK_CLIENT_ID or "(mock)",
            "lockId": str(lock_id),
            "date": int(time.time() * 1000),
            "endpoint": f"{config.TTLOCK_BASE_URL}{path}",
            "action": action,
            "params": {key: payload[key] for key in payload if key != "lockId"},
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
        data = self._api_post(path, payload, timeout=45)
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

    def _open_state_value(self, lock_id: str | int) -> int | None:
        try:
            state = self.query_open_state(lock_id)
        except TTLockError as exc:
            logger.warning("Could not read open state for lockId=%s: %s", lock_id, exc)
            return None
        try:
            return int(state.get("state"))
        except (TypeError, ValueError):
            return None

    def unlock(self, lock_id: str | int) -> dict[str, Any]:
        return self._lock_command(lock_id, "unlock")

    def lock(self, lock_id: str | int) -> dict[str, Any]:
        """Raise a parking barrier. Same gateway packet as Open, then wait for the motor."""
        parking = self.is_parking_lock(lock_id)
        if not parking:
            return self._lock_command(lock_id, "lock")

        # Do not send extra controlType/controlAction, and do not fire a second
        # close ~1s later — that interrupts the BM1002 motor after the beep.
        result = self._lock_command(lock_id, "lock")
        if not result.get("success"):
            return result

        time.sleep(6.5)
        after = self._open_state_value(lock_id)
        result.setdefault("response", {})
        if isinstance(result["response"], dict) and after is not None:
            result["response"]["openState"] = {"state": after}

        if after == 0:
            result["message"] = "Barrier locked"
        elif after == 1:
            result["success"] = False
            result["message"] = (
                "The parking lock beeped but the barrier stayed down. "
                "Stand clear of the sensor and make sure no car is on the space, then try Lock again."
            )
        return result

    def add_keyboard_pin(
        self,
        lock_id: str | int,
        pin: str,
        *,
        name: str = "ParkAccess",
        start_ms: int | None = None,
        end_ms: int | None = None,
    ) -> dict[str, Any]:
        now_ms = int(time.time() * 1000)
        extra = {
            "lockId": lock_id,
            "keyboardPwd": pin,
            "keyboardPwdName": name[:50],
            "addType": 2,
            "startDate": start_ms or now_ms,
            "endDate": end_ms or (now_ms + 1000 * 60 * 60 * 24 * 365),
        }
        if self.mock_mode:
            return {"success": True, "mock": True, "keyboardPwdId": f"mock-{pin}", "response": extra}
        data = self._api_post("/v3/keyboardPwd/add", extra, timeout=20)
        pwd_id = data.get("keyboardPwdId")
        success = bool(pwd_id) or data.get("errcode") in (0, None, -3007)
        return {
            "success": success,
            "mock": False,
            "keyboardPwdId": str(pwd_id) if pwd_id else None,
            "message": data.get("errmsg") or data.get("description") or "",
            "response": data,
        }

    def delete_keyboard_pin(self, lock_id: str | int, keyboard_pwd_id: str | int) -> dict[str, Any]:
        if self.mock_mode:
            return {"success": True, "mock": True}
        extra = {"lockId": lock_id, "keyboardPwdId": keyboard_pwd_id, "deleteType": 2}
        data = self._api_post("/v3/keyboardPwd/delete", extra, timeout=20)
        success = data.get("errcode") in (0, None)
        return {"success": success, "mock": False, "response": data, "message": data.get("errmsg") or ""}


def client_for_owner(owner_id: int) -> TTLockClient:
    from models import get_user

    user = get_user(owner_id, include_secrets=True)
    if user is None:
        return TTLockClient()
    return TTLockClient.for_manager(user)


def client_for_hotel(hotel: dict[str, Any]) -> TTLockClient:
    return TTLockClient(
        username=hotel.get("ttlockUsername") or "",
        password=hotel.get("ttlockPassword") or "",
    )


def client_for_space(space: dict[str, Any]) -> TTLockClient:
    from models import get_hotel

    if space.get("hotelId"):
        hotel = get_hotel(space["hotelId"], include_secrets=True)
        if hotel and hotel.get("ttlockConfigured"):
            return client_for_hotel(hotel)
    owner_id = space.get("ownerId")
    return client_for_owner(owner_id) if owner_id else TTLockClient()
