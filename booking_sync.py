"""Assign / release parking PINs from Beds24 bookings."""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone, timedelta

import beds24
from beds24 import Beds24Error
from models import (
    IntegrityError,
    add_log,
    create_space,
    find_available_space,
    get_booking_by_pms_id,
    get_hotel,
    get_hotel_by_public_id,
    get_space,
    get_space_by_owner_lock,
    list_active_bookings_for_owner,
    list_hotels,
    list_spaces,
    list_unassigned_bookings_for_owner,
    set_pms_credentials,
    update_space,
    upsert_booking,
    upsert_hotel,
)
from ttlock_service import TTLockError, client_for_hotel

logger = logging.getLogger(__name__)


def pin_from_booking_id(booking_id: str, length: int = 6) -> str:
    digits = "".join(c for c in str(booking_id or "") if c.isdigit()) or "0"
    return digits[-length:].rjust(length, "0")


def _guest_name(booking: dict) -> str:
    return f"{booking.get('firstName', '')} {booking.get('lastName', '')}".strip() or "Guest"


def _is_cancelled(booking: dict) -> bool:
    status = booking.get("status")
    if status in (0, "0"):
        return True
    raw = booking.get("rawPayload")
    if isinstance(raw, dict) and raw is not booking:
        if _is_cancelled(raw):
            return True
    return str(status or "").lower() in {"cancelled", "canceled", "deleted", "no-show", "noshow"}


def _departure_date(booking: dict):
    raw = booking.get("rawPayload") if isinstance(booking.get("rawPayload"), dict) else {}
    value = str(booking.get("departure") or raw.get("departure") or "")[:10]
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        return None


def _booking_is_inactive(booking: dict) -> bool:
    """Cancelled, deleted, or already checked out — must not receive a parking PIN."""
    if not booking:
        return False
    if _is_cancelled(booking):
        return True
    day = _departure_date(booking)
    return bool(day and day < datetime.now(timezone.utc).date())


def _ensure_token(user: dict, *, force: bool = False) -> str | None:
    token = (user.get("pmsToken") or "").strip()
    refresh = (user.get("pmsRefreshToken") or "").strip()
    if not token and not refresh:
        return None
    refreshed_at = user.get("pmsTokenRefreshedAt")
    stale = force or not token
    if refreshed_at and not stale:
        try:
            dt = datetime.fromisoformat(str(refreshed_at).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            stale = datetime.now(timezone.utc) - dt > timedelta(hours=23)
        except ValueError:
            stale = True
    elif not refreshed_at:
        stale = True
    if stale:
        if not refresh:
            logger.warning(
                "PMS access token is stale for %s and no refresh token is stored",
                user.get("username"),
            )
            return token or None
        try:
            result = beds24.refresh_access_token(refresh)
            token = result["token"]
            refresh = result.get("refreshToken") or refresh
            set_pms_credentials(user["id"], token, refresh)
            user["pmsToken"] = token
            user["pmsRefreshToken"] = refresh
            user["pmsTokenRefreshedAt"] = datetime.now(timezone.utc).isoformat()
            logger.info("Renewed Beds24 access token for %s", user.get("username"))
        except Beds24Error as exc:
            logger.warning("PMS token refresh failed for user %s: %s", user.get("username"), exc)
            return None
    return token


def _beds24_call(user: dict, func, *args):
    token = _ensure_token(user)
    if not token:
        raise Beds24Error("No PMS token configured")
    try:
        return func(token, *args)
    except Beds24Error as exc:
        if not exc.auth_failed or not (user.get("pmsRefreshToken") or "").strip():
            raise
        token = _ensure_token(user, force=True)
        if not token:
            raise
        return func(token, *args)


def sync_hotels_for_user(user: dict) -> list[dict]:
    properties = _beds24_call(user, beds24.get_properties)
    hotels = []
    for prop in properties:
        hotel = upsert_hotel(
            owner_id=user["id"],
            hotel_id=str(prop.get("id") or ""),
            name=str(prop.get("name") or f"Hotel {prop.get('id')}"),
            check_in_start=str(prop.get("checkInStart") or "14:00")[:5],
            check_out_end=str(prop.get("checkOutEnd") or "10:00")[:5],
        )
        hotels.append(hotel)
    return hotels


def _lock_name(lock: dict, lock_id: str) -> str:
    return (
        str(lock.get("lockAlias") or lock.get("lockName") or f"Park {lock_id}").strip()
        or f"Park {lock_id}"
    )


def _collect_hotel_locks(client, gateways: list | None) -> tuple[list[tuple[dict, dict]], bool]:
    """Locks from gateways plus the account lock list, de-duplicated by lockId."""
    mock = False
    if gateways is None:
        try:
            result = client.list_gateways(include_locks=True)
        except TTLockError as exc:
            logger.warning("Gateway lock list failed: %s", exc)
            result = {"gateways": [], "mock": client.mock_mode}
        gateways = result.get("gateways") or []
        mock = bool(result.get("mock"))

    extra_locks: list[dict] = []
    try:
        extra_locks = client.list_locks()
        mock = mock or client.mock_mode
    except TTLockError as exc:
        logger.warning("Account lock list failed: %s", exc)

    seen: set[str] = set()
    pairs: list[tuple[dict, dict]] = []
    for gateway in gateways:
        for lock in gateway.get("locks") or []:
            lock_id = str(lock.get("lockId") or lock.get("lock_id") or "").strip()
            if not lock_id or lock_id in seen:
                continue
            seen.add(lock_id)
            pairs.append((gateway, lock))
    for lock in extra_locks:
        lock_id = str(lock.get("lockId") or lock.get("lock_id") or "").strip()
        if not lock_id or lock_id in seen:
            continue
        seen.add(lock_id)
        pairs.append(({"gatewayId": "account"}, lock))
    return pairs, mock


def sync_locks_for_hotel(hotel: dict, gateways: list | None = None) -> dict:
    """Import every TTLock lock on this hotel account as a parking space."""
    hotel_full = get_hotel(hotel["id"], include_secrets=True)
    if hotel_full is None or not hotel_full.get("ttlockConfigured"):
        return {"ok": False, "error": "Hotel HHS Lock is not configured", "added": 0, "updated": 0, "spaces": []}

    client = client_for_hotel(hotel_full)
    try:
        pairs, mock = _collect_hotel_locks(client, gateways)
    except TTLockError as exc:
        logger.warning("Lock sync failed for hotel %s: %s", hotel_full.get("hotelId"), exc)
        return {"ok": False, "error": str(exc), "added": 0, "updated": 0, "spaces": []}

    added = 0
    updated = 0
    errors: list[dict] = []
    spaces = []
    owner_id = hotel_full["ownerId"]

    for gateway, lock in pairs:
        lock_id = str(lock.get("lockId") or lock.get("lock_id") or "").strip()
        if not lock_id:
            continue
        name = _lock_name(lock, lock_id)
        existing = get_space_by_owner_lock(owner_id, lock_id)
        if existing:
            fields = {}
            if existing.get("hotelId") != hotel_full["id"]:
                fields["hotelId"] = hotel_full["id"]
            if not existing.get("pin") and name and existing.get("name") != name:
                fields["name"] = name
            if existing.get("pin") == "":
                fields["pin"] = None
            if not existing.get("enabled"):
                fields["enabled"] = True
            if fields:
                existing = update_space(existing["id"], **fields) or existing
                updated += 1
            spaces.append(existing)
            continue
        try:
            space = create_space(
                owner_id=owner_id,
                hotel_id=hotel_full["id"],
                name=name,
                lock_id=lock_id,
                pin=None,
                enabled=True,
                notes=f"Auto-imported from gateway {gateway.get('gatewayId') or ''}".strip(),
            )
            added += 1
            spaces.append(space)
        except IntegrityError as exc:
            existing = get_space_by_owner_lock(owner_id, lock_id)
            if existing:
                spaces.append(existing)
            else:
                errors.append({"lockId": lock_id, "error": str(exc)})
                logger.warning(
                    "Failed to import lock %s for hotel %s: %s",
                    lock_id,
                    hotel_full.get("hotelId"),
                    exc,
                )

    return {
        "ok": len(errors) == 0,
        "added": added,
        "updated": updated,
        "count": len(spaces),
        "spaces": spaces,
        "errors": errors,
        "mock": mock,
    }


def sync_locks_for_user(user: dict) -> dict:
    hotels = list_hotels(user["id"])
    added = 0
    updated = 0
    for hotel in hotels:
        if not hotel.get("ttlockConfigured"):
            continue
        result = sync_locks_for_hotel(hotel)
        added += int(result.get("added") or 0)
        updated += int(result.get("updated") or 0)
    return {"ok": True, "added": added, "updated": updated, "hotels": len(hotels)}


def _booking_payload_from_row(row: dict) -> dict:
    """Rebuild a Beds24-like payload so unassigned DB rows can be retried."""
    raw = row.get("rawPayload") or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except Exception:
            raw = {}
    if not isinstance(raw, dict):
        raw = {}
    payload = dict(raw)
    payload.setdefault("id", row.get("bookingId"))
    payload.setdefault("arrival", row.get("arrival"))
    payload.setdefault("departure", row.get("departure"))
    if not payload.get("firstName") and not payload.get("lastName"):
        guest = row.get("guestName") or ""
        payload["firstName"] = guest.split(" ", 1)[0]
        payload["lastName"] = guest.split(" ", 1)[1] if " " in guest else ""
    return payload


def _normalize_park_label(value) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[^a-z0-9]+", " ", text)
    return " ".join(text.split())


def _collect_text_values(node, into: list[str], *, depth: int = 0) -> None:
    if depth > 4 or node is None:
        return
    if isinstance(node, str):
        text = node.strip()
        if text:
            into.append(text)
        return
    if isinstance(node, (int, float)) and not isinstance(node, bool):
        into.append(str(node))
        return
    if isinstance(node, dict):
        for key, value in node.items():
            key_l = str(key).lower()
            if any(token in key_l for token in ("park", "unit", "room", "space", "spot", "stall")):
                _collect_text_values(value, into, depth=depth + 1)
            elif key_l in {"name", "title", "label", "description", "text", "value", "code", "comment", "comments", "note", "notes"}:
                _collect_text_values(value, into, depth=depth + 1)
            elif isinstance(value, (dict, list)):
                _collect_text_values(value, into, depth=depth + 1)
        return
    if isinstance(node, list):
        for item in node[:30]:
            _collect_text_values(item, into, depth=depth + 1)


def _is_parking_room_label(value) -> bool:
    """True for catalog names like Park, Parking, Parkplatz."""
    norm = _normalize_park_label(value)
    return "park" in norm


def parking_hints_from_booking(booking: dict) -> list[str]:
    """Pull parking / unit / room labels from a booking plus hotel catalog names."""
    hints: list[str] = []
    for key in (
        "unitName",
        "unit_name",
        "roomName",
        "room_name",
        "parking",
        "parkingName",
        "parkingSpace",
        "parking_space",
        "offerName",
        "unit",
        "room",
    ):
        value = booking.get(key)
        if isinstance(value, str) and value.strip():
            hints.append(value.strip())
        elif isinstance(value, dict):
            for inner in ("name", "unitName", "roomName", "title", "label"):
                if value.get(inner):
                    hints.append(str(value[inner]).strip())
    _collect_text_values(booking.get("invoiceItems"), hints)
    _collect_text_values(booking.get("infoItems"), hints)
    for key in ("comments", "comment", "note", "notes", "guestComments"):
        if booking.get(key):
            hints.append(str(booking[key]).strip())

    room_name = str(booking.get("roomName") or booking.get("room_name") or "").strip()
    unit_label = str(booking.get("unitName") or booking.get("unit_name") or "").strip()
    if not unit_label:
        unit_label = str(booking.get("unitId") or "").strip()
    if _is_parking_room_label(room_name) and unit_label:
        if _is_parking_room_label(unit_label) and re.search(r"\d+", unit_label):
            hints.append(unit_label)
        else:
            num = re.search(r"(\d+)$", _normalize_park_label(unit_label))
            hints.append(f"Park {num.group(1)}" if num else f"Park {unit_label}")

    seen: set[str] = set()
    cleaned: list[str] = []
    for hint in hints:
        if "[" in hint and "]" in hint:
            continue
        norm = _normalize_park_label(hint)
        if not norm or norm in seen:
            continue
        if "park" not in norm and (len(norm) < 3 or norm.isdigit()):
            continue
        seen.add(norm)
        cleaned.append(hint.strip())
    return cleaned


def _space_match_score(space: dict, hints: list[str]) -> int:
    name = _normalize_park_label(space.get("name") or "")
    lock_id = _normalize_park_label(space.get("lockId") or "")
    if not name:
        return 0
    best = 0
    for hint in hints:
        hn = _normalize_park_label(hint)
        if not hn:
            continue
        # Generic room type "Parking" is not the same as lock "Park 1".
        if hn in {"park", "parking"} and name not in {"park", "parking"}:
            continue
        if hn == name or hn == lock_id:
            best = max(best, 100)
            continue
        if any(c.isalpha() for c in hn) and (hn in name or name in hn):
            best = max(best, 80)
            continue
        hint_num = re.search(r"(\d+)$", hn)
        name_num = re.search(r"(\d+)$", name)
        if hint_num and name_num and hint_num.group(1) == name_num.group(1):
            if "park" in hn and "park" in name:
                best = max(best, 70)
    return best


def _match_space(spaces: list[dict], hints: list[str]) -> dict | None:
    ranked = []
    for space in spaces:
        score = _space_match_score(space, hints)
        if score >= 70:
            ranked.append((score, space))
    if not ranked:
        return None
    ranked.sort(key=lambda item: (-item[0], item[1].get("id") or 0))
    return ranked[0][1]


def _unit_name_index(properties: list[dict]) -> dict[tuple, str]:
    """Map (property, room) and (property, room, unit) to catalog names."""
    index: dict[tuple, str] = {}
    for prop in properties or []:
        pid = str(prop.get("id") or "")
        rooms = prop.get("roomTypes") or prop.get("rooms") or []
        if isinstance(prop.get("unitDetails"), list):
            rooms = list(rooms) + list(prop.get("unitDetails") or [])
        for room in rooms:
            if not isinstance(room, dict):
                continue
            room_id = str(room.get("id") or room.get("roomId") or "")
            room_name = str(room.get("name") or room.get("roomName") or "").strip()
            if pid and room_id and room_name:
                index[(pid, "room", room_id)] = room_name
            for unit in room.get("units") or room.get("unitDetails") or []:
                if not isinstance(unit, dict):
                    continue
                unit_id = str(unit.get("id") or unit.get("unitId") or "")
                unit_name = str(unit.get("name") or unit.get("unitName") or "").strip()
                if pid and room_id and unit_id:
                    index[(pid, "room_unit", room_id, unit_id)] = unit_name or unit_id
    return index


def _enrich_booking(booking: dict, unit_index: dict | None) -> dict:
    if not isinstance(booking, dict):
        return {}
    enriched = dict(booking)
    if not unit_index:
        return enriched
    pid = str(enriched.get("propertyId") or "")
    unit_id = str(enriched.get("unitId") or "")
    room_id = str(enriched.get("roomId") or "")
    if pid and room_id and (pid, "room", room_id) in unit_index:
        enriched["roomName"] = unit_index[(pid, "room", room_id)]
    room_unit_key = (pid, "room_unit", room_id, unit_id)
    if pid and room_id and unit_id and room_unit_key in unit_index:
        enriched["unitName"] = unit_index[room_unit_key]
    elif unit_id and not enriched.get("unitName"):
        enriched["unitName"] = unit_id
    return enriched


def _booking_needs_detail(booking: dict) -> bool:
    if booking.get("propertyId") and (booking.get("unitId") or booking.get("roomId")):
        return False
    if parking_hints_from_booking(booking):
        return False
    return True


def _refresh_booking_detail(user: dict, booking: dict, *, force: bool = False) -> dict:
    """Fetch the live HHS PMS booking. Do not copy catalog room names onto the payload."""
    if not force and not _booking_needs_detail(booking):
        return booking
    booking_id = str(booking.get("id") or booking.get("bookingId") or "")
    if not booking_id:
        return booking
    try:
        fresh = _beds24_call(user, beds24.get_booking, booking_id)
    except Beds24Error as exc:
        logger.warning("Beds24 booking %s detail fetch failed: %s", booking_id, exc)
        return booking
    if not isinstance(fresh, dict):
        return booking
    return fresh


def _pick_space(hotel: dict, booking: dict) -> tuple[dict | None, str, str | None]:
    """
    Returns (space, reason, unmatched_hint).
    reason is 'random', 'auto', or a failure explanation used in logs.
    """
    mode = str(hotel.get("pinAssignMode") or "random").lower()
    if mode not in {"random", "auto"}:
        mode = "random"
    hints = parking_hints_from_booking(booking)
    parking_hints = [hint for hint in hints if "park" in _normalize_park_label(hint)]
    if mode == "auto":
        if not parking_hints:
            return None, "Auto mode: booking has no parking info", None
        spaces = list_spaces(hotel_id=hotel["id"])
        match = _match_space(spaces, parking_hints)
        if match is None:
            return None, f"Auto mode: no HHS Lock matches booking parking '{parking_hints[0]}'", parking_hints[0]
        if not match.get("enabled"):
            return None, f"Auto mode: matched {match.get('name')} is disabled", parking_hints[0]
        if match.get("pin"):
            return None, f"Auto mode: matched {match.get('name')} is already occupied", parking_hints[0]
        return match, f"auto:{match.get('name')}", parking_hints[0]
    space = find_available_space(hotel["id"])
    return space, "random", parking_hints[0] if parking_hints else (hints[0] if hints else None)


def _assign_pin(user: dict, hotel: dict, booking: dict, unit_index: dict | None = None) -> dict:
    booking_id = str(booking.get("id") or "")
    pin = pin_from_booking_id(booking_id)
    guest = _guest_name(booking)
    existing = get_booking_by_pms_id(user["id"], booking_id)
    if existing and existing.get("status") == "active" and existing.get("parkingSpaceId"):
        held = get_space(existing["parkingSpaceId"])
        still_on_lock = held and str(held.get("bookingId") or "") == str(booking_id)
        if still_on_lock:
            if _booking_is_inactive(existing) or _booking_is_inactive(booking):
                _release_pin(user, existing, "cancelled_or_ended")
                return get_booking_by_pms_id(user["id"], booking_id)
            return existing
    if hotel.get("blocked"):
        return existing
    if _booking_is_inactive(booking) or (existing and _booking_is_inactive(existing)):
        if existing and existing.get("status") in {"active", "unassigned"}:
            _release_pin(user, existing, "cancelled_or_ended")
            return get_booking_by_pms_id(user["id"], booking_id)
        return existing

    auto = str(hotel.get("pinAssignMode") or "").lower() == "auto"
    match_payload = dict(booking)
    if auto:
        match_payload = _refresh_booking_detail(user, match_payload, force=True)
    if _booking_is_inactive(match_payload):
        if existing and existing.get("status") in {"active", "unassigned"}:
            _release_pin(user, existing, "cancelled_or_ended")
            return get_booking_by_pms_id(user["id"], booking_id)
        return existing
    booking = dict(match_payload)
    if auto and not unit_index:
        try:
            unit_index = _unit_name_index(_beds24_call(user, beds24.get_properties))
        except Exception as exc:
            logger.warning("Property catalog lookup failed before Auto PIN assign: %s", exc)
            unit_index = {}
    if unit_index:
        booking = _enrich_booking(booking, unit_index)
    guest = _guest_name(booking)

    space, pick_reason, hint = _pick_space(hotel, booking)
    if space is None and not hotel.get("_locksRefreshed"):
        hotel["_locksRefreshed"] = True
        try:
            sync_locks_for_hotel(hotel)
        except Exception as exc:
            logger.warning("Lock refresh before PIN assign failed: %s", exc)
        space, pick_reason, hint = _pick_space(hotel, booking)
    if space is None:
        if pick_reason == "random":
            fail_message = (
                f"No free parking lock for hotel {hotel['hotelId']} booking {booking_id}. "
                f"All imported locks already have a PIN, or no HHS Lock devices were found for this hotel."
            )
        else:
            fail_message = f"{pick_reason} (booking {booking_id}, hotel {hotel['hotelId']})"
        upsert_booking(
            owner_id=user["id"],
            hotel_id=hotel["id"],
            booking_id=booking_id,
            guest_name=guest,
            arrival=booking.get("arrival"),
            departure=booking.get("departure"),
            status="unassigned",
            pin=pin,
            raw_payload=booking,
        )
        # Only log once when first becoming unassigned — avoid toast spam every minute.
        if not existing or existing.get("status") != "unassigned":
            add_log(
                action="booking_assign",
                owner_id=user["id"],
                success=False,
                message=fail_message,
                pin=pin,
            )
        return get_booking_by_pms_id(user["id"], booking_id)

    keyboard_id = None
    hotel_full = get_hotel(hotel["id"], include_secrets=True)
    if hotel_full and hotel_full.get("ttlockConfigured"):
        client = client_for_hotel(hotel_full)
        try:
            result = client.add_keyboard_pin(
                space["lockId"],
                pin,
                name=f"{guest}-{booking_id}"[:50],
            )
            if result.get("success"):
                keyboard_id = result.get("keyboardPwdId")
        except TTLockError as exc:
            logger.warning("TTLock PIN add failed: %s", exc)

    try:
        update_space(
            space["id"],
            pin=pin,
            bookingId=booking_id,
            keyboardPwdId=keyboard_id,
            hotelId=hotel["id"],
        )
    except IntegrityError:
        upsert_booking(
            owner_id=user["id"],
            hotel_id=hotel["id"],
            booking_id=booking_id,
            guest_name=guest,
            arrival=booking.get("arrival"),
            departure=booking.get("departure"),
            status="unassigned",
            pin=pin,
            raw_payload=booking,
        )
        add_log(
            action="booking_assign",
            owner_id=user["id"],
            success=False,
            message=f"PIN {pin} already in use at hotel {hotel['hotelId']} for booking {booking_id}",
            pin=pin,
        )
        return get_booking_by_pms_id(user["id"], booking_id)
    saved = upsert_booking(
        owner_id=user["id"],
        hotel_id=hotel["id"],
        booking_id=booking_id,
        guest_name=guest,
        arrival=booking.get("arrival"),
        departure=booking.get("departure"),
        status="active",
        pin=pin,
        parking_space_id=space["id"],
        keyboard_pwd_id=keyboard_id,
        raw_payload=booking,
    )
    add_log(
        action="booking_assign",
        owner_id=user["id"],
        parking_space_id=space["id"],
        parking_space_name=space["name"],
        lock_id=space["lockId"],
        pin=pin,
        success=True,
        message=f"Assigned PIN {pin} for booking {booking_id} at hotel {hotel['hotelId']} ({pick_reason})",
    )
    return saved


def _release_pin(user: dict, booking_row: dict, reason: str) -> None:
    space = get_space(booking_row["parkingSpaceId"]) if booking_row.get("parkingSpaceId") else None
    hotel = get_hotel(booking_row["hotelId"], include_secrets=True) if booking_row.get("hotelId") else None
    if space and space.get("keyboardPwdId") and hotel and hotel.get("ttlockConfigured"):
        try:
            client_for_hotel(hotel).delete_keyboard_pin(space["lockId"], space["keyboardPwdId"])
        except TTLockError as exc:
            logger.warning("TTLock PIN delete failed: %s", exc)
    if space:
        update_space(space["id"], pin="", bookingId=None, keyboardPwdId=None)
    upsert_booking(
        owner_id=user["id"],
        hotel_id=booking_row["hotelId"],
        booking_id=booking_row["bookingId"],
        guest_name=booking_row.get("guestName") or "",
        arrival=booking_row.get("arrival"),
        departure=booking_row.get("departure"),
        status="released",
        pin=None,
        parking_space_id=None,
        keyboard_pwd_id=None,
    )
    add_log(
        action="booking_release",
        owner_id=user["id"],
        parking_space_id=space["id"] if space else None,
        parking_space_name=space["name"] if space else None,
        lock_id=space["lockId"] if space else None,
        pin=booking_row.get("pin"),
        success=True,
        message=f"Released PIN for booking {booking_row['bookingId']} ({reason})",
    )


def _hotel_for_booking(user: dict, booking: dict) -> dict | None:
    property_id = str(booking.get("propertyId") or "")
    if not property_id:
        return None
    return get_hotel_by_public_id(property_id, user["id"], include_secrets=True)


def sync_bookings_for_user(user: dict) -> dict:
    assigned = 0
    released = 0
    errors = 0

    try:
        new_bookings = _beds24_call(user, beds24.get_new_bookings)
        modified = _beds24_call(user, beds24.get_modified_bookings)
        departed = _beds24_call(user, beds24.get_departed_bookings)
    except Beds24Error as exc:
        logger.warning("Beds24 fetch failed for %s: %s", user.get("username"), exc)
        return {"ok": False, "error": str(exc)}

    unit_index: dict[tuple, str] = {}
    try:
        unit_index = _unit_name_index(_beds24_call(user, beds24.get_properties))
    except Beds24Error as exc:
        logger.warning("Beds24 property lookup failed for %s: %s", user.get("username"), exc)

    seen_ids = set()
    for booking in list(new_bookings) + list(modified):
        booking = _enrich_booking(booking, unit_index)
        booking_id = str(booking.get("id") or "")
        if not booking_id or booking_id in seen_ids:
            continue
        seen_ids.add(booking_id)
        hotel = _hotel_for_booking(user, booking)
        if hotel is None:
            continue
        try:
            if _is_cancelled(booking):
                existing = get_booking_by_pms_id(user["id"], booking_id)
                if existing and existing.get("status") in {"active", "unassigned"}:
                    _release_pin(user, existing, "cancelled")
                    released += 1
                continue
            if hotel.get("blocked"):
                continue
            _assign_pin(user, hotel, booking, unit_index)
            assigned += 1
        except Exception as exc:
            errors += 1
            logger.exception("Booking sync failed for %s: %s", booking_id, exc)

    departed_ids = {str(b.get("id")) for b in departed if b.get("id")}
    for row in list_active_bookings_for_owner(user["id"]):
        if row["bookingId"] in departed_ids or _booking_is_inactive(row):
            _release_pin(user, row, "departed" if row["bookingId"] in departed_ids else "cancelled_or_ended")
            released += 1

    # Retry bookings that were waiting for a free lock (e.g. after Space delete/re-import).
    for row in list_unassigned_bookings_for_owner(user["id"]):
        if row["bookingId"] in departed_ids or _booking_is_inactive(row):
            _release_pin(user, row, "cancelled_or_ended")
            released += 1
            continue
        hotel = get_hotel(row["hotelId"], include_secrets=True)
        if hotel is None:
            continue
        if hotel.get("blocked"):
            continue
        try:
            before = row.get("parkingSpaceId")
            payload = _enrich_booking(_booking_payload_from_row(row), unit_index)
            saved = _assign_pin(user, hotel, payload, unit_index)
            if saved and saved.get("parkingSpaceId") and saved.get("parkingSpaceId") != before:
                assigned += 1
        except Exception as exc:
            errors += 1
            logger.exception("Unassigned retry failed for %s: %s", row.get("bookingId"), exc)

    return {"ok": True, "assigned": assigned, "released": released, "errors": errors}


def sync_all_managers() -> None:
    from models import list_users_with_pms

    for user in list_users_with_pms():
        try:
            sync_hotels_for_user(user)
            sync_locks_for_user(user)
            result = sync_bookings_for_user(user)
            logger.info("PMS sync user=%s result=%s", user.get("username"), result)
        except Exception as exc:
            logger.exception("PMS sync failed for %s: %s", user.get("username"), exc)
