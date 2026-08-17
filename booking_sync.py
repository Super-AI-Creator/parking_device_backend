"""Assign / release parking PINs from Beds24 bookings."""

from __future__ import annotations

import logging
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
    return str(status or "").lower() in {"cancelled", "canceled", "deleted", "no-show", "noshow"}


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
        return {"ok": False, "error": "Hotel TTLock is not configured", "added": 0, "updated": 0, "spaces": []}

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
    return {
        "id": row.get("bookingId"),
        "arrival": row.get("arrival"),
        "departure": row.get("departure"),
        "firstName": (row.get("guestName") or "").split(" ", 1)[0],
        "lastName": (
            (row.get("guestName") or "").split(" ", 1)[1]
            if " " in (row.get("guestName") or "")
            else ""
        ),
    }


def _assign_pin(user: dict, hotel: dict, booking: dict) -> dict:
    booking_id = str(booking.get("id") or "")
    pin = pin_from_booking_id(booking_id)
    guest = _guest_name(booking)
    existing = get_booking_by_pms_id(user["id"], booking_id)
    if existing and existing.get("status") == "active" and existing.get("parkingSpaceId"):
        return existing

    space = find_available_space(hotel["id"])
    if space is None and not hotel.get("_locksRefreshed"):
        hotel["_locksRefreshed"] = True
        try:
            sync_locks_for_hotel(hotel)
        except Exception as exc:
            logger.warning("Lock refresh before PIN assign failed: %s", exc)
        space = find_available_space(hotel["id"])
    if space is None:
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
                message=(
                    f"No free parking lock for hotel {hotel['hotelId']} booking {booking_id}. "
                    f"All imported locks already have a PIN, or no TTLock locks were found for this hotel."
                ),
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
        message=f"Assigned PIN {pin} for booking {booking_id} at hotel {hotel['hotelId']}",
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

    seen_ids = set()
    for booking in list(new_bookings) + list(modified):
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
                if existing and existing.get("status") == "active":
                    _release_pin(user, existing, "cancelled")
                    released += 1
                continue
            _assign_pin(user, hotel, booking)
            assigned += 1
        except Exception as exc:
            errors += 1
            logger.exception("Booking sync failed for %s: %s", booking_id, exc)

    departed_ids = {str(b.get("id")) for b in departed if b.get("id")}
    for row in list_active_bookings_for_owner(user["id"]):
        if row["bookingId"] in departed_ids:
            _release_pin(user, row, "departed")
            released += 1

    # Retry bookings that were waiting for a free lock (e.g. after Space delete/re-import).
    for row in list_unassigned_bookings_for_owner(user["id"]):
        if row["bookingId"] in departed_ids:
            continue
        hotel = get_hotel(row["hotelId"], include_secrets=True)
        if hotel is None:
            continue
        try:
            before = row.get("parkingSpaceId")
            saved = _assign_pin(user, hotel, _booking_payload_from_row(row))
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
