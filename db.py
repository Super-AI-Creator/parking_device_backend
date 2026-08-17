"""MySQL connection helpers for ParkAccess."""

from __future__ import annotations

import re
import ssl
from contextlib import contextmanager

import pymysql
from pymysql.cursors import DictCursor
from pymysql.err import IntegrityError

import config

_DB_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")


def _require_mysql_settings() -> None:
    if not config.MYSQL_USER:
        raise RuntimeError("MYSQL_USER is missing from backend/.env")
    if not _DB_NAME_RE.match(config.MYSQL_DATABASE):
        raise RuntimeError("MYSQL_DATABASE must be letters, numbers, or underscore only")


def _connect(*, with_database: bool = True):
    _require_mysql_settings()
    kwargs = {
        "host": config.MYSQL_HOST,
        "port": config.MYSQL_PORT,
        "user": config.MYSQL_USER,
        "password": config.MYSQL_PASSWORD,
        "charset": "utf8mb4",
        "cursorclass": DictCursor,
        "autocommit": False,
    }
    if config.MYSQL_SSL:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs["ssl"] = ctx
    if with_database:
        kwargs["database"] = config.MYSQL_DATABASE
    return pymysql.connect(**kwargs)


@contextmanager
def get_connection():
    conn = _connect(with_database=True)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def ensure_database() -> None:
    conn = _connect(with_database=False)
    try:
        with conn.cursor() as cur:
            cur.execute(
                f"CREATE DATABASE IF NOT EXISTS `{config.MYSQL_DATABASE}` "
                "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
            )
        conn.commit()
    finally:
        conn.close()


SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS users (
      id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      username             VARCHAR(64)  NOT NULL,
      password_hash        VARCHAR(255) NOT NULL,
      role                 VARCHAR(32)  NOT NULL,
      status               VARCHAR(32)  NOT NULL DEFAULT 'pending',
      display_name         VARCHAR(120) NOT NULL DEFAULT '',
      email                VARCHAR(190) NOT NULL DEFAULT '',
      company_name         VARCHAR(190) NOT NULL DEFAULT '',
      ttlock_username      VARCHAR(190) NOT NULL DEFAULT '',
      ttlock_password_enc  TEXT         NOT NULL,
      pms_token            VARCHAR(512) NOT NULL DEFAULT '',
      pms_refresh_token    VARCHAR(512) NOT NULL DEFAULT '',
      pms_token_refreshed_at DATETIME(0) NULL,
      created_at           DATETIME(0)  NOT NULL,
      updated_at           DATETIME(0)  NOT NULL,
      approved_at          DATETIME(0)  NULL,
      approved_by          BIGINT UNSIGNED NULL,
      PRIMARY KEY (id),
      UNIQUE KEY uq_users_username (username),
      KEY idx_users_role_status (role, status),
      KEY idx_users_approved_by (approved_by),
      CONSTRAINT fk_users_approved_by
        FOREIGN KEY (approved_by) REFERENCES users (id)
        ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS hotels (
      id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      owner_id             BIGINT UNSIGNED NOT NULL,
      hotel_id             VARCHAR(64)  NOT NULL,
      name                 VARCHAR(190) NOT NULL DEFAULT '',
      check_in_start       VARCHAR(16)  NOT NULL DEFAULT '14:00',
      check_out_end        VARCHAR(16)  NOT NULL DEFAULT '10:00',
      ttlock_username      VARCHAR(190) NOT NULL DEFAULT '',
      ttlock_password_enc  TEXT         NOT NULL,
      created_at           DATETIME(0)  NOT NULL,
      updated_at           DATETIME(0)  NOT NULL,
      PRIMARY KEY (id),
      UNIQUE KEY uq_hotels_owner_hotel (owner_id, hotel_id),
      KEY idx_hotels_hotel_id (hotel_id),
      CONSTRAINT fk_hotels_owner
        FOREIGN KEY (owner_id) REFERENCES users (id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS parking_spaces (
      id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      owner_id         BIGINT UNSIGNED NULL,
      hotel_id         BIGINT UNSIGNED NULL,
      name             VARCHAR(120) NOT NULL,
      lock_id          VARCHAR(64)  NOT NULL,
      pin              VARCHAR(32)  NULL,
      booking_id       VARCHAR(64)  NULL,
      keyboard_pwd_id  VARCHAR(64)  NULL,
      enabled          TINYINT(1)   NOT NULL DEFAULT 1,
      notes            VARCHAR(500) NOT NULL DEFAULT '',
      created_at       DATETIME(0)  NOT NULL,
      updated_at       DATETIME(0)  NOT NULL,
      PRIMARY KEY (id),
      UNIQUE KEY uq_parking_spaces_hotel_pin (hotel_id, pin),
      UNIQUE KEY uq_parking_spaces_owner_lock (owner_id, lock_id),
      KEY idx_parking_spaces_owner (owner_id),
      KEY idx_parking_spaces_hotel (hotel_id),
      KEY idx_parking_spaces_booking (booking_id),
      CONSTRAINT fk_parking_spaces_owner
        FOREIGN KEY (owner_id) REFERENCES users (id)
        ON DELETE CASCADE,
      CONSTRAINT fk_parking_spaces_hotel
        FOREIGN KEY (hotel_id) REFERENCES hotels (id)
        ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS api_logs (
      id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      owner_id             BIGINT UNSIGNED NULL,
      actor_user_id        BIGINT UNSIGNED NULL,
      action               VARCHAR(64)  NOT NULL,
      parking_space_id     BIGINT UNSIGNED NULL,
      parking_space_name   VARCHAR(120) NULL,
      lock_id              VARCHAR(64)  NULL,
      pin                  VARCHAR(32)  NULL,
      success              TINYINT(1)   NOT NULL DEFAULT 0,
      message              VARCHAR(500) NULL,
      request_payload      JSON         NULL,
      response_payload     JSON         NULL,
      created_at           DATETIME(0)  NOT NULL,
      PRIMARY KEY (id),
      KEY idx_api_logs_owner_created (owner_id, created_at),
      KEY idx_api_logs_action_created (action, created_at),
      KEY idx_api_logs_space (parking_space_id),
      KEY idx_api_logs_actor (actor_user_id),
      CONSTRAINT fk_api_logs_owner
        FOREIGN KEY (owner_id) REFERENCES users (id)
        ON DELETE SET NULL,
      CONSTRAINT fk_api_logs_actor
        FOREIGN KEY (actor_user_id) REFERENCES users (id)
        ON DELETE SET NULL,
      CONSTRAINT fk_api_logs_space
        FOREIGN KEY (parking_space_id) REFERENCES parking_spaces (id)
        ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
    """
    CREATE TABLE IF NOT EXISTS bookings (
      id                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      owner_id           BIGINT UNSIGNED NOT NULL,
      hotel_id           BIGINT UNSIGNED NOT NULL,
      booking_id         VARCHAR(64)  NOT NULL,
      guest_name         VARCHAR(190) NOT NULL DEFAULT '',
      arrival            VARCHAR(32)  NULL,
      departure          VARCHAR(32)  NULL,
      status             VARCHAR(32)  NOT NULL DEFAULT 'active',
      pin                VARCHAR(32)  NULL,
      parking_space_id   BIGINT UNSIGNED NULL,
      keyboard_pwd_id    VARCHAR(64)  NULL,
      raw_payload        JSON         NULL,
      created_at         DATETIME(0)  NOT NULL,
      updated_at         DATETIME(0)  NOT NULL,
      PRIMARY KEY (id),
      UNIQUE KEY uq_bookings_owner_booking (owner_id, booking_id),
      KEY idx_bookings_hotel (hotel_id),
      KEY idx_bookings_status (status),
      CONSTRAINT fk_bookings_owner
        FOREIGN KEY (owner_id) REFERENCES users (id)
        ON DELETE CASCADE,
      CONSTRAINT fk_bookings_hotel
        FOREIGN KEY (hotel_id) REFERENCES hotels (id)
        ON DELETE CASCADE,
      CONSTRAINT fk_bookings_space
        FOREIGN KEY (parking_space_id) REFERENCES parking_spaces (id)
        ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """,
]


def _column_exists(cur, table: str, column: str) -> bool:
    cur.execute(
        """
        SELECT COUNT(*) AS c FROM information_schema.COLUMNS
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s
        """,
        (config.MYSQL_DATABASE, table, column),
    )
    return int(cur.fetchone()["c"]) > 0


def _index_exists(cur, table: str, index: str) -> bool:
    cur.execute(
        """
        SELECT COUNT(*) AS c FROM information_schema.STATISTICS
        WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND INDEX_NAME = %s
        """,
        (config.MYSQL_DATABASE, table, index),
    )
    return int(cur.fetchone()["c"]) > 0


def migrate_schema() -> None:
    """Add PMS/hotel columns on existing databases."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            if not _column_exists(cur, "users", "pms_token"):
                cur.execute("ALTER TABLE users ADD COLUMN pms_token VARCHAR(512) NOT NULL DEFAULT ''")
            if not _column_exists(cur, "users", "pms_refresh_token"):
                cur.execute("ALTER TABLE users ADD COLUMN pms_refresh_token VARCHAR(512) NOT NULL DEFAULT ''")
            if not _column_exists(cur, "users", "pms_token_refreshed_at"):
                cur.execute("ALTER TABLE users ADD COLUMN pms_token_refreshed_at DATETIME(0) NULL")

            if not _column_exists(cur, "parking_spaces", "hotel_id"):
                cur.execute("ALTER TABLE parking_spaces ADD COLUMN hotel_id BIGINT UNSIGNED NULL")
            if not _column_exists(cur, "parking_spaces", "booking_id"):
                cur.execute("ALTER TABLE parking_spaces ADD COLUMN booking_id VARCHAR(64) NULL")
            if not _column_exists(cur, "parking_spaces", "keyboard_pwd_id"):
                cur.execute("ALTER TABLE parking_spaces ADD COLUMN keyboard_pwd_id VARCHAR(64) NULL")

            try:
                cur.execute("ALTER TABLE parking_spaces MODIFY pin VARCHAR(32) NULL")
                cur.execute("UPDATE parking_spaces SET pin = NULL WHERE pin = ''")
            except Exception:
                pass

            if _index_exists(cur, "parking_spaces", "uq_parking_spaces_pin"):
                try:
                    cur.execute("ALTER TABLE parking_spaces DROP INDEX uq_parking_spaces_pin")
                except Exception:
                    pass
            if not _index_exists(cur, "parking_spaces", "uq_parking_spaces_hotel_pin"):
                try:
                    cur.execute(
                        "ALTER TABLE parking_spaces ADD UNIQUE KEY uq_parking_spaces_hotel_pin (hotel_id, pin)"
                    )
                except Exception:
                    pass
