-- ParkAccess MySQL schema
-- Compatible with MySQL 8.0+ / MariaDB 10.5+
-- Charset: utf8mb4

CREATE DATABASE IF NOT EXISTS parkaccess
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE parkaccess;

-- ---------------------------------------------------------------------------
-- users
-- roles: admin | manager | customer
-- status: pending | approved | rejected | disabled
-- ---------------------------------------------------------------------------
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- hotels (Beds24 properties, one TTLock account per hotel)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hotels (
  id                   BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  owner_id             BIGINT UNSIGNED NOT NULL,
  hotel_id             VARCHAR(64)  NOT NULL,
  name                 VARCHAR(190) NOT NULL DEFAULT '',
  check_in_start       VARCHAR(16)  NOT NULL DEFAULT '14:00',
  check_out_end        VARCHAR(16)  NOT NULL DEFAULT '10:00',
      ttlock_username      VARCHAR(190) NOT NULL DEFAULT '',
      ttlock_password_enc  TEXT         NOT NULL,
      pin_assign_mode      VARCHAR(16)  NOT NULL DEFAULT 'random',
      created_at           DATETIME(0)  NOT NULL,
  updated_at           DATETIME(0)  NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_hotels_owner_hotel (owner_id, hotel_id),
  KEY idx_hotels_hotel_id (hotel_id),
  CONSTRAINT fk_hotels_owner
    FOREIGN KEY (owner_id) REFERENCES users (id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- parking_spaces
-- PIN is unique per hotel (customer keypad uses hotel ID + PIN)
-- lock_id is unique per owner (manager)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS parking_spaces (
  id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  owner_id         BIGINT UNSIGNED NULL,
  hotel_id         BIGINT UNSIGNED NULL,
  name             VARCHAR(120) NOT NULL,
  lock_id          VARCHAR(64)  NOT NULL,
  pin              VARCHAR(32)  NULL,
  -- Unique only when a PIN is set; multiple free (NULL) locks per hotel are allowed.
  pin_slot         VARCHAR(96)
                   GENERATED ALWAYS AS (
                     CASE
                       WHEN pin IS NULL OR pin = '' THEN NULL
                       ELSE CONCAT(IFNULL(hotel_id, 0), ':', pin)
                     END
                   ) STORED,
  booking_id       VARCHAR(64)  NULL,
  keyboard_pwd_id  VARCHAR(64)  NULL,
  enabled          TINYINT(1)   NOT NULL DEFAULT 1,
  notes            VARCHAR(500) NOT NULL DEFAULT '',
  created_at       DATETIME(0)  NOT NULL,
  updated_at       DATETIME(0)  NOT NULL,

  PRIMARY KEY (id),
  UNIQUE KEY uq_parking_spaces_owner_lock (owner_id, lock_id),
  UNIQUE KEY uq_parking_spaces_pin_slot (pin_slot),
  KEY idx_parking_spaces_owner (owner_id),
  KEY idx_parking_spaces_hotel (hotel_id),
  KEY idx_parking_spaces_booking (booking_id),

  CONSTRAINT fk_parking_spaces_owner
    FOREIGN KEY (owner_id) REFERENCES users (id)
    ON DELETE CASCADE,
  CONSTRAINT fk_parking_spaces_hotel
    FOREIGN KEY (hotel_id) REFERENCES hotels (id)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- bookings (Beds24 reservations mapped to parking PINs)
-- ---------------------------------------------------------------------------
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- api_logs
-- ---------------------------------------------------------------------------
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- Default platform admin
-- username: admin
-- password: admin123
-- ---------------------------------------------------------------------------
INSERT INTO users (
  username, password_hash, role, status, display_name,
  email, company_name, ttlock_username, ttlock_password_enc,
  created_at, updated_at, approved_at
) VALUES (
  'admin',
  'scrypt:32768:8:1$dooLg0Ue3F0B9JA1$a5986f96d265d15abbb4608df3be046d6496174262a73e8000de3de16fd39adfada3d7aa69780a5153d0c35fc57fcfe279e7a849e54a622b036e61b9b03cad1f',
  'admin',
  'approved',
  'Platform Admin',
  '',
  '',
  '',
  '',
  UTC_TIMESTAMP(),
  UTC_TIMESTAMP(),
  UTC_TIMESTAMP()
)
ON DUPLICATE KEY UPDATE
  password_hash = VALUES(password_hash),
  role = 'admin',
  status = 'approved',
  updated_at = UTC_TIMESTAMP();
