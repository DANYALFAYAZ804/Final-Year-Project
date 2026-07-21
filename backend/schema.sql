-- =============================================================
-- Trust-Flow — Database Schema
-- =============================================================
-- MySQL 5.7+/8.0 (works with the XAMPP MySQL used in local dev and
-- with a managed MySQL instance such as Railway in production).
--
-- This file is a hand-written, human-readable mirror of the
-- SQLAlchemy models defined in backend/app.py. The Flask app calls
-- db.create_all() itself at startup and does not read this file — it
-- is provided for: manual provisioning (phpMyAdmin / mysql CLI),
-- documentation/review, and reproducing the exact schema outside the
-- app (backups, migrations, another environment).
--
-- Design notes:
--   * Every table uses InnoDB (required for foreign keys) and
--     utf8mb4 (full Unicode, incl. emoji/international domains —
--     plain utf8 in MySQL is only a 3-byte subset and can silently
--     truncate/reject valid input).
--   * Passwords are NEVER stored in plaintext — password_hash holds a
--     werkzeug generate_password_hash() digest (scrypt by default),
--     never the raw password.
--   * "Stay logged in" sessions are NOT stored in any table here.
--     They are stateless, signed tokens (itsdangerous
--     URLSafeTimedSerializer) that embed the user_id and an issue
--     timestamp. Expiry (30 days) is enforced cryptographically on
--     verification rather than by looking up a row, so no
--     sessions table is needed or created.
-- =============================================================

CREATE DATABASE IF NOT EXISTS `trust_flow_db`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE `trust_flow_db`;

-- -------------------------------------------------------------
-- users — one row per registered account.
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `users` (
    `user_id`       INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    `full_name`     VARCHAR(100)    NOT NULL,
    `email`         VARCHAR(150)    NOT NULL,
    `password_hash` VARCHAR(255)    NOT NULL COMMENT 'werkzeug password hash — never plaintext',
    `last_login_at` DATETIME        NULL,
    `created_at`    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `is_active`     TINYINT(1)      NOT NULL DEFAULT 1 COMMENT '0 = deactivated/soft-disabled account',
    PRIMARY KEY (`user_id`),
    UNIQUE KEY `uq_users_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -------------------------------------------------------------
-- login_history — audit trail of every login attempt, success or
-- failure, against an existing account (unknown-email attempts have
-- no user_id to attach to and are not logged here).
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `login_history` (
    `login_id`      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`       INT UNSIGNED    NOT NULL,
    `ip_address`    VARCHAR(45)     NULL COMMENT '45 chars fits a full IPv6 address',
    `login_status`  VARCHAR(10)     NOT NULL COMMENT "'success' or 'failed'",
    `logged_in_at`  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`login_id`),
    KEY `ix_login_history_user_id` (`user_id`),
    KEY `ix_login_history_logged_in_at` (`logged_in_at`),
    CONSTRAINT `fk_login_history_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- -------------------------------------------------------------
-- user_scans — every URL a logged-in user has had scanned by the
-- trust-score engine (ML + WHOIS + VirusTotal), and the resulting
-- verdict. Written by POST /scan-url once Electron's local scoring
-- has already produced a result — this table stores that result, it
-- does not recompute it.
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `user_scans` (
    `scan_id`      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`      INT UNSIGNED    NOT NULL,
    `scanned_url`  TEXT            NOT NULL,
    `domain`       VARCHAR(255)    NOT NULL,
    `verdict`      VARCHAR(50)     NOT NULL COMMENT "'safe' | 'suspicious' | 'malicious' | 'phishing'",
    `threat_score` DECIMAL(5,2)    NOT NULL DEFAULT 0.00 COMMENT '0.00-100.00',
    `scanned_at`   DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`scan_id`),
    KEY `ix_user_scans_user_id` (`user_id`),
    KEY `ix_user_scans_domain` (`domain`),
    KEY `ix_user_scans_scanned_at` (`scanned_at`),
    CONSTRAINT `fk_user_scans_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
