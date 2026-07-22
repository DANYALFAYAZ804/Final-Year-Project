CREATE TABLE IF NOT EXISTS `users` (
    `user_id`       INT             NOT NULL AUTO_INCREMENT,
    `full_name`     VARCHAR(100)    NOT NULL,
    `email`         VARCHAR(150)    NOT NULL,
    `password_hash` VARCHAR(255)    NOT NULL,
    `last_login_at` DATETIME        NULL,
    `created_at`    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `is_active`     TINYINT(1)      NOT NULL DEFAULT 1,
    PRIMARY KEY (`user_id`),
    UNIQUE KEY `uq_users_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `login_history` (
    `login_id`      BIGINT          NOT NULL AUTO_INCREMENT,
    `user_id`       INT             NOT NULL,
    `ip_address`    VARCHAR(45)     NULL,
    `login_status`  VARCHAR(10)     NOT NULL,
    `logged_in_at`  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`login_id`),
    KEY `ix_login_history_user_id` (`user_id`),
    KEY `ix_login_history_logged_in_at` (`logged_in_at`),
    CONSTRAINT `fk_login_history_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`user_id`)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `user_scans` (
    `scan_id`      BIGINT          NOT NULL AUTO_INCREMENT,
    `user_id`      INT             NOT NULL,
    `scanned_url`  TEXT            NOT NULL,
    `domain`       VARCHAR(255)    NOT NULL,
    `verdict`      VARCHAR(50)     NOT NULL,
    `threat_score` DECIMAL(5,2)    NOT NULL DEFAULT 0.00,
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