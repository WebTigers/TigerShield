<?php
// SPDX-License-Identifier: BSD-3-Clause
// TigerShield 0001 — the event log (blocked / flagged / captcha / allow-logged requests).
// Additive-only, one logical DDL change (AGENTS.md). The rule + decision-cache tables land in their
// build phases (FEATURES.md §10, §15).
return [
    'up' => [
        "CREATE TABLE IF NOT EXISTS `tigershield_event` (
            `event_id`   CHAR(36)     NOT NULL,
            `ip`         VARCHAR(45)  NOT NULL DEFAULT '',
            `country`    VARCHAR(2)   NOT NULL DEFAULT '',
            `action`     VARCHAR(20)  NOT NULL DEFAULT '',
            `reason`     VARCHAR(191) NOT NULL DEFAULT '',
            `route`      VARCHAR(191) NOT NULL DEFAULT '',
            `ua`         VARCHAR(255) NOT NULL DEFAULT '',
            `status`     VARCHAR(20)  NOT NULL DEFAULT 'active',
            `deleted`    TINYINT(1)   NOT NULL DEFAULT 0,
            `created_by` CHAR(36)     NULL,
            `updated_by` CHAR(36)     NULL,
            `created_at` DATETIME     NULL,
            `updated_at` DATETIME     NULL,
            PRIMARY KEY (`event_id`),
            KEY `ix_ts_event_ip`      (`ip`),
            KEY `ix_ts_event_action`  (`action`),
            KEY `ix_ts_event_created` (`created_at`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    ],
    'down' => [
        "DROP TABLE IF EXISTS `tigershield_event`",
    ],
];
