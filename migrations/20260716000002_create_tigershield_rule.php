<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Create `tigershield_rule` — admin-authored custom WAF rules (§10). Supplements the shipped, curated
 * ruleset (rules/default-waf.php): an operator adds their own signature over a chosen request surface.
 *
 * TIMESTAMP version (not 0001) — the tiger_migration ledger is one bare-version namespace across core +
 * app + all modules, so a low sequence would collide (see the module-migration gotcha). Standard Tiger
 * columns; `Tigershield_Model_Rule` declares $_primary = 'rule_id'.
 */
return [
    'up' => [
        "CREATE TABLE `tigershield_rule` (
            `rule_id`    CHAR(36)     NOT NULL,
            `label`      VARCHAR(191) NOT NULL,
            `target`     VARCHAR(16)  NOT NULL DEFAULT 'query',    -- path|query|pathquery|ua|method|body
            `match_type` VARCHAR(16)  NOT NULL DEFAULT 'contains', -- contains|regex
            `pattern`    VARCHAR(500) NOT NULL,
            `action`     VARCHAR(16)  NOT NULL DEFAULT 'log',      -- log|captcha|block
            `enabled`    TINYINT(1)   NOT NULL DEFAULT 1,
            `sort_order` INT          NOT NULL DEFAULT 100,
            `status`     VARCHAR(32)  NOT NULL DEFAULT 'active',
            `deleted`    TINYINT(1)   NOT NULL DEFAULT 0,
            `created_by` CHAR(36)         NULL,
            `updated_by` CHAR(36)         NULL,
            `created_at` DATETIME     NOT NULL,
            `updated_at` DATETIME         NULL,
            PRIMARY KEY (`rule_id`),
            KEY `ix_rule_active` (`deleted`, `enabled`, `sort_order`)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",
    ],
    'down' => [
        "DROP TABLE IF EXISTS `tigershield_rule`",
    ],
];
