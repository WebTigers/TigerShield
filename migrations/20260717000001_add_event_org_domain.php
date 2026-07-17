<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Add `domain` + `org_id` to `tigershield_event`. A security event belongs to the SITE it hit — the
 * request host, and the org that owns that site (Tiger_Model_Org::siteOrgId()) — so that on a multi-site
 * install the Live Traffic log can be filtered per tenant/domain. `''` on both until populated / on a
 * platform old enough to lack the site-org resolver. Timestamp version (shared bare-version ledger).
 */
return [
    'up' => [
        "ALTER TABLE `tigershield_event`
            ADD COLUMN `domain` VARCHAR(191) NOT NULL DEFAULT '' AFTER `route`,
            ADD COLUMN `org_id` VARCHAR(36)  NOT NULL DEFAULT '' AFTER `domain`,
            ADD KEY `ix_ts_event_org`    (`org_id`),
            ADD KEY `ix_ts_event_domain` (`domain`)",
    ],
    'down' => [
        "ALTER TABLE `tigershield_event` DROP COLUMN `domain`, DROP COLUMN `org_id`",
    ],
];
