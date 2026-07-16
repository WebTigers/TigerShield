<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_Model_Event — the shield's event log (one row per blocked / flagged / captcha /
 * allow-logged request). Powers the live-traffic view and the dashboard widget. Extends
 * Tiger_Model_Table (UUID PK + timestamps + soft-delete + standard columns).
 */
class Tigershield_Model_Event extends Tiger_Model_Table
{
    protected $_name    = 'tigershield_event';
    protected $_primary = 'event_id';

    /**
     * Record a shield event. Kept dependency-light + guarded by the caller so logging can never break
     * the gate (FEATURES.md §11).
     *
     * @param  array $data ip, action, reason, route, ua, country?
     * @return string the new event_id
     */
    public function record(array $data)
    {
        return $this->insert([
            'ip'      => (string) ($data['ip'] ?? ''),
            'country' => (string) ($data['country'] ?? ''),
            'action'  => (string) ($data['action'] ?? ''),
            'reason'  => (string) ($data['reason'] ?? ''),
            'route'   => substr((string) ($data['route'] ?? ''), 0, 191),
            'ua'      => substr((string) ($data['ua'] ?? ''), 0, 255),
        ]);
    }
}
