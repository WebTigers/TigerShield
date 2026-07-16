<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_Service_Events — the live-traffic feed over /api. Server-side DataTables over the event
 * log (time, IP, country, action, reason, route). Admin-only (configs/acl.ini).
 */
class Tigershield_Service_Events extends Tiger_Service_Service
{
    /** DataTables server-side grid of recent shield events. */
    public function datatable(array $params): void
    {
        if (!$this->_isAdmin()) { $this->_error('core.api.error.not_allowed'); return; }

        // TODO(phase 1): query tigershield_event with _dtParams()/_dtResponse() (WEBSERVICES.md §5),
        // each row carrying can_allowlist/can_block flags. Scaffold returns an empty grid.
        $dt = $this->_dtParams($params);
        $this->_dtResponse($dt['draw'] ?? 0, 0, 0, []);
    }
}
