<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_Service_Events — the live-traffic feed over /api. Server-side DataTables over the event
 * log (time, IP, country, action, reason, route). Admin-only (configs/acl.ini).
 */
class Tigershield_Service_Events extends Tiger_Service_Service
{
    /** DataTables server-side grid of recent shield events (live traffic). */
    public function datatable(array $params): void
    {
        if (!$this->_isAdmin()) { $this->_error('core.api.error.not_allowed'); return; }

        $dt      = $this->_dtParams($params);
        $actions = ['observed', 'block', 'captcha', 'captcha_pass', 'allow'];
        $data = (new Tigershield_Model_Event())->datatable([
            'search'   => $dt['search'],
            'action'   => in_array(($params['event_action'] ?? ''), $actions, true) ? (string) $params['event_action'] : '',
            'orderCol' => isset($dt['order'][0]) ? $dt['order'][0]['column'] : -1,
            'orderDir' => isset($dt['order'][0]) ? $dt['order'][0]['dir'] : '',
            'offset'   => $dt['start'],
            'limit'    => $dt['length'],
        ]);

        $rows = [];
        foreach ($data['rows'] as $r) {
            $rows[] = [
                'time'    => substr((string) $r['created_at'], 0, 16),
                'ip'      => (string) $r['ip'],
                'country' => (string) $r['country'],
                'action'  => (string) $r['action'],
                'reason'  => (string) $r['reason'],
                'route'   => (string) $r['route'],
            ];
        }

        $this->_dtResponse($dt['draw'], $data['total'], $data['filtered'], $rows);
    }
}
