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

    /** The columns the live-traffic grid can order by, in DataTables column order. */
    private static $_orderCols = ['created_at', 'ip', 'country', 'action', 'reason', 'route'];

    /**
     * The top offending IPs by event count over a window — the dashboard "who the shield is stopping"
     * signal. Counts all flagged events (in learn mode these are `observed`).
     *
     * @param  int $sinceSeconds look-back window (default 7 days)
     * @param  int $limit        max rows
     * @return array<int,array{ip:string, hits:int}>
     */
    public function topIps($sinceSeconds = 604800, $limit = 10)
    {
        $db    = $this->getAdapter();
        $since = date('Y-m-d H:i:s', time() - max(60, (int) $sinceSeconds));
        $rows  = $db->fetchAll(
            $db->select()
                ->from($this->_name, ['ip', 'hits' => new Zend_Db_Expr('COUNT(*)')])
                ->where('deleted = ?', 0)
                ->where('created_at >= ?', $since)
                ->where("ip <> ''")
                ->group('ip')
                ->order(new Zend_Db_Expr('COUNT(*) DESC'))
                ->limit(max(1, (int) $limit))
        );
        return array_map(function ($r) {
            return ['ip' => (string) $r['ip'], 'hits' => (int) $r['hits']];
        }, $rows);
    }

    /** Total flagged events since a timestamp (optionally only enforce-worthy actions). */
    public function countSince($sinceSeconds, array $actions = [])
    {
        $db    = $this->getAdapter();
        $since = date('Y-m-d H:i:s', time() - max(60, (int) $sinceSeconds));
        $sel   = $db->select()->from($this->_name, [new Zend_Db_Expr('COUNT(*)')])
            ->where('deleted = ?', 0)->where('created_at >= ?', $since);
        if ($actions) { $sel->where('action IN (?)', $actions); }
        return (int) $db->fetchOne($sel);
    }

    /**
     * Server-side DataTables query for the live-traffic view. Returns ['rows','total','filtered'].
     * Injection-safe (query builder + quoteInto); newest first by default.
     *
     * @param  array $o search, action (filter), orderCol, orderDir, offset, limit
     * @return array{rows:array, total:int, filtered:int}
     */
    public function datatable(array $o)
    {
        $db     = $this->getAdapter();
        $table  = $this->_name;
        $search = trim((string) ($o['search'] ?? ''));
        $action = (string) ($o['action'] ?? '');

        // A fresh, deleted-excluding select with the given columns.
        $base = function ($cols) use ($db, $table) {
            return $db->select()->from($table, $cols)->where('deleted = ?', 0);
        };
        // Apply the search box across the visible columns (injection-safe via quoteInto).
        $applySearch = function ($sel) use ($db, $search) {
            if ($search !== '') {
                $like = '%' . $search . '%';
                $sel->where(
                    $db->quoteInto('ip LIKE ?', $like) . ' OR ' . $db->quoteInto('country LIKE ?', $like) . ' OR '
                    . $db->quoteInto('action LIKE ?', $like) . ' OR ' . $db->quoteInto('reason LIKE ?', $like) . ' OR '
                    . $db->quoteInto('route LIKE ?', $like)
                );
            }
            return $sel;
        };

        // Total = the working set defined by the toolbar (action) filter, before the search box.
        $totalSel = $base([new Zend_Db_Expr('COUNT(*)')]);
        if ($action !== '') { $totalSel->where('action = ?', $action); }
        $total = (int) $db->fetchOne($totalSel);

        // Filtered = the working set narrowed by the search box.
        $filteredSel = $base([new Zend_Db_Expr('COUNT(*)')]);
        if ($action !== '') { $filteredSel->where('action = ?', $action); }
        $applySearch($filteredSel);
        $filtered = (int) $db->fetchOne($filteredSel);

        // The page of rows.
        $oi  = (int) ($o['orderCol'] ?? -1);
        $dir = strtolower((string) ($o['orderDir'] ?? 'desc')) === 'asc' ? 'ASC' : 'DESC';
        $col = ($oi >= 0 && isset(self::$_orderCols[$oi])) ? self::$_orderCols[$oi] : 'created_at';

        $rowsSel = $base(['event_id', 'ip', 'country', 'action', 'reason', 'route', 'created_at']);
        if ($action !== '') { $rowsSel->where('action = ?', $action); }
        $applySearch($rowsSel);
        $rowsSel->order($col . ' ' . $dir)->limit((int) ($o['limit'] ?? 25), (int) ($o['offset'] ?? 0));

        return ['rows' => $db->fetchAll($rowsSel), 'total' => $total, 'filtered' => $filtered];
    }
}
