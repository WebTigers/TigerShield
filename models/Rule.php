<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_Model_Rule — admin-authored custom WAF rules (the store behind the rule editor).
 *
 * The DB is the source of truth; the gate never queries it. On every write the ENABLED rules are
 * compiled to a small cache file (compileCache) that Tigershield_Service_Waf reads on the hot path —
 * same "no I/O in the gate" discipline as the CrowdSec blocklist. Extends Tiger_Model_Table.
 */
class Tigershield_Model_Rule extends Tiger_Model_Table
{
    protected $_name    = 'tigershield_rule';
    protected $_primary = 'rule_id';

    const TARGETS = ['path', 'query', 'pathquery', 'ua', 'method', 'body'];
    const MATCHES = ['contains', 'regex'];
    const ACTIONS = ['log', 'captcha', 'block'];

    /** The compiled-cache file the WAF engine reads (under the module's writable runtime dir). */
    public static function cacheFile()
    {
        return Tigershield_Service_Blocklist::dir() . '/waf-custom.json';
    }

    /** Active (enabled, non-deleted) rules, ordered. */
    public function active()
    {
        return $this->fetchAll(
            $this->activeSelect()->where('enabled = ?', 1)->order(['sort_order ASC', 'created_at ASC'])
        );
    }

    /**
     * Compile the active rules to the cache file the gate reads. Called on every write. Atomic; fail-soft.
     *
     * @return int the number of rules written
     */
    public function compileCache()
    {
        $out = [];
        foreach ($this->active() as $r) {
            $out[] = [
                'label'   => (string) $r->label,
                'target'  => (string) $r->target,
                'match'   => (string) $r->match_type,
                'pattern' => (string) $r->pattern,
                'action'  => (string) $r->action,
            ];
        }
        $file = self::cacheFile();
        $tmp  = $file . '.' . getmypid() . '.tmp';
        if (@file_put_contents($tmp, json_encode($out), LOCK_EX) !== false && @rename($tmp, $file)) {
            @chmod($file, 0664);
        }
        return count($out);
    }

    /**
     * Server-side DataTables query for the rule editor grid.
     *
     * @param  array $o search, offset, limit
     * @return array{rows:array, total:int, filtered:int}
     */
    public function datatable(array $o)
    {
        $db     = $this->getAdapter();
        $search = trim((string) ($o['search'] ?? ''));

        $total = (int) $db->fetchOne($db->select()->from($this->_name, [new Zend_Db_Expr('COUNT(*)')])->where('deleted = ?', 0));

        $sel = $db->select()->from($this->_name, ['rule_id', 'label', 'target', 'match_type', 'pattern', 'action', 'enabled'])
            ->where('deleted = ?', 0);
        if ($search !== '') {
            $like = '%' . $search . '%';
            $sel->where($db->quoteInto('label LIKE ?', $like) . ' OR ' . $db->quoteInto('pattern LIKE ?', $like));
        }
        $filtered = (int) $db->fetchOne(
            $db->select()->from(['t' => new Zend_Db_Expr('(' . $sel->assemble() . ')')], [new Zend_Db_Expr('COUNT(*)')])
        );
        $sel->order(['sort_order ASC', 'created_at ASC'])->limit((int) ($o['limit'] ?? 25), (int) ($o['offset'] ?? 0));

        return ['rows' => $db->fetchAll($sel), 'total' => $total, 'filtered' => $filtered];
    }
}
