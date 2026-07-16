<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_Service_Rules — /api for the custom WAF rule editor. Validates + writes admin-authored
 * rules to tigershield_rule, then recompiles the gate's cache file (compileCache) so the change is live
 * next request with no DB hit on the hot path. Admin-only (configs/acl.ini).
 */
class Tigershield_Service_Rules extends Tiger_Service_Service
{
    /** DataTables grid of custom rules. */
    public function datatable(array $params): void
    {
        if (!$this->_isAdmin()) { $this->_error('core.api.error.not_allowed'); return; }
        $dt   = $this->_dtParams($params);
        $data = (new Tigershield_Model_Rule())->datatable(['search' => $dt['search'], 'offset' => $dt['start'], 'limit' => $dt['length']]);
        $rows = [];
        foreach ($data['rows'] as $r) {
            $rows[] = [
                'rule_id' => $r['rule_id'], 'label' => (string) $r['label'], 'target' => (string) $r['target'],
                'match'   => (string) $r['match_type'], 'pattern' => (string) $r['pattern'],
                'action'  => (string) $r['action'], 'enabled' => (int) $r['enabled'],
            ];
        }
        $this->_dtResponse($dt['draw'], $data['total'], $data['filtered'], $rows);
    }

    /** Create or update a rule (rule_id present = update). Validates, then recompiles the cache. */
    public function save(array $params): void
    {
        if (!$this->_isAdmin()) { $this->_error('core.api.error.not_allowed'); return; }

        $label   = trim((string) ($params['label'] ?? ''));
        $target  = (string) ($params['target'] ?? 'query');
        $match   = (string) ($params['match_type'] ?? 'contains');
        $pattern = (string) ($params['pattern'] ?? '');
        $action  = (string) ($params['action'] ?? 'log');
        $enabled = !empty($params['enabled']) ? 1 : 0;
        $order   = (int) ($params['sort_order'] ?? 100);
        $id      = trim((string) ($params['rule_id'] ?? ''));

        if ($label === '')                                        { $this->_error('tigershield.rule.err_label'); return; }
        if (trim($pattern) === '')                                { $this->_error('tigershield.rule.err_pattern'); return; }
        if (!in_array($target, Tigershield_Model_Rule::TARGETS, true)) { $this->_error('tigershield.rule.err_target'); return; }
        if (!in_array($match, Tigershield_Model_Rule::MATCHES, true))  { $match = 'contains'; }
        if (!in_array($action, Tigershield_Model_Rule::ACTIONS, true)) { $action = 'log'; }
        // A regex rule must compile (wrapped exactly as the engine will run it).
        if ($match === 'regex' && @preg_match('~' . str_replace('~', '\\~', $pattern) . '~i', '') === false) {
            $this->_error('tigershield.rule.err_regex'); return;
        }

        try {
            $model = new Tigershield_Model_Rule();
            $data  = ['label' => $label, 'target' => $target, 'match_type' => $match, 'pattern' => $pattern,
                      'action' => $action, 'enabled' => $enabled, 'sort_order' => $order];
            $this->_transaction(function () use ($model, $data, $id) {
                if ($id !== '') {
                    $model->update($data, $model->getAdapter()->quoteInto('rule_id = ?', $id));
                } else {
                    $model->insert($data);
                }
            });
            $model->compileCache();
            $this->_success([], 'tigershield.rule.saved');
        } catch (Throwable $e) {
            $this->_error(APPLICATION_ENV !== 'production' ? $e->getMessage() : 'core.api.error.general');
        }
    }

    /** Flip a single rule's enabled flag (inline switch), then recompile the cache. */
    public function toggle(array $params): void
    {
        if (!$this->_isAdmin()) { $this->_error('core.api.error.not_allowed'); return; }
        $id = trim((string) ($params['rule_id'] ?? ''));
        if ($id === '') { $this->_error('core.api.error.general'); return; }
        $enabled = !empty($params['enabled']) ? 1 : 0;
        try {
            $model = new Tigershield_Model_Rule();
            $model->update(['enabled' => $enabled], $model->getAdapter()->quoteInto('rule_id = ?', $id));
            $model->compileCache();
            $this->_success(['enabled' => $enabled], 'tigershield.rule.saved');
        } catch (Throwable $e) {
            $this->_error(APPLICATION_ENV !== 'production' ? $e->getMessage() : 'core.api.error.general');
        }
    }

    /** Soft-delete a rule, then recompile the cache. */
    public function delete(array $params): void
    {
        if (!$this->_isAdmin()) { $this->_error('core.api.error.not_allowed'); return; }
        $id = trim((string) ($params['rule_id'] ?? ''));
        if ($id === '') { $this->_error('core.api.error.general'); return; }
        try {
            $model = new Tigershield_Model_Rule();
            $model->softDelete($model->getAdapter()->quoteInto('rule_id = ?', $id));
            $model->compileCache();
            $this->_success([], 'tigershield.rule.deleted');
        } catch (Throwable $e) {
            $this->_error(APPLICATION_ENV !== 'production' ? $e->getMessage() : 'core.api.error.general');
        }
    }
}
