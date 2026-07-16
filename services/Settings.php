<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_Service_Settings — save the shield's settings over /api (validate → config tier).
 *
 * Writes tiger.tigershield.* to the config table (live-override, per-org capable, no deploy), exactly
 * like every other Tiger settings screen. The CrowdSec enrollment key is a SECRET — it goes to
 * local.ini via Tiger_Install::provisionSecrets-style storage, never the DB in plaintext.
 */
class Tigershield_Service_Settings extends Tiger_Service_Service
{
    /** Persist the settings form. */
    public function save(array $params): void
    {
        if (!$this->_isAdmin()) { $this->_error('core.api.error.not_allowed'); return; }

        // TODO: $form = new Tigershield_Form_Settings(); validate; then persist each key.
        // Scaffold: accept the known keys and write them to the config tier.
        try {
            $config = new Tiger_Model_Config();
            $keys = [
                'tiger.tigershield.mode',
                'tiger.tigershield.ratelimit.enabled',
                'tiger.tigershield.crowdsec.enabled',
                'tiger.tigershield.waf.enabled',
                'tiger.tigershield.waf.action',
            ];
            $this->_transaction(function () use ($config, $keys, $params) {
                foreach ($keys as $k) {
                    // global scope for now (per-org tuning is a later refinement — FEATURES.md §12).
                    if (array_key_exists($k, $params)) { $config->set('global', '', $k, (string) $params[$k]); }
                }
            });
            $this->_success([], 'tigershield.settings.saved');
        } catch (Throwable $e) {
            $this->_error(APPLICATION_ENV !== 'production' ? $e->getMessage() : 'core.api.error.general');
        }
    }
}
