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
                'tiger.tigershield.crowdsec.contribute',
                'tiger.tigershield.captcha.fallback',
                'tiger.tigershield.waf.enabled',
                'tiger.tigershield.waf.action',
                'tiger.tigershield.waf.cat.files',
                'tiger.tigershield.waf.cat.cms',
                'tiger.tigershield.waf.cat.traversal',
                'tiger.tigershield.waf.cat.rce',
                'tiger.tigershield.waf.cat.nullbyte',
                'tiger.tigershield.waf.cat.method',
                'tiger.tigershield.waf.cat.scanners',
                'tiger.tigershield.waf.cat.sqli',
                'tiger.tigershield.waf.cat.xss',
            ];
            $this->_transaction(function () use ($config, $keys, $params) {
                foreach ($keys as $k) {
                    // global scope for now (per-org tuning is a later refinement — FEATURES.md §12).
                    if (array_key_exists($k, $params)) { $config->set('global', '', $k, (string) $params[$k]); }
                }
            });

            // reCAPTCHA controls (shared with the core System settings screen) — same shared writer, so
            // the two screens stay in lockstep. Only touched when the captcha card submitted its fields.
            if (class_exists('Tiger_Recaptcha') && method_exists('Tiger_Recaptcha', 'saveSettings') && array_key_exists('recaptcha_enabled', $params)) {
                Tiger_Recaptcha::saveSettings([
                    'enabled'    => !empty($params['recaptcha_enabled']) ? 1 : 0,
                    'version'    => $params['recaptcha_version'] ?? 'v2',
                    'site_key'   => $params['recaptcha_site_key'] ?? '',
                    'secret_key' => $params['recaptcha_secret_key'] ?? '',
                    'min_score'  => ($params['recaptcha_min_score'] ?? '') === '' ? 0.5 : $params['recaptcha_min_score'],
                    'fail_open'  => !empty($params['recaptcha_fail_open']) ? 1 : 0,
                    'hide_badge' => !empty($params['recaptcha_hide_badge']) ? 1 : 0,
                ]);
            }

            // If the operator supplied a CrowdSec enrollment (attachment) key, enroll now — OUTSIDE the
            // transaction (it makes a network call). Fail-soft: a failed enroll never fails the save.
            $msg = 'tigershield.settings.saved';
            $enrollKey = trim((string) ($params['crowdsec_enroll_key'] ?? ''));
            if ($enrollKey !== '' && (string) ($params['tiger.tigershield.crowdsec.enabled'] ?? '') === '1'
                && class_exists('Tigershield_Service_Crowdsec')) {
                $res = (new Tigershield_Service_Crowdsec())->enroll($enrollKey);
                $msg = $res['ok'] ? 'tigershield.crowdsec.enrolled' : 'tigershield.crowdsec.enroll_failed';
            }
            $this->_success([], $msg);
        } catch (Throwable $e) {
            $this->_error(APPLICATION_ENV !== 'production' ? $e->getMessage() : 'core.api.error.general');
        }
    }
}
