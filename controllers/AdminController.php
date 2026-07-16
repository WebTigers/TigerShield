<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_AdminController — the admin surface (settings + live traffic), in the PUMA admin shell.
 *
 * Thin by the ADMIN.md rule: it only reads + renders; every mutation is an /api call
 * (Tigershield_Service_Settings). ACL-gated to admin+ (configs/acl.ini).
 */
class Tigershield_AdminController extends Tiger_Controller_Admin_Action
{
    public function init()
    {
        parent::init();
    }

    /** Security settings: mode, CrowdSec, rate limits, login protection, WAF, captcha. */
    public function settingsAction()
    {
        $this->view->title    = 'Security — Tiger Admin';
        $this->view->settings = self::_currentConfig();
        $this->view->crowdsec = class_exists('Tigershield_Service_Crowdsec')
            ? (new Tigershield_Service_Crowdsec())->status()
            : ['enabled' => false, 'registered' => false, 'enrolled' => false, 'last_sync' => 0, 'count' => 0, 'last_error' => ''];
        $this->view->captcha = [
            'available' => class_exists('Tigershield_Service_Challenge') && (new Tigershield_Service_Challenge())->available(),
        ];
        // The same reCAPTCHA controls the core System screen offers — surfaced here for convenience,
        // saved through the shared Tiger_Recaptcha::saveSettings(). Requires a core new enough to expose
        // the shared reader/writer; on an older platform the card degrades to a status + link.
        $manageable = class_exists('Tiger_Recaptcha') && method_exists('Tiger_Recaptcha', 'settings');
        $this->view->recaptchaManageable = $manageable;
        $this->view->recaptcha = $manageable
            ? Tiger_Recaptcha::settings()
            : ['enabled' => 0, 'version' => 'v2', 'site_key' => '', 'has_secret' => false, 'min_score' => 0.5, 'fail_open' => 1, 'hide_badge' => 0];
    }

    /** Live traffic: a DataTables grid of recent shield events (rows load from Tigershield_Service_Events). */
    public function eventsAction()
    {
        $this->view->title         = 'Security — Live Traffic';
        $this->view->useDataTables = true;
    }

    /** Custom WAF rules: a DataTables grid + add/edit form (rows + writes via Tigershield_Service_Rules). */
    public function rulesAction()
    {
        $this->view->title         = 'Security — Custom Rules';
        $this->view->useDataTables = true;
        $this->view->targets       = Tigershield_Model_Rule::TARGETS;
        $this->view->matches       = Tigershield_Model_Rule::MATCHES;
        $this->view->actions       = Tigershield_Model_Rule::ACTIONS;
    }

    /** Read the live tiger.tigershield.* config for prefilling the form. */
    protected static function _currentConfig()
    {
        $out = [];
        if (Zend_Registry::isRegistered('Zend_Config')) {
            $cfg = Zend_Registry::get('Zend_Config');
            $t   = $cfg->get('tiger'); $s = $t ? $t->get('tigershield') : null;
            if ($s) { $out = $s->toArray(); }
        }
        return $out;
    }
}
