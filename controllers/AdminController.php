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
            'version'   => class_exists('Tiger_Recaptcha') ? Tiger_Recaptcha::version() : 'v2',
        ];
    }

    /** Live traffic: a DataTables grid of recent shield events (rows load from Tigershield_Service_Events). */
    public function eventsAction()
    {
        $this->view->title         = 'Security — Live Traffic';
        $this->view->useDataTables = true;
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
