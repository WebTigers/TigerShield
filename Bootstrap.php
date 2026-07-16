<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * TigerShield module bootstrap.
 *
 * Registers the front-controller **firewall gate** (Tigershield_Plugin_Firewall) — which runs BEFORE
 * dispatch on every request and is **fail-open** (a bug or a data-outage never blocks/500s the site) —
 * and contributes the module's Security screen to the admin Settings tree.
 *
 * Extending Zend_Application_Module_Bootstrap gives the module its resource autoloader, so
 * Tigershield_Service_* (services/), Tigershield_Model_* (models/), and Tigershield_Plugin_*
 * (plugins/) load by convention; configs/acl.ini + languages/ are picked up by the core globs.
 */
class Tigershield_Bootstrap extends Zend_Application_Module_Bootstrap
{
    /**
     * Register the firewall gate. A LOW stack index so it runs early — before the ACL gate — since a
     * banned IP should never reach dispatch at all. Fail-open, so registering it can't break boot.
     */
    protected function _initFirewall()
    {
        $this->bootstrap('frontController');
        Zend_Controller_Front::getInstance()->registerPlugin(new Tigershield_Plugin_Firewall(), 5);
    }

    /** Contribute the TigerShield page to the admin Settings tree (ACL-gated in the menu). */
    protected function _initAdminSettings()
    {
        if (!class_exists('Tiger_Admin_Settings')) { return; }
        Tiger_Admin_Settings::register([
            'key'      => 'tigershield',
            'label'    => 'Security',
            'icon'     => 'fa-shield-halved',
            'href'     => '/tigershield/admin/settings',
            'resource' => 'Tigershield_AdminController',
            'order'    => 80,
        ]);
    }

    /**
     * Surface the module's dashboard card (the WP `wp_add_dashboard_widget` analog). Registers ONLY when
     * the platform dashboard-widget API exists — that registry isn't built yet (see FEATURES.md §15.6 +
     * the backlog-dashboard-widgets note), so until it ships this is a harmless no-op. When it lands,
     * nothing here changes: Tigershield_Widget_Shield already carries its own registration descriptor.
     */
    protected function _initDashboardWidget()
    {
        if (!class_exists('Tiger_Dashboard')) { return; }   // platform API pending — no-op for now
        // The core module autoloader maps Service/Model/Plugin/Form but not Widget → widgets/, so load
        // the class explicitly. Once required it's in memory for the dashboard renderer this request.
        if (!class_exists('Tigershield_Widget_Shield')) { require_once __DIR__ . '/widgets/Shield.php'; }
        Tiger_Dashboard::registerWidget(Tigershield_Widget_Shield::descriptor());
    }
}
