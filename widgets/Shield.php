<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_Widget_Shield — the module's admin-dashboard widget (the at-a-glance "shield" card:
 * mode, blocks today, top offending IP, CrowdSec sync). This is TigerShield's side of the contract;
 * the *platform* side — a `Tiger_Dashboard` registry + optional `Tiger_Dashboard_Widget_Abstract`
 * base — is NOT written yet (see FEATURES.md §15.6 and the backlog-dashboard-widgets note).
 *
 * Bootstrap::_initDashboardWidget() registers this class ONLY when `Tiger_Dashboard` exists, so today
 * it is a harmless no-op. When the platform lands, the dashboard calls data()/render() to paint the
 * card — no change needed here (and, if the base class ships, this can `extends
 * Tiger_Dashboard_Widget_Abstract` to inherit caching/partial-rendering).
 *
 * Contract this implements (kept deliberately small — mirrors WP's wp_add_dashboard_widget callback):
 *   title():  string  heading text (i18n key or literal)
 *   icon():   string  Font Awesome class
 *   data():   array   the cheap, cacheable numbers the card shows
 *   render(): string  self-contained HTML for the card body (from data())
 */
class Tigershield_Widget_Shield
{
    /** Stable, dot-namespaced widget id (module slug prefix) — the registry key. */
    const ID = 'tigershield.shield';

    public function title(): string
    {
        return 'tigershield.dashboard.title';   // resolved by the translator; falls back to the literal
    }

    public function icon(): string
    {
        return 'fa-shield-halved';
    }

    /**
     * The numbers the card shows. Cheap + defensive (the dashboard may poll it): every failure returns
     * a safe zero-state rather than throwing — same fail-open spirit as the gate.
     *
     * @return array{mode:string, blocks_today:int, events_today:int, top_ip:?string, crowdsec:string}
     */
    public function data(): array
    {
        $out = [
            'mode'         => 'learn',
            'blocks_today' => 0,
            'events_today' => 0,
            'top_ip'       => null,
            'crowdsec'     => 'off',
        ];
        try {
            if (Zend_Registry::isRegistered('Zend_Config')) {
                $cfg = Zend_Registry::get('Zend_Config');
                $ts  = $cfg->get('tiger') ? $cfg->get('tiger')->get('tigershield') : null;
                if ($ts) {
                    $out['mode']     = (string) ($ts->get('mode') ?: 'learn');
                    $cs              = $ts->get('crowdsec');
                    $out['crowdsec'] = ($cs && (string) $cs->get('enabled') === '1') ? 'on' : 'off';
                }
            }
        } catch (Throwable $e) { /* fall through to the zero-state */ }

        try {
            $db    = Zend_Db_Table_Abstract::getDefaultAdapter();
            $since = date('Y-m-d 00:00:00');
            if ($db) {
                $out['events_today'] = (int) $db->fetchOne(
                    'SELECT COUNT(*) FROM tigershield_event WHERE created_at >= ?', $since
                );
                // In enforce mode the action is the real verdict; in learn it is logged as "observed".
                $out['blocks_today'] = (int) $db->fetchOne(
                    'SELECT COUNT(*) FROM tigershield_event WHERE created_at >= ? AND action IN (?, ?)',
                    [$since, 'block', 'captcha']
                );
                $out['top_ip'] = $db->fetchOne(
                    'SELECT ip FROM tigershield_event WHERE created_at >= ? GROUP BY ip'
                    . ' ORDER BY COUNT(*) DESC LIMIT 1', $since
                ) ?: null;
            }
        } catch (Throwable $e) { /* table may not exist yet / no adapter — zero-state */ }

        return $out;
    }

    /** Self-contained card HTML built from data(). Minimal + inline so it needs no view resolution. */
    public function render(): string
    {
        $d    = $this->data();
        $enf  = $d['mode'] === 'enforce';
        $tone = $enf ? '#22c55e' : ($d['mode'] === 'off' ? '#9aa4b2' : '#f59e0b');
        $mode = htmlspecialchars(ucfirst($d['mode']), ENT_QUOTES);
        $ip   = $d['top_ip'] ? htmlspecialchars($d['top_ip'], ENT_QUOTES) : '—';
        $cs   = $d['crowdsec'] === 'on' ? 'Connected' : 'Off';

        return '<div class="tigershield-widget" style="display:flex;flex-direction:column;gap:.75rem">'
             . '<div style="display:flex;align-items:center;gap:.5rem">'
             . '<i class="fa-solid ' . $this->icon() . '" style="color:' . $tone . '"></i>'
             . '<strong>Mode:</strong> <span style="color:' . $tone . '">' . $mode . '</span></div>'
             . '<div style="display:grid;grid-template-columns:1fr 1fr;gap:.75rem;text-align:center">'
             . self::_stat($d['blocks_today'], 'blocked today')
             . self::_stat($d['events_today'], 'events today')
             . '</div>'
             . '<div style="display:flex;justify-content:space-between;color:#9aa4b2;font-size:.9em">'
             . '<span>Top IP: <code>' . $ip . '</code></span><span>CrowdSec: ' . $cs . '</span></div>'
             . '<a href="/tigershield/admin/events" style="font-size:.9em">View live traffic →</a>'
             . '</div>';
    }

    private static function _stat($n, $label): string
    {
        return '<div><div style="font-size:1.6rem;font-weight:700">' . (int) $n . '</div>'
             . '<div style="color:#9aa4b2;font-size:.85em">' . htmlspecialchars($label, ENT_QUOTES)
             . '</div></div>';
    }

    /**
     * The descriptor Bootstrap hands to the platform registry. Kept here so the widget owns its own
     * registration metadata (id, sizing, gating) — the shape the forthcoming Tiger_Dashboard API
     * consumes (see backlog-dashboard-widgets).
     */
    public static function descriptor(): array
    {
        return [
            'id'       => self::ID,
            'module'   => 'tigershield',
            'title'    => 'tigershield.dashboard.title',
            'icon'     => 'fa-shield-halved',
            'widget'   => __CLASS__,                    // class exposing data()/render()
            'resource' => 'Tigershield_AdminController', // ACL resource gating visibility (admin+)
            'width'    => 1,                             // column-span in the even-column grid
            'order'    => 50,                            // sort within the dashboard
            'refresh'  => 60,                            // client auto-refresh seconds (0 = static)
        ];
    }
}
