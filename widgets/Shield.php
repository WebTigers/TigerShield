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
        $window = 604800;   // 7 days — matches WordFence's "activity in the past week"
        $out = [
            'mode'          => 'learn',
            'crowdsec'      => 'off',
            'flagged'       => 0,
            'top_ips'       => [],   // [{ip, country, hits}]
            'top_countries' => [],   // [{country, hits}]
            'top_failed'    => [],   // [{identifier, attempts, existing}]
        ];

        try {
            if (Zend_Registry::isRegistered('Zend_Config')) {
                $cfg = Zend_Registry::get('Zend_Config');
                $ts  = $cfg->get('tiger') ? $cfg->get('tiger')->get('tigershield') : null;
                if ($ts) {
                    $out['mode'] = (string) ($ts->get('mode') ?: 'learn');
                    $cs = $ts->get('crowdsec');
                    $out['crowdsec'] = ($cs && (string) $cs->get('enabled') === '1') ? 'on' : 'off';
                }
            }
        } catch (Throwable $e) { /* zero-state */ }

        // Top offending IPs (+ geolocated countries, aggregated) — the "who the shield is stopping" view.
        try {
            $event = new Tigershield_Model_Event();
            $out['flagged'] = $event->countSince($window);
            $countries = [];
            foreach ($event->topIps($window, 10) as $r) {
                $cc = self::_geo($r['ip']);
                if (count($out['top_ips']) < 5) {
                    $out['top_ips'][] = ['ip' => $r['ip'], 'country' => $cc, 'hits' => $r['hits']];
                }
                if ($cc !== '') { $countries[$cc] = ($countries[$cc] ?? 0) + $r['hits']; }
            }
            arsort($countries);
            foreach (array_slice($countries, 0, 5, true) as $cc => $hits) {
                $out['top_countries'][] = ['country' => $cc, 'hits' => $hits];
            }
        } catch (Throwable $e) { /* zero-state */ }

        // Top targeted accounts by failed sign-ins — straight off the login audit log.
        try {
            if (class_exists('Tiger_Model_Login')) {
                $out['top_failed'] = (new Tiger_Model_Login())->topFailures($window, 5);
            }
        } catch (Throwable $e) { /* zero-state */ }

        return $out;
    }

    /** The card BODY — the WordFence-style "security is working" tables. Themed Bootstrap (light/dark). */
    public function render(): string
    {
        $d    = $this->data();
        $tone = $d['mode'] === 'enforce' ? 'success' : ($d['mode'] === 'off' ? 'secondary' : 'warning');
        $mode = htmlspecialchars(ucfirst($d['mode']), ENT_QUOTES);
        $cs   = $d['crowdsec'] === 'on' ? 'On' : 'Off';

        $h  = '<div class="d-flex justify-content-between align-items-center small mb-2">'
            . '<span><strong>Mode:</strong> <span class="text-' . $tone . '">' . $mode . '</span></span>'
            . '<span class="text-body-secondary">CrowdSec: ' . $cs . '</span></div>'
            . '<p class="small text-body-secondary mb-3"><strong class="text-body">' . (int) $d['flagged']
            . '</strong> events flagged in the last 7 days.</p>';

        $any = false;

        if (!empty($d['top_ips'])) {
            $any  = true;
            $rows = '';
            foreach ($d['top_ips'] as $r) {
                $rows .= '<tr><td><code>' . htmlspecialchars($r['ip'], ENT_QUOTES) . '</code></td><td>'
                       . ($r['country'] !== '' ? '<span class="badge text-bg-light text-uppercase">' . htmlspecialchars($r['country'], ENT_QUOTES) . '</span>' : '<span class="text-body-secondary">—</span>')
                       . '</td><td class="text-end">' . (int) $r['hits'] . '</td></tr>';
            }
            $h .= self::_table('Top offending IPs', '<tr><th>IP</th><th>Country</th><th class="text-end">Hits</th></tr>', $rows);
        }

        if (!empty($d['top_countries'])) {
            $any  = true;
            $rows = '';
            foreach ($d['top_countries'] as $r) {
                $rows .= '<tr><td><span class="badge text-bg-light text-uppercase">' . htmlspecialchars($r['country'], ENT_QUOTES)
                       . '</span></td><td class="text-end">' . (int) $r['hits'] . '</td></tr>';
            }
            $h .= self::_table('Top countries', '<tr><th>Country</th><th class="text-end">Hits</th></tr>', $rows);
        }

        if (!empty($d['top_failed'])) {
            $any  = true;
            $rows = '';
            foreach ($d['top_failed'] as $r) {
                $ex = !empty($r['existing']) ? '<span class="text-success">Yes</span>' : '<span class="text-danger">No</span>';
                $rows .= '<tr><td class="text-truncate" style="max-width:9rem">' . htmlspecialchars($r['identifier'], ENT_QUOTES)
                       . '</td><td class="text-end">' . (int) $r['attempts'] . '</td><td class="text-center">' . $ex . '</td></tr>';
            }
            $h .= self::_table('Top targeted logins', '<tr><th>Account</th><th class="text-end">Tries</th><th class="text-center">Real?</th></tr>', $rows);
        }

        if (!$any) {
            $h .= '<p class="small text-body-secondary mb-2"><i class="fa-regular fa-circle-check me-1"></i>The shield is watching — nothing flagged in the last 7 days.</p>';
        }

        $h .= '<a href="/tigershield/admin/events" class="small text-decoration-none">View live traffic &rarr;</a>';
        return '<div class="tigershield-widget">' . $h . '</div>';
    }

    /** A small titled table (themed). $thead + $rows are trusted HTML built by render(). */
    private static function _table(string $title, string $thead, string $rows): string
    {
        return '<div class="mb-3"><div class="fw-semibold small mb-1">' . htmlspecialchars($title, ENT_QUOTES) . '</div>'
             . '<table class="table table-sm small mb-0"><thead>' . $thead . '</thead><tbody>' . $rows . '</tbody></table></div>';
    }

    /**
     * Best-effort ISO country for an IP, cached in APCu (IPs don't move countries). Bounded to the few
     * IPs the widget shows; fail-soft to '' when geolocation is unconfigured/unavailable. Never networks
     * on a cache hit, so a warm dashboard is a pure DB read.
     */
    private static function _geo(string $ip): string
    {
        if ($ip === '' || !class_exists('Tiger_Location')) { return ''; }
        $ck   = 'tigershield:geo:' . md5($ip);
        $apcu = function_exists('apcu_fetch') && (bool) ini_get('apc.enabled');
        if ($apcu) { $v = @apcu_fetch($ck); if (is_string($v)) { return $v; } }
        $cc = '';
        try {
            $place = (new Tiger_Location())->ip($ip);
            if ($place && $place->country) { $cc = strtoupper(substr((string) $place->country, 0, 2)); }
        } catch (Throwable $e) { /* geolocation is best-effort */ }
        if ($apcu) { @apcu_store($ck, $cc, 86400); }
        return $cc;
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
