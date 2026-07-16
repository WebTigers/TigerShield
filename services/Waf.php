<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_Service_Waf — the request WAF engine (§7). Matches the incoming request's CONTENT (path,
 * query, User-Agent, method) against the curated ruleset (rules/default-waf.php) and returns the first
 * category hit. WHO-based engines (CrowdSec / login / rate) judge the caller; this judges the request.
 *
 * Fast + bounded: literal `strpos` checks before regex, the query surface capped at 4KB (ReDoS ceiling),
 * static assets skipped by the caller, first-match short-circuits. Pure CPU on short strings — no DB, no
 * network. Does NOT scan POST bodies in v1 (that's where false positives live — deferred to 5.1). Each
 * category is an admin on/off toggle; soft (SQLi/XSS) categories are advisory (the gate caps them to
 * log-only). Internal engine (NOT a /api service).
 */
class Tigershield_Service_Waf
{
    const MAX_QUERY = 4096;   // only inspect the first 4KB of the query string

    /** @var array|null the compiled ruleset (per-request static memo) */
    private static $_rules = null;

    /**
     * Inspect the request. Returns the first matching category as ['category','label','tier'], or null.
     *
     * @param  Zend_Controller_Request_Abstract $request
     * @return array|null
     */
    public function inspect(Zend_Controller_Request_Abstract $request)
    {
        $surface = $this->_surface($request);
        foreach ($this->_rules() as $key => $cat) {
            if (!$this->_categoryEnabled($key)) { continue; }
            if ($this->_matches($cat, $surface)) {
                return ['category' => $key, 'label' => (string) ($cat['label'] ?? $key), 'tier' => ($cat['tier'] ?? 'high') === 'soft' ? 'soft' : 'high'];
            }
        }
        return null;
    }

    // -- internals -----------------------------------------------------------------------------------

    /** Build the normalized match surfaces from the request (decoded + lowercased where matched CI). */
    private function _surface(Zend_Controller_Request_Abstract $request)
    {
        $uri  = method_exists($request, 'getRequestUri') ? (string) $request->getRequestUri() : (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $raw  = substr($uri, 0, 8192);                                   // undecoded — for %00 / control-char detection
        $path = strtolower(rawurldecode((string) (parse_url($uri, PHP_URL_PATH) ?: '/')));
        $qry  = strtolower(rawurldecode(substr((string) (parse_url($uri, PHP_URL_QUERY) ?? ''), 0, self::MAX_QUERY)));

        return [
            'path'      => $path,
            'query'     => $qry,
            'pathquery' => $path . ' ' . $qry,
            'ua'        => strtolower((string) ($_SERVER['HTTP_USER_AGENT'] ?? '')),
            'method'    => strtoupper((string) $request->getMethod()),
            'raw'       => $raw,
        ];
    }

    /** Does a category match the surface? Literal needles first (cheap), then regex. */
    private function _matches(array $cat, array $surface)
    {
        $target = $surface[$cat['in'] ?? 'path'] ?? '';
        if ($target === '') { return false; }

        if (!empty($cat['contains'])) {
            foreach ($cat['contains'] as $needle) {
                if (strpos($target, $needle) !== false) { return true; }
            }
        }
        if (!empty($cat['regex'])) {
            foreach ($cat['regex'] as $pattern) {
                if (@preg_match($pattern, $target) === 1) { return true; }
            }
        }
        return false;
    }

    /** A category is on unless explicitly disabled (tiger.tigershield.waf.cat.<key> = 0). */
    private function _categoryEnabled($key)
    {
        return $this->_config('waf.cat.' . $key, '1') !== '0';
    }

    /** Load + memo the shipped ruleset (opcache-cached require). Fail-soft to []. */
    private function _rules()
    {
        if (self::$_rules !== null) { return self::$_rules; }
        try {
            $file = dirname(__DIR__) . '/rules/default-waf.php';
            $rules = is_file($file) ? require $file : [];
            self::$_rules = is_array($rules) ? $rules : [];
        } catch (Throwable $e) {
            self::$_rules = [];
        }
        return self::$_rules;
    }

    /** Read a tiger.tigershield.<key> config value (live-override tier), with a default. */
    private function _config($key, $default = null)
    {
        if (!Zend_Registry::isRegistered('Zend_Config')) { return $default; }
        $node = Zend_Registry::get('Zend_Config');
        foreach (['tiger', 'tigershield'] as $seg) { $node = $node instanceof Zend_Config ? $node->get($seg) : null; }
        foreach (explode('.', $key) as $seg) {
            if (!($node instanceof Zend_Config)) { return $default; }
            $node = $node->get($seg);
            if ($node === null) { return $default; }
        }
        return is_scalar($node) ? (string) $node : $default;
    }

    /** The category keys + labels + tiers, for the admin toggles. */
    public function categories()
    {
        $out = [];
        foreach ($this->_rules() as $key => $cat) {
            $out[$key] = ['label' => (string) ($cat['label'] ?? $key), 'tier' => ($cat['tier'] ?? 'high')];
        }
        return $out;
    }
}
