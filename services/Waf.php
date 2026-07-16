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
 * network. Each category is an admin on/off toggle; soft (SQLi/XSS) categories are advisory (log-only).
 *
 * Two 5.1 additions: (1) admin-authored CUSTOM rules, read from the compiled cache file
 * (Tigershield_Model_Rule::cacheFile) so the gate never queries the DB, run after the shipped ruleset
 * and carrying their own action; (2) opt-in POST-BODY scanning (waf.body.enabled) — the content
 * categories (traversal/rce/sqli/xss) and any body-targeted custom rule also match form-field values,
 * minus a rich-content skip list. Internal engine (NOT a /api service).
 */
class Tigershield_Service_Waf
{
    const MAX_QUERY = 4096;   // only inspect the first 4KB of the query string
    const MAX_BODY  = 8192;   // only inspect the first 8KB of the (form-encoded) POST body

    // The rich-content fields exempted from body scanning by default. Lives in CODE (not just
    // module.ini) because the module.ini base is NOT merged into the registry — the engine runs on
    // these defaults + any DB/config override of waf.body.skip. Keep in sync with module.ini's doc copy.
    const DEFAULT_BODY_SKIP = 'body,content,message,description,html,markdown,text,comment,bio,notes,about,summary,excerpt';

    /** @var array|null the compiled ruleset (per-request static memo) */
    private static $_rules = null;
    /** @var array|null the compiled custom rules (per-request static memo) */
    private static $_custom = null;

    /**
     * Inspect the request. Returns the first match as ['label','action'] (the engine resolves the action:
     * shipped-high → waf.action, shipped-soft → log-only, custom → the rule's own action), or null.
     *
     * @param  Zend_Controller_Request_Abstract $request
     * @return array|null
     */
    public function inspect(Zend_Controller_Request_Abstract $request)
    {
        $custom    = $this->_customRules();
        $needBody  = $this->_bodyScanEnabled() || $this->_anyTargetsBody($custom);
        $surface   = $this->_surface($request, $needBody);
        $wafAction = $this->_config('waf.action', 'log');

        // Shipped ruleset — each category against its surface, plus the body for content categories.
        foreach ($this->_rules() as $key => $cat) {
            if (!$this->_categoryEnabled($key)) { continue; }
            $soft = ($cat['tier'] ?? 'high') === 'soft';
            if ($this->_matchNeedles($cat, $surface[$cat['in'] ?? 'path'] ?? '')) {
                return ['label' => (string) ($cat['label'] ?? $key), 'action' => $this->_norm($soft ? 'log' : $wafAction)];
            }
            if ($needBody && !empty($cat['body']) && isset($surface['body']) && $this->_matchNeedles($cat, $surface['body'])) {
                return ['label' => (string) ($cat['label'] ?? $key) . ' (body)', 'action' => $this->_norm($soft ? 'log' : $wafAction)];
            }
        }

        // Custom admin rules (from the compiled cache) — each carries its own action.
        foreach ($custom as $r) {
            $val = $surface[$r['target'] ?? 'query'] ?? '';
            if ($val === '') { continue; }
            if ($this->_matchPattern($r['match'] ?? 'contains', (string) ($r['pattern'] ?? ''), $val)) {
                return ['label' => (string) ($r['label'] ?? 'custom') . ' (custom)', 'action' => $this->_norm($r['action'] ?? 'log')];
            }
        }
        return null;
    }

    // -- internals -----------------------------------------------------------------------------------

    /** Build the normalized match surfaces (decoded + lowercased where matched CI). Body is opt-in. */
    private function _surface(Zend_Controller_Request_Abstract $request, $withBody = false)
    {
        $uri  = method_exists($request, 'getRequestUri') ? (string) $request->getRequestUri() : (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $raw  = substr($uri, 0, 8192);                                   // undecoded — for %00 / control-char detection
        $path = strtolower(rawurldecode((string) (parse_url($uri, PHP_URL_PATH) ?: '/')));
        $qry  = strtolower(rawurldecode(substr((string) (parse_url($uri, PHP_URL_QUERY) ?? ''), 0, self::MAX_QUERY)));

        $surface = [
            'path'      => $path,
            'query'     => $qry,
            'pathquery' => $path . ' ' . $qry,
            'ua'        => strtolower((string) ($_SERVER['HTTP_USER_AGENT'] ?? '')),
            'method'    => strtoupper((string) $request->getMethod()),
            'raw'       => $raw,
        ];
        if ($withBody) { $surface['body'] = $this->_bodySurface(); }
        return $surface;
    }

    /** A category's literal needles (cheap) then regex, against a single string. */
    private function _matchNeedles(array $cat, $string)
    {
        if ($string === '') { return false; }
        if (!empty($cat['contains'])) {
            foreach ($cat['contains'] as $needle) {
                if (strpos($string, $needle) !== false) { return true; }
            }
        }
        if (!empty($cat['regex'])) {
            foreach ($cat['regex'] as $pattern) {
                if (@preg_match($pattern, $string) === 1) { return true; }
            }
        }
        return false;
    }

    /** Match a custom rule's pattern (contains = case-insensitive substring; regex = the body, wrapped ~…~i). */
    private function _matchPattern($type, $pattern, $string)
    {
        if ($pattern === '' || $string === '') { return false; }
        if ($type === 'regex') {
            return @preg_match('~' . str_replace('~', '\\~', $pattern) . '~i', $string) === 1;
        }
        return stripos($string, $pattern) !== false;
    }

    /** The form-encoded POST body as one lowercased string, minus rich-content + framework fields. Capped. */
    private function _bodySurface()
    {
        if (empty($_POST) || !is_array($_POST)) { return ''; }
        $skip = array_filter(array_map('trim', explode(',', strtolower((string) $this->_config('waf.body.skip', self::DEFAULT_BODY_SKIP)))));
        $skip = array_merge($skip, ['_csrf', 'tigershield_challenge', 'g-recaptcha-response', 'h-captcha-response', 'password', 'password_confirm', 'password_confirmation']);
        $parts = [];
        $len   = 0;
        foreach ($_POST as $k => $v) {
            if (in_array(strtolower((string) $k), $skip, true)) { continue; }
            $s = is_scalar($v) ? (string) $v : (string) json_encode($v);
            $parts[] = $s;
            $len += strlen($s);
            if ($len > self::MAX_BODY) { break; }
        }
        return strtolower(substr(implode(' ', $parts), 0, self::MAX_BODY));
    }

    private function _bodyScanEnabled()
    {
        return $this->_config('waf.body.enabled', '0') === '1';
    }

    private function _anyTargetsBody(array $custom)
    {
        foreach ($custom as $r) { if (($r['target'] ?? '') === 'body') { return true; } }
        return false;
    }

    /** Normalize an action to the allowed set (defaults to the safest — log). */
    private function _norm($action)
    {
        return in_array($action, ['log', 'captcha', 'block'], true) ? $action : 'log';
    }

    /** The active custom rules from the compiled cache (lazy-rebuild on a miss). Per-request memo. */
    private function _customRules()
    {
        if (self::$_custom !== null) { return self::$_custom; }
        self::$_custom = [];
        if (!class_exists('Tigershield_Model_Rule')) { return self::$_custom; }
        try {
            $file = Tigershield_Model_Rule::cacheFile();
            if (!is_file($file)) { (new Tigershield_Model_Rule())->compileCache(); }   // one-shot rebuild
            if (is_file($file)) {
                $data = json_decode((string) @file_get_contents($file), true);
                if (is_array($data)) { self::$_custom = $data; }
            }
        } catch (Throwable $e) { /* fail-soft — no custom rules */ }
        return self::$_custom;
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
