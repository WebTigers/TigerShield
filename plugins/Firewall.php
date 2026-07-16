<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_Plugin_Firewall — the front-controller WAF gate. Runs before dispatch on EVERY request.
 *
 * FAIL-OPEN by contract (FEATURES.md §0/§11): any error, the kill-switch, or the absence of fresh
 * local data ALLOWS the request. Blocking is a *positive* decision from *fresh, local* data — never a
 * side effect of a bug or an outage. The hot path is a cache/DB-audit lookup, never a live network call.
 *
 * Phase 2 (built): login protection (Tiger's login audit log — no cache, works anywhere) + general
 * per-request rate limiting (APCu when present). CrowdSec IP decisions (§3) and the request WAF (§7)
 * plug into _decide() in their phases.
 */
class Tigershield_Plugin_Firewall extends Zend_Controller_Plugin_Abstract
{
    /** Gate the request as early as possible (before the ACL plugin). */
    public function routeStartup(Zend_Controller_Request_Abstract $request)
    {
        try {
            if (!self::_enabled()) { return; }                        // kill-switch / break-glass file
            self::_maybeScheduleRefresh($request);                    // opportunistic out-of-band CrowdSec pull
            $ip = self::_clientIp($request);
            if ($ip === '' || self::_isAllowlisted($ip)) { return; }  // trusted → never gated

            $decision = self::_decide($ip, $request);                 // null (allow) | ['action','reason']
            if ($decision === null) { return; }

            self::_logEvent($ip, $decision, $request);
            if (self::_mode() !== 'enforce') { return; }              // off / learn → log only, never block

            if ($decision['action'] === 'captcha') {
                self::_challenge($request, $ip);                       // phase 4 (no-op until then → allow)
            } else {
                self::_block($request, $ip, $decision['reason']);
            }
        } catch (Throwable $e) {
            // FAIL-OPEN: the shield must never take the site down. Log and continue.
            if (class_exists('Tiger_Log')) {
                Tiger_Log::warn('tigershield.gate', ['error' => $e->getMessage()]);
            }
        }
    }

    // -- the decision pipeline (first non-null decision wins; order = cheapest/highest-value first) ----

    protected static function _decide($ip, Zend_Controller_Request_Abstract $request)
    {
        // CrowdSec cached decision first — a known-bad IP shouldn't reach anything else. Pure local
        // cache lookup (the blocklist is filled out-of-band), so it's microseconds and never networks.
        $d = self::_crowdsecDecision($ip);
        if ($d !== null) { return $d; }

        if (self::_config('ratelimit.enabled', '1') !== '0') {
            // Login protection — reads Tiger's login audit log (no cache; works on any host). Catches
            // distributed brute force (many failures from one IP) AND credential stuffing (one IP
            // spraying many accounts). Complements Tiger's per-ACCOUNT lockout with a per-IP dimension.
            if (self::_isLoginPost($request)) {
                $d = self::_loginDecision($ip, $request);
                if ($d !== null) { return $d; }
            }
            // General per-request rate limiting — needs a fast counter (APCu); graceful no-op without.
            return self::_rateLimitDecision($ip, $request);
        }
        return null;

        // TODO(phase 5): request WAF ruleset.
    }

    /**
     * CrowdSec / local-blocklist decision — a set-membership lookup against the locally cached community
     * blocklist (Tigershield_Service_Blocklist, filled by Tigershield_Service_Crowdsec out of band).
     * Own toggle (crowdsec.enabled, default off) so it costs nothing until enrolled. Never networks.
     */
    protected static function _crowdsecDecision($ip)
    {
        if (self::_config('crowdsec.enabled', '0') !== '1') { return null; }
        if (!class_exists('Tigershield_Service_Blocklist')) { return null; }
        $d = (new Tigershield_Service_Blocklist())->lookup($ip);
        if (!$d) { return null; }
        return [
            'action' => (($d['type'] ?? 'ban') === 'captcha' ? 'captcha' : 'block'),
            'reason' => 'crowdsec: ' . ($d['scenario'] ?? 'community blocklist'),
        ];
    }

    /** Is this a POST to the sign-in endpoint (/login or /auth/login)? */
    protected static function _isLoginPost(Zend_Controller_Request_Abstract $request)
    {
        if (strtoupper((string) $request->getMethod()) !== 'POST') { return false; }
        $p = self::_path($request);
        return $p === '/login' || $p === '/auth/login';
    }

    /**
     * Login brute-force / credential-stuffing decision from the login audit log. Counts recent
     * FAILURES (result <> success); the current attempt isn't recorded yet, so this throttles the
     * (N+1)th attempt once N prior failures are on record — from this IP, or against this account.
     */
    protected static function _loginDecision($ip, Zend_Controller_Request_Abstract $request)
    {
        if (!class_exists('Tiger_Model_Login')) { return null; }
        $window = (int) self::_config('ratelimit.login.window', '300');
        $ipMax  = (int) self::_config('ratelimit.login.max', '10');
        $idMax  = (int) self::_config('ratelimit.login.identifier_max', '20');
        $action = self::_config('ratelimit.login.action', 'block');

        $login = new Tiger_Model_Login();
        if ($ipMax > 0 && $login->recentFailuresFromIp($ip, $window) >= $ipMax) {
            return ['action' => $action, 'reason' => 'login: too many failed sign-ins from this IP'];
        }
        $id = trim((string) $request->getPost('identifier'));
        if ($id !== '' && $idMax > 0 && $login->recentFailuresForIdentifier($id, $window) >= $idMax) {
            return ['action' => $action, 'reason' => 'login: too many failed sign-ins for this account'];
        }
        return null;
    }

    /** General per-request rate limit (fixed window per IP). No-op without a fast cache (APCu). */
    protected static function _rateLimitDecision($ip, Zend_Controller_Request_Abstract $request)
    {
        if (self::_isAsset($request)) { return null; }
        $rl = new Tigershield_Service_RateLimit();
        if (!$rl->available()) { return null; }               // no fast cache → general limiting off
        $max = (int) self::_config('ratelimit.request.max', '300');
        $win = (int) self::_config('ratelimit.request.window', '60');
        $r = $rl->hit('req:' . $ip, $max, $win);
        if ($r['over']) {
            return ['action' => 'block', 'reason' => 'rate: ' . $r['count'] . ' requests in ' . $win . 's'];
        }
        return null;
    }

    /**
     * No-cron CrowdSec refresh: on a capable host (a cron running the module CLI) this never fires; on a
     * shared host without cron, one request per interval pulls the blocklist AFTER the response is flushed
     * (fastcgi_finish_request), so the visitor never waits. A lock file + its mtime throttle it to one
     * refresh per interval across all workers. Entirely fail-open — scheduling can't affect the request.
     */
    protected static function _maybeScheduleRefresh(Zend_Controller_Request_Abstract $request)
    {
        try {
            if (self::_config('crowdsec.enabled', '0') !== '1') { return; }
            if (!function_exists('fastcgi_finish_request')) { return; }   // only where we can run post-response
            if (!class_exists('Tigershield_Service_Crowdsec')) { return; }

            $interval = max(300, (int) self::_config('crowdsec.refresh', '900'));
            $lock = Tigershield_Service_Blocklist::dir() . '/refresh.lock';
            if (time() - (int) (@filemtime($lock) ?: 0) < $interval) { return; }   // not due (cheap stat)

            $fh = @fopen($lock, 'c');
            if (!$fh) { return; }
            if (!@flock($fh, LOCK_EX | LOCK_NB)) { @fclose($fh); return; }          // another worker has it
            clearstatcache(true, $lock);
            if (time() - (int) (@filemtime($lock) ?: 0) < $interval) {             // re-check under lock
                @flock($fh, LOCK_UN); @fclose($fh); return;
            }
            @touch($lock);                                                          // claim the window now
            @flock($fh, LOCK_UN); @fclose($fh);

            register_shutdown_function(function () {
                try {
                    if (function_exists('fastcgi_finish_request')) { @fastcgi_finish_request(); }
                    @set_time_limit(30);
                    (new Tigershield_Service_Crowdsec())->refresh();
                } catch (Throwable $e) { /* out-of-band; never surfaces */ }
            });
        } catch (Throwable $e) { /* scheduling must never affect the request */ }
    }

    // -- helpers -------------------------------------------------------------------------------------

    protected static function _enabled()
    {
        if (defined('APPLICATION_ROOT') && is_file(APPLICATION_ROOT . '/storage/.tigershield-off')) { return false; }
        return self::_config('enabled', '1') !== '0';
    }

    protected static function _mode()
    {
        $m = self::_config('mode', 'learn');                          // off | learn | enforce
        return in_array($m, ['off', 'learn', 'enforce'], true) ? $m : 'learn';
    }

    protected static function _clientIp(Zend_Controller_Request_Abstract $request)
    {
        // Tiger_Application::normalizeProxy already fixed REMOTE_ADDR behind the ALB, so getClientIp
        // reflects the real client.
        return method_exists($request, 'getClientIp') ? (string) $request->getClientIp() : (string) ($_SERVER['REMOTE_ADDR'] ?? '');
    }

    protected static function _isAllowlisted($ip)
    {
        // TODO(phase 3): config allow-list (IP/CIDR) + optionally logged-in admins.
        return false;
    }

    /** Skip static assets — no point rate-limiting or WAF-ing them. */
    protected static function _isAsset(Zend_Controller_Request_Abstract $request)
    {
        $p = self::_path($request);
        return (bool) preg_match('~\.(?:css|js|mjs|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|eot|map)$~', $p)
            || strncmp($p, '/_', 2) === 0;                            // /_theme, /_media, /_tiger, ...
    }

    /** The request path (no query string), lowercased, trimmed — from the raw URI (routing hasn't run). */
    protected static function _path(Zend_Controller_Request_Abstract $request)
    {
        $uri = method_exists($request, 'getRequestUri') ? (string) $request->getRequestUri() : (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $p   = (string) (parse_url($uri, PHP_URL_PATH) ?: '/');
        $p   = rtrim(strtolower($p), '/');
        return $p === '' ? '/' : $p;
    }

    protected static function _logEvent($ip, array $decision, Zend_Controller_Request_Abstract $request)
    {
        try {
            (new Tigershield_Model_Event())->record([
                'ip'     => $ip,
                'action' => (self::_mode() === 'enforce' ? $decision['action'] : 'observed'),
                'reason' => $decision['reason'] ?? '',
                'route'  => self::_path($request),
                'ua'     => (string) ($_SERVER['HTTP_USER_AGENT'] ?? ''),
            ]);
        } catch (Throwable $e) { /* logging must never break the gate */ }
    }

    /** Render the reCAPTCHA interstitial and stop dispatch (phase 4). No-op for now → request allowed. */
    protected static function _challenge(Zend_Controller_Request_Abstract $request, $ip)
    {
        // TODO(phase 4): show the challenge page; a pass sets a short-lived clear-token for this IP.
    }

    /**
     * Emit a 429 block response and stop the request — a clean, minimal branded page + the right
     * status so bots back off and a human gets a clear message. Never a bare die().
     */
    protected static function _block(Zend_Controller_Request_Abstract $request, $ip, $reason)
    {
        $response = Zend_Controller_Front::getInstance()->getResponse();
        $response->clearBody();
        $response->setHttpResponseCode(429);
        $response->setHeader('Retry-After', '60', true);
        $response->setHeader('Content-Type', 'text/html; charset=utf-8', true);
        $response->setHeader('X-TigerShield', 'blocked', true);
        $response->setBody(self::_blockPage());
        $response->sendResponse();
        $request->setDispatched(true);
        exit;
    }

    protected static function _blockPage()
    {
        return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
             . '<meta name="viewport" content="width=device-width, initial-scale=1"><title>Access blocked</title>'
             . '<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;'
             . 'font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0f1216;color:#e8eaed}'
             . '.c{max-width:440px;text-align:center;padding:32px}h1{font-size:1.4rem;margin:.4em 0}'
             . '.m{color:#9aa4b2}.s{color:#f59e0b;font-size:2.2rem}</style></head><body><div class="c">'
             . '<div class="s">&#128737;</div><h1>Access temporarily blocked</h1>'
             . '<p class="m">Too many requests from your connection. Please wait a minute and try again. '
             . 'If you believe this is a mistake, contact the site owner.</p></div></body></html>';
    }

    /** Read a tiger.tigershield.* config value (live-override tier), with a default. */
    protected static function _config($key, $default = null)
    {
        if (!Zend_Registry::isRegistered('Zend_Config')) { return $default; }
        $cfg = Zend_Registry::get('Zend_Config');
        $t   = $cfg->get('tiger'); $s = $t ? $t->get('tigershield') : null;
        if (!$s) { return $default; }
        // Support dotted sub-keys (ratelimit.login.max) against the nested config tree.
        $node = $s;
        foreach (explode('.', $key) as $seg) {
            if (!($node instanceof Zend_Config)) { return $default; }
            $node = $node->get($seg);
            if ($node === null) { return $default; }
        }
        return is_scalar($node) ? (string) $node : $default;
    }
}
