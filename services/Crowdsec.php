<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_Service_Crowdsec — the built-in, dependency-free CrowdSec Central API (CAPI) client (§3, §5).
 *
 * The shared-hosting way to consume CrowdSec's crowd-sourced threat intel WITHOUT the agent/daemon: act
 * as a standalone bouncer against the CAPI. Self-register a machine, log in for a short-lived JWT, pull
 * the community blocklist (decisions stream + downloadable blocklist links), and drop it into the local
 * decision cache (Tigershield_Service_Blocklist) that the gate reads. Optionally enroll the machine to a
 * CrowdSec console account, and optionally push our own detections back as signals — both plain REST, so
 * NO CrowdSec SDK is required (the decision recorded in FEATURES.md §5).
 *
 * Everything here runs OUT OF BAND (a cron/CLI refresh, or a throttled post-response lazy tick) — never
 * on the request hot path. Every network call is FAIL-SOFT: on any error it returns a safe empty/false
 * result and leaves the last-good cache in place, so CrowdSec being down never blocks the site.
 *
 * Internal engine (NOT a /api service).
 *
 * Machine credentials are stored ENCRYPTED at rest in the config tier (Tiger_Crypto; the key lives in
 * local.ini) — so no local.ini write is needed (which the web user often can't do), and they're never
 * plaintext in the DB.
 */
class Tigershield_Service_Crowdsec
{
    const CAPI_DEFAULT = 'https://api.crowdsec.net/v3';
    const UA           = 'TigerShield (+https://github.com/WebTigers/TigerShield)';

    const K_MACHINE    = 'tiger.tigershield.crowdsec.machine';     // encrypted {id,pw}
    const K_REGISTERED = 'tiger.tigershield.crowdsec.registered';
    const K_ENROLLED   = 'tiger.tigershield.crowdsec.enrolled';
    const K_ENROLLKEY  = 'tiger.tigershield.crowdsec.enroll_key';
    const K_LASTSYNC   = 'tiger.tigershield.crowdsec.last_sync';
    const K_COUNT      = 'tiger.tigershield.crowdsec.count';
    const K_LASTERROR  = 'tiger.tigershield.crowdsec.last_error';

    /** Is the CrowdSec integration turned on by the operator? */
    public function enabled()
    {
        return $this->_setting('crowdsec.enabled', '0') === '1';
    }

    /**
     * The main out-of-band job: make sure we're registered, get a token, pull the blocklist, and swap it
     * into the local cache. Returns a stats array (never throws). Safe to call from cron or lazily.
     *
     * @return array{ok:bool, registered:bool, ips:int, ranges:int, total:int, error:?string}
     */
    public function refresh()
    {
        $res = ['ok' => false, 'registered' => false, 'ips' => 0, 'ranges' => 0, 'total' => 0, 'error' => null];
        try {
            if (!$this->enabled()) { $res['error'] = 'disabled'; return $res; }
            if (!$this->ensureMachine()) { $res['error'] = 'registration failed'; $this->_note($res['error']); return $res; }
            $res['registered'] = true;

            $token = $this->_token();
            if (!$token) { $res['error'] = 'login failed'; $this->_note($res['error']); return $res; }

            $decisions = $this->_pullDecisions($token);
            if ($decisions === null) { $res['error'] = 'stream fetch failed'; $this->_note($res['error']); return $res; }

            $bl    = new Tigershield_Service_Blocklist();
            $stats = $bl->replace($decisions, ['last_sync' => time()]);
            $res = array_merge($res, ['ok' => (bool) $stats['ok'], 'ips' => $stats['ips'], 'ranges' => $stats['ranges'], 'total' => $stats['total']]);

            $this->_set(self::K_LASTSYNC, (string) time());
            $this->_set(self::K_COUNT, (string) $stats['total']);
            $this->_set(self::K_LASTERROR, '');
        } catch (Throwable $e) {
            $res['error'] = $e->getMessage();
            $this->_note($e->getMessage());
        }
        return $res;
    }

    /**
     * Ensure a registered machine exists: load stored creds (or mint + store a fresh pair), then register
     * with the CAPI if we haven't yet. Idempotent. Returns true when we hold registered credentials.
     */
    public function ensureMachine()
    {
        $creds = $this->_loadCreds();
        if (!$creds) {
            $creds = ['id' => 'tiger' . bin2hex(random_bytes(20)), 'pw' => rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=')];
            if (!$this->_saveCreds($creds)) { return false; }   // can't persist → don't register a machine we'll forget
        }
        if ($this->_get(self::K_REGISTERED) === '1') { return true; }

        $r = $this->_request('POST', $this->_capi('/watchers'), [], ['machine_id' => $creds['id'], 'password' => $creds['pw']]);
        // 200/201 = created; 403 = already registered with these creds (fine — we own them).
        if (in_array($r['code'], [200, 201, 202, 403], true)) {
            $this->_set(self::K_REGISTERED, '1');
            return true;
        }
        return false;
    }

    /**
     * Enroll this machine into a CrowdSec console account with an attachment key (the "enrollment key"
     * the operator pastes into Settings). Optional — registration alone already pulls the community
     * blocklist; enrolling adds console visibility and any subscribed blocklists. Returns [ok, message].
     */
    public function enroll($attachmentKey = null, $name = null)
    {
        $key = trim((string) ($attachmentKey ?? $this->_get(self::K_ENROLLKEY)));
        if ($key === '') { return ['ok' => false, 'message' => 'no enrollment key']; }
        if (!$this->ensureMachine()) { return ['ok' => false, 'message' => 'registration failed']; }
        $token = $this->_token();
        if (!$token) { return ['ok' => false, 'message' => 'login failed']; }

        $body = [
            'attachment_key' => $key,
            'name'           => substr((string) ($name ?: $this->_siteName()), 0, 128),
            'tags'           => ['tigershield'],
            'overwrite'      => false,
        ];
        $r = $this->_request('POST', $this->_capi('/watchers/enroll'), ['Authorization: Bearer ' . $token], $body);
        if ($r['code'] >= 200 && $r['code'] < 300) {
            $this->_set(self::K_ENROLLED, '1');
            $this->_set(self::K_ENROLLKEY, '');   // used once — don't keep the key lying around
            return ['ok' => true, 'message' => 'enrolled'];
        }
        return ['ok' => false, 'message' => 'enroll failed (HTTP ' . $r['code'] . ')'];
    }

    /**
     * Push our own detections back to the community (opt-in contribute-back, §3). Plain REST (POST
     * /signals) — no SDK. Only sends when the operator has turned contribute-back on. Fail-soft.
     *
     * @param  array $signals CAPI signal objects
     * @return bool sent
     */
    public function pushSignals(array $signals)
    {
        if (empty($signals) || $this->_setting('crowdsec.contribute', '0') !== '1') { return false; }
        if (!$this->ensureMachine()) { return false; }
        $token = $this->_token();
        if (!$token) { return false; }
        $r = $this->_request('POST', $this->_capi('/signals'), ['Authorization: Bearer ' . $token], array_values($signals));
        return $r['code'] >= 200 && $r['code'] < 300;
    }

    /** Status for the admin readout. */
    public function status()
    {
        $bl = new Tigershield_Service_Blocklist();
        return [
            'enabled'    => $this->enabled(),
            'registered' => $this->_get(self::K_REGISTERED) === '1',
            'enrolled'   => $this->_get(self::K_ENROLLED) === '1',
            'last_sync'  => (int) $this->_get(self::K_LASTSYNC, '0'),
            'count'      => $bl->count(),
            'last_error' => $this->_get(self::K_LASTERROR),
        ];
    }

    // -- CAPI calls ----------------------------------------------------------------------------------

    /** Fetch + normalize the current community blocklist. Returns a flat decision list, or null on failure. */
    private function _pullDecisions($token)
    {
        $r = $this->_request('GET', $this->_capi('/decisions/stream') . '?startup=true', ['Authorization: Bearer ' . $token]);
        if ($r['code'] < 200 || $r['code'] >= 300 || !is_array($r['json'])) { return null; }
        $data = $r['json'];
        $out  = [];

        // Inline decisions, grouped by scenario+scope: new[] = {scenario, scope, decisions:[{value,duration}]}.
        foreach (($data['new'] ?? []) as $grp) {
            $scen = (string) ($grp['scenario'] ?? 'crowdsec community blocklist');
            foreach (($grp['decisions'] ?? []) as $dec) {
                $out[] = [
                    'value'    => (string) ($dec['value'] ?? ''),
                    'duration' => self::_duration((string) ($dec['duration'] ?? '')),
                    'type'     => 'ban',
                    'scenario' => $scen,
                ];
            }
        }

        // Downloadable blocklist links (where the bulk community list lives in CAPI v3):
        // links.blocklists[] = {name, url, remediation, scope, duration}. Fail-soft per list.
        foreach (($data['links']['blocklists'] ?? []) as $bl) {
            $url = (string) ($bl['url'] ?? '');
            if ($url === '') { continue; }
            $scen = (string) ($bl['name'] ?? 'crowdsec blocklist');
            $type = ($bl['remediation'] ?? 'ban') === 'captcha' ? 'captcha' : 'ban';
            $dur  = self::_duration((string) ($bl['duration'] ?? '')) ?: 86400;
            $list = $this->_request('GET', $url, ['Authorization: Bearer ' . $token, 'Accept: text/plain']);
            if ($list['code'] < 200 || $list['code'] >= 300 || !is_string($list['raw'])) { continue; }
            foreach (preg_split('/\r?\n/', $list['raw']) as $line) {
                $ip = trim($line);
                if ($ip === '' || $ip[0] === '#') { continue; }
                $out[] = ['value' => $ip, 'duration' => $dur, 'type' => $type, 'scenario' => $scen];
            }
        }
        return $out;
    }

    /** A valid CAPI JWT (file-cached until ~1 min before expiry). Logs in on demand. Null on failure. */
    private function _token()
    {
        $cacheFile = Tigershield_Service_Blocklist::dir() . '/token.json';
        $cached = @json_decode((string) @file_get_contents($cacheFile), true);
        if (is_array($cached) && !empty($cached['token']) && (int) ($cached['expire'] ?? 0) > time() + 60) {
            return $cached['token'];
        }
        $creds = $this->_loadCreds();
        if (!$creds) { return null; }

        $scenarios = array_values(array_filter(array_map('trim', explode(',', (string) $this->_setting('crowdsec.scenarios', '')))));
        $r = $this->_request('POST', $this->_capi('/watchers/login'), [], [
            'machine_id' => $creds['id'],
            'password'   => $creds['pw'],
            'scenarios'  => $scenarios,
        ]);
        if ($r['code'] < 200 || $r['code'] >= 300 || empty($r['json']['token'])) { return null; }
        $token  = (string) $r['json']['token'];
        $expire = isset($r['json']['expire']) ? (strtotime((string) $r['json']['expire']) ?: (time() + 3600)) : (time() + 3600);
        @file_put_contents($cacheFile, json_encode(['token' => $token, 'expire' => $expire]), LOCK_EX);
        @chmod($cacheFile, 0600);
        return $token;
    }

    /**
     * curl (preferred) with a stream-context fallback — matches the platform house style
     * (Tiger_Recaptcha / Tiger_Location adapters). JSON in/out. Returns ['code','json','raw'].
     * Never throws; a transport error is code 0.
     */
    private function _request($method, $url, array $headers = [], $body = null, $timeout = 8)
    {
        $payload = null;
        $hdrs = array_merge(['Accept: application/json', 'User-Agent: ' . self::UA], $headers);
        if ($body !== null) {
            $payload = is_string($body) ? $body : json_encode($body);
            $hdrs[]  = 'Content-Type: application/json';
        }

        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            $opts = [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => $timeout,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_CUSTOMREQUEST  => $method,
                CURLOPT_HTTPHEADER     => $hdrs,
                CURLOPT_FOLLOWLOCATION => true,
            ];
            if ($payload !== null) { $opts[CURLOPT_POSTFIELDS] = $payload; }
            curl_setopt_array($ch, $opts);
            $raw  = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            $raw = ($raw === false) ? null : $raw;
        } else {
            $ctx = stream_context_create(['http' => [
                'method'        => $method,
                'header'        => implode("\r\n", $hdrs),
                'content'       => $payload ?? '',
                'timeout'       => $timeout,
                'ignore_errors' => true,
            ], 'ssl' => ['verify_peer' => true, 'verify_peer_name' => true]]);
            $raw  = @file_get_contents($url, false, $ctx);
            $code = 0;
            if (isset($http_response_header[0]) && preg_match('~\s(\d{3})\s~', $http_response_header[0], $m)) { $code = (int) $m[1]; }
            $raw = ($raw === false) ? null : $raw;
        }
        $json = ($raw !== null) ? json_decode($raw, true) : null;
        return ['code' => $code, 'json' => is_array($json) ? $json : null, 'raw' => $raw];
    }

    // -- credentials (encrypted at rest) -------------------------------------------------------------

    private function _loadCreds()
    {
        $blob = $this->_get(self::K_MACHINE);
        if ($blob === '' || !class_exists('Tiger_Crypto')) { return null; }
        try {
            $plain = Tiger_Crypto::decrypt($blob);
            $c = json_decode((string) $plain, true);
            return (isset($c['id'], $c['pw'])) ? $c : null;
        } catch (Throwable $e) { return null; }
    }

    private function _saveCreds(array $creds)
    {
        if (!class_exists('Tiger_Crypto') || !Tiger_Crypto::isConfigured()) { return false; }
        try {
            $this->_set(self::K_MACHINE, Tiger_Crypto::encrypt(json_encode(['id' => $creds['id'], 'pw' => $creds['pw']])));
            return true;
        } catch (Throwable $e) { return false; }
    }

    // -- config helpers ------------------------------------------------------------------------------

    /** CAPI base URL (operator-overridable), no trailing slash, + a relative path. */
    private function _capi($path = '')
    {
        $base = rtrim((string) $this->_setting('crowdsec.capi_url', self::CAPI_DEFAULT), '/');
        return $base . $path;
    }

    /** Read an operator SETTING from the merged runtime config (tiger.tigershield.<key>). */
    private function _setting($key, $default = null)
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

    /** Read module STATE from the config table directly (immediate, unlike the boot-merged cascade). */
    private function _get($key, $default = '')
    {
        try {
            $v = (new Tiger_Model_Config())->get('global', '', $key);
            return ($v === null || $v === '') ? $default : (string) $v;
        } catch (Throwable $e) {
            return $default;
        }
    }

    /** Write module STATE to the config table directly. */
    private function _set($key, $value)
    {
        try { (new Tiger_Model_Config())->set('global', '', $key, (string) $value); } catch (Throwable $e) { /* fail-soft */ }
    }

    private function _note($msg) { $this->_set(self::K_LASTERROR, substr((string) $msg, 0, 240)); }

    private function _siteName()
    {
        $h = (string) $this->_setting('crowdsec.name', '');
        if ($h !== '') { return $h; }
        return (string) ($_SERVER['HTTP_HOST'] ?? gethostname() ?: 'TigerShield');
    }

    /** Parse a Go duration ("3h59m12.34s", "168h0m0s") to whole seconds. */
    private static function _duration($s)
    {
        $s = trim($s);
        if ($s === '') { return 0; }
        if (preg_match_all('/(-?\d+(?:\.\d+)?)\s*(h|m|s|ms)/', $s, $m, PREG_SET_ORDER)) {
            $secs = 0.0;
            foreach ($m as $p) {
                $n = (float) $p[1];
                $secs += $p[2] === 'h' ? $n * 3600 : ($p[2] === 'm' ? $n * 60 : ($p[2] === 'ms' ? $n / 1000 : $n));
            }
            return (int) round($secs);
        }
        return is_numeric($s) ? (int) $s : 0;
    }
}
