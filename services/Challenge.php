<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_Service_Challenge — the captcha-gating engine (§6). Turns a `captcha` verdict into an
 * interstitial the visitor can solve, instead of a flat block — so a shared IP or a false-positive
 * proves it's human rather than getting a 403.
 *
 * This is the **provider seam**: today it wraps Tiger's reCAPTCHA (`Tiger_Recaptcha`, v2 checkbox or v3
 * score, config-driven, secret in local.ini); hCaptcha / Turnstile would slot in behind the same three
 * methods (available / interstitial / verify). On a pass it issues a short-lived, **HMAC-signed,
 * IP-bound clearance cookie** — no server-side state, works on the barest host — that the gate honors to
 * skip re-challenging that browser for a window.
 *
 * Internal engine (NOT a /api service).
 */
class Tigershield_Service_Challenge
{
    const COOKIE = 'tigershield_clear';

    /** Is a captcha provider configured and usable? (No keys → captcha gating can't run.) */
    public function available()
    {
        return class_exists('Tiger_Recaptcha')
            && Tiger_Recaptcha::isEnabled()
            && Tiger_Recaptcha::siteKey() !== ''
            && Tiger_Recaptcha::secretKey() !== '';
    }

    /**
     * Verify a solved captcha token with the provider. Honors the provider's fail-open policy on a
     * transport failure (can't reach the verifier). Returns true only on a genuine pass.
     *
     * @param  string $token the provider response token from the interstitial
     * @param  string $ip    the client IP (passed to the verifier)
     * @return bool
     */
    public function verify($token, $ip)
    {
        if (!$this->available() || (string) $token === '') { return false; }
        $res = Tiger_Recaptcha::verify($token, $ip);
        if ($res === null) {                                   // transport failure
            return (bool) Tiger_Recaptcha::failOpen();
        }
        if (empty($res['success'])) { return false; }
        if (Tiger_Recaptcha::version() === 'v3') {             // score gate
            return (float) ($res['score'] ?? 0) >= Tiger_Recaptcha::minScore();
        }
        return true;
    }

    /** Clearance window in seconds (how long a solved browser is trusted for this IP). */
    public function window()
    {
        $w = (int) $this->_config('captcha.window', 3600);
        return $w > 0 ? $w : 3600;
    }

    /** Issue the signed clearance cookie for this IP (and return its value, for testing). */
    public function issueClearance($ip, ?Zend_Controller_Request_Abstract $request = null)
    {
        $exp   = time() + $this->window();
        $value = $exp . '.' . $this->_sign($ip, $exp);
        $secure = $request ? ($request->getScheme() === 'https') : (!empty($_SERVER['HTTPS']));
        if (!headers_sent()) {
            @setcookie(self::COOKIE, $value, [
                'expires'  => $exp,
                'path'     => '/',
                'httponly' => true,
                'secure'   => $secure,
                'samesite' => 'Lax',
            ]);
        }
        $_COOKIE[self::COOKIE] = $value;                       // visible to this request too
        return $value;
    }

    /** Does the request carry a valid, unexpired clearance cookie bound to this IP? */
    public function hasClearance($ip, Zend_Controller_Request_Abstract $request)
    {
        $raw = method_exists($request, 'getCookie') ? (string) $request->getCookie(self::COOKIE) : (string) ($_COOKIE[self::COOKIE] ?? '');
        return $this->verifyClearance($ip, $raw);
    }

    /** Validate a clearance token string against an IP (exposed for testing). */
    public function verifyClearance($ip, $token)
    {
        if (strpos((string) $token, '.') === false) { return false; }
        [$exp, $sig] = explode('.', $token, 2);
        if (!ctype_digit($exp) || (int) $exp < time()) { return false; }
        return hash_equals($this->_sign($ip, (int) $exp), (string) $sig);
    }

    /**
     * The full interstitial HTML page — a clean, self-contained challenge screen with the provider
     * widget. The form re-POSTs to $actionUrl with the solve token + the marker the gate recognizes.
     *
     * @param  string      $actionUrl where the form posts (a path the gate intercepts)
     * @param  string      $returnUrl the local path to send the visitor to on success
     * @param  string|null $error     an optional "please try again" message
     * @return string
     */
    public function interstitial($actionUrl, $returnUrl, $error = null)
    {
        $site = htmlspecialchars(Tiger_Recaptcha::siteKey(), ENT_QUOTES);
        $v3   = Tiger_Recaptcha::version() === 'v3';
        $act  = htmlspecialchars($actionUrl, ENT_QUOTES);
        $ret  = htmlspecialchars($returnUrl, ENT_QUOTES);
        $err  = $error ? '<p class="e">' . htmlspecialchars($error, ENT_QUOTES) . '</p>' : '';

        $script = $v3
            ? '<script src="https://www.google.com/recaptcha/api.js?render=' . $site . '"></script>'
            : '<script src="https://www.google.com/recaptcha/api.js" async defer></script>';

        $widget = $v3
            ? '<input type="hidden" name="g-recaptcha-response" id="tok">'
            : '<div class="g-recaptcha" data-sitekey="' . $site . '" style="display:inline-block"></div>';

        $submitJs = $v3
            ? '<script>document.getElementById("cf").addEventListener("submit",function(e){e.preventDefault();var f=this;'
              . 'grecaptcha.ready(function(){grecaptcha.execute("' . $site . '",{action:"tigershield"}).then(function(t){'
              . 'document.getElementById("tok").value=t;f.submit();});});});</script>'
            : '';

        // Honor the platform's "hide the v3 badge" setting (with the required legal notice in its place).
        $badge  = class_exists('Tiger_Recaptcha') ? Tiger_Recaptcha::badgeCss() : '';
        $notice = class_exists('Tiger_Recaptcha') ? Tiger_Recaptcha::legalNotice() : '';

        return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
             . '<meta name="viewport" content="width=device-width, initial-scale=1"><title>Verify you\'re human</title>'
             . $script . $badge
             . '<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;'
             . 'font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0f1216;color:#e8eaed}'
             . '.c{max-width:440px;text-align:center;padding:32px}h1{font-size:1.4rem;margin:.4em 0}'
             . '.m{color:#9aa4b2}.e{color:#f87171}.s{color:#f59e0b;font-size:2.2rem}button{margin-top:18px;'
             . 'font:inherit;padding:.6em 1.4em;border:0;border-radius:8px;background:#2563eb;color:#fff;cursor:pointer}'
             . 'form{margin-top:14px}</style></head><body><div class="c">'
             . '<div class="s">&#128737;</div><h1>Please confirm you\'re human</h1>'
             . '<p class="m">Automated activity was detected from your connection. Complete the check below to continue.</p>'
             . $err
             . '<form id="cf" method="post" action="' . $act . '">'
             . '<input type="hidden" name="tigershield_challenge" value="1">'
             . '<input type="hidden" name="return" value="' . $ret . '">'
             . $widget
             . '<div><button type="submit">Continue</button></div></form>'
             . $notice
             . '</div>' . $submitJs . '</body></html>';
    }

    // -- internals -----------------------------------------------------------------------------------

    /** HMAC a clearance token: binds the IP + expiry so a solved cookie can't be replayed elsewhere. */
    private function _sign($ip, $exp)
    {
        return substr(hash_hmac('sha256', $ip . '|' . (int) $exp, $this->_secret()), 0, 32);
    }

    /** The signing secret — the app crypto key (always provisioned at install), then the pepper. */
    private function _secret()
    {
        foreach (['tiger.crypto.key', 'tiger.security.pepper'] as $k) {
            $v = $this->_configRaw($k);
            if ($v !== null && $v !== '') { return 'tigershield|' . $v; }
        }
        return 'tigershield|fallback-unkeyed';   // degraded, but never unsigned
    }

    /** Read a tiger.tigershield.<key> setting (with a default). */
    private function _config($key, $default = null)
    {
        $v = $this->_configRaw('tiger.tigershield.' . $key);
        return $v === null ? $default : $v;
    }

    /** Read any dotted config key from the merged runtime config. */
    private function _configRaw($dotted)
    {
        if (!Zend_Registry::isRegistered('Zend_Config')) { return null; }
        $node = Zend_Registry::get('Zend_Config');
        foreach (explode('.', $dotted) as $seg) {
            if (!($node instanceof Zend_Config)) { return null; }
            $node = $node->get($seg);
            if ($node === null) { return null; }
        }
        return is_scalar($node) ? (string) $node : null;
    }
}
