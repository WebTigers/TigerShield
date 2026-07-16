<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * TigerShield module CLI — CrowdSec maintenance from the shell / cron.
 *
 * Tiger's console (bin/tiger) has no module-command registry (a platform gap — see the module docs), so
 * the module ships its own tiny entrypoint. It boots the app exactly like a web request, then runs one
 * of the CrowdSec jobs. On a host WITH cron, schedule the refresh (every ~15 min):
 *
 *     * /15 * * * *  php /path/to/app/application/modules/tigershield/bin/tigershield.php refresh >/dev/null 2>&1
 *
 * On a host WITHOUT cron, the firewall plugin runs the same refresh lazily after the response is flushed.
 *
 * Usage:
 *   php bin/tigershield.php refresh          Pull the community blocklist into the local cache
 *   php bin/tigershield.php status           Show enrollment + cache status
 *   php bin/tigershield.php provision         Register a CAPI machine (mint + store credentials)
 *   php bin/tigershield.php enroll --key=XXX  Enroll into a CrowdSec console account (attachment key)
 */

error_reporting(E_ALL & ~E_DEPRECATED);

// Resolve the application root from this file: application/modules/tigershield/bin/ -> up 4.
$root = dirname(__DIR__, 4);
$autoload = $root . '/vendor/autoload.php';
if (!is_file($autoload)) {
    fwrite(STDERR, "tigershield: cannot find vendor/autoload.php (looked in {$root})\n");
    exit(1);
}
require $autoload;

try {
    (new Tiger_Application($root))->boot();
} catch (Throwable $e) {
    fwrite(STDERR, "tigershield: boot failed: " . $e->getMessage() . "\n");
    exit(1);
}

// Parse "command --key=value" args.
$argvv = $_SERVER['argv'];
array_shift($argvv);
$cmd   = array_shift($argvv) ?: 'status';
$flags = [];
foreach ($argvv as $a) {
    if (preg_match('/^--([^=]+)=(.*)$/', $a, $m)) { $flags[$m[1]] = $m[2]; }
    elseif (preg_match('/^--(.+)$/', $a, $m))     { $flags[$m[1]] = true; }
}

$cs = new Tigershield_Service_Crowdsec();

switch ($cmd) {
    case 'refresh':
        $r = $cs->refresh();
        if ($r['ok']) {
            echo "  ✓ CrowdSec cache refreshed: {$r['total']} decisions ({$r['ips']} IPs, {$r['ranges']} ranges).\n";
            exit(0);
        }
        fwrite(STDERR, "  refresh incomplete: " . ($r['error'] ?: 'unknown') . "\n");
        exit(1);

    case 'provision':
        if ($cs->ensureMachine()) { echo "  ✓ Machine registered with the CrowdSec CAPI.\n"; exit(0); }
        fwrite(STDERR, "  provision failed (check `status` → last error).\n");
        exit(1);

    case 'enroll':
        $key = is_string($flags['key'] ?? null) ? $flags['key'] : null;
        $res = $cs->enroll($key, is_string($flags['name'] ?? null) ? $flags['name'] : null);
        echo ($res['ok'] ? "  ✓ " : "  ✗ ") . $res['message'] . "\n";
        exit($res['ok'] ? 0 : 1);

    case 'status':
    default:
        $s = $cs->status();
        echo "  TigerShield · CrowdSec\n";
        echo "    enabled     : " . ($s['enabled'] ? 'yes' : 'no') . "\n";
        echo "    registered  : " . ($s['registered'] ? 'yes' : 'no') . "\n";
        echo "    enrolled    : " . ($s['enrolled'] ? 'yes (console)' : 'no') . "\n";
        echo "    blocklist   : " . $s['count'] . " decisions cached\n";
        echo "    last sync   : " . ($s['last_sync'] ? date('Y-m-d H:i:s', $s['last_sync']) : 'never') . "\n";
        if ($s['last_error']) { echo "    last error  : " . $s['last_error'] . "\n"; }
        exit(0);
}
