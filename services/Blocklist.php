<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_Service_Blocklist — the LOCAL decision cache the gate reads (§10). This is the hot path:
 * the firewall gate calls lookup() on every request, so it must be microseconds and NEVER touch the
 * network. The CrowdSec client (Tigershield_Service_Crowdsec) fills it out-of-band; the gate only reads.
 *
 * Store = one atomic JSON file under storage/tigershield/ (the blessed writable runtime tree — survives
 * across FPM workers, unlike APCu, whose CLI and FPM pools are separate so a cron-written APCu cache is
 * invisible to the web). On FPM we additionally memo the decoded set in APCu keyed by the file's mtime,
 * so repeat requests are O(1) and a fresh file is picked up automatically. FAIL-OPEN: any read error →
 * empty set → every lookup returns null (allow).
 *
 * Internal engine (NOT a /api service).
 */
class Tigershield_Service_Blocklist
{
    /** @var array|null request-static memo of the decoded set */
    private static $_set = null;

    /** The cache file (authoritative durable store). */
    public static function file()
    {
        return self::dir() . '/blocklist.json';
    }

    /**
     * The module's writable runtime dir. Under storage/cache/ — the app-writable runtime subtree
     * (provisionStorage creates storage/cache; storage/ itself is often not writable by the web user).
     * Created on demand (setgid-inheriting group); fail-open if we can't.
     */
    public static function dir()
    {
        $root = defined('APPLICATION_ROOT') ? APPLICATION_ROOT : getcwd();
        $dir  = $root . '/storage/cache/tigershield';
        if (!is_dir($dir)) { @mkdir($dir, 0775, true); }
        // Ensure setgid + group-write so a cron user in the same group can also refresh the cache (the
        // process umask often strips the group-write bit off mkdir's mode; chmod isn't umask-masked).
        if (is_dir($dir) && (@fileperms($dir) & 0020) === 0) { @chmod($dir, 02775); }
        return $dir;
    }

    /**
     * Is $ip on the blocklist right now? Returns null (allow) or a decision:
     * ['type' => 'ban'|'captcha', 'scenario' => string, 'until' => int].
     */
    public function lookup($ip)
    {
        if ($ip === '' || $ip === null) { return null; }
        $set = $this->_load();
        if (!$set) { return null; }
        $now = time();

        // Exact IP — O(1). Stored as ip => [untilTs, type, scenario].
        if (isset($set['ips'][$ip])) {
            $d = $set['ips'][$ip];
            if ((int) $d[0] === 0 || (int) $d[0] > $now) {
                return ['type' => $d[1] ?? 'ban', 'scenario' => $d[2] ?? 'community blocklist', 'until' => (int) $d[0]];
            }
        }

        // CIDR ranges — few in practice; linear scan. Each: [network(bin), bits, untilTs, type, scenario].
        if (!empty($set['ranges'])) {
            $bin = @inet_pton($ip);
            if ($bin !== false) {
                foreach ($set['ranges'] as $r) {
                    if (((int) $r[2] !== 0 && (int) $r[2] <= $now)) { continue; }   // expired
                    $netBin = base64_decode((string) $r[0], true);
                    if ($netBin === false) { continue; }
                    if (self::_inCidrBin($bin, $netBin, (int) $r[1])) {
                        return ['type' => $r[3] ?? 'ban', 'scenario' => $r[4] ?? 'community blocklist', 'until' => (int) $r[2]];
                    }
                }
            }
        }
        return null;
    }

    /**
     * Replace the whole blocklist from a normalized decision list (full snapshot — we always pull the
     * CAPI stream with startup=true, so a full replace is correct and idempotent). Each item:
     * ['value' => ip-or-cidr, 'duration' => seconds, 'type' => 'ban'|'captcha', 'scenario' => string].
     * Returns ['ips' => int, 'ranges' => int, 'total' => int]. Atomic write; fail-open (returns zeros).
     */
    public function replace(array $decisions, array $meta = [])
    {
        $now  = time();
        $ips  = [];
        $ranges = [];
        foreach ($decisions as $d) {
            $value = trim((string) ($d['value'] ?? ''));
            if ($value === '') { continue; }
            $until = ((int) ($d['duration'] ?? 0) > 0) ? $now + (int) $d['duration'] : 0;
            $type  = ($d['type'] ?? 'ban') === 'captcha' ? 'captcha' : 'ban';
            $scen  = substr((string) ($d['scenario'] ?? 'community blocklist'), 0, 80);
            if (strpos($value, '/') !== false) {
                [$net, $bits] = explode('/', $value, 2);
                $bin = @inet_pton(trim($net));
                if ($bin === false) { continue; }
                // base64 the packed-binary network — raw bytes aren't valid UTF-8 and would make
                // json_encode() fail (returning false), silently losing the whole cache.
                $ranges[] = [base64_encode($bin), (int) $bits, $until, $type, $scen];
            } else {
                if (@inet_pton($value) === false) { continue; }
                $ips[$value] = [$until, $type, $scen];
            }
        }
        $set = [
            'v'      => 1,
            'ips'    => $ips,
            'ranges' => $ranges,
            'meta'   => array_merge(['synced_at' => $now, 'count' => count($ips) + count($ranges)], $meta),
        ];
        $ok = self::_writeAtomic($set);
        self::$_set = $ok ? $set : self::$_set;
        return ['ips' => count($ips), 'ranges' => count($ranges), 'total' => count($ips) + count($ranges), 'ok' => $ok];
    }

    /** Cache metadata (synced_at, count, …) for the admin status readout. */
    public function meta()
    {
        $set = $this->_load();
        return $set['meta'] ?? ['synced_at' => 0, 'count' => 0];
    }

    /** Number of cached decisions. */
    public function count()
    {
        $set = $this->_load();
        if (!$set) { return 0; }
        return count($set['ips'] ?? []) + count($set['ranges'] ?? []);
    }

    /** Wipe the cache (e.g. operator disabled CrowdSec). */
    public function clear()
    {
        @unlink(self::file());
        self::$_set = null;
    }

    // -- internals -----------------------------------------------------------------------------------

    /** Load the decoded set (request-static memo; mtime-keyed APCu warm on FPM). Fail-open → []. */
    private function _load()
    {
        if (self::$_set !== null) { return self::$_set; }
        $file = self::file();
        if (!is_file($file)) { return self::$_set = []; }

        $mtime = @filemtime($file) ?: 0;
        $apcu  = function_exists('apcu_fetch') && (bool) ini_get('apc.enabled');
        $akey  = 'tigershield:bl:' . $mtime;
        if ($apcu) {
            $hit = @apcu_fetch($akey);
            if (is_array($hit)) { return self::$_set = $hit; }
        }
        try {
            $raw = @file_get_contents($file);
            $set = $raw === false ? [] : json_decode($raw, true);
            if (!is_array($set)) { $set = []; }
        } catch (Throwable $e) {
            $set = [];
        }
        if ($apcu && $set) { @apcu_store($akey, $set, 3600); }
        return self::$_set = $set;
    }

    /** Atomic write: tmp file in the same dir + rename (atomic on the same filesystem). */
    private static function _writeAtomic(array $set)
    {
        $file = self::file();
        $json = json_encode($set);
        if ($json === false) { return false; }
        $tmp = $file . '.' . getmypid() . '.tmp';
        if (@file_put_contents($tmp, $json, LOCK_EX) === false) { return false; }
        if (!@rename($tmp, $file)) { @unlink($tmp); return false; }
        @chmod($file, 0664);
        return true;
    }

    /** Is a packed-binary IP inside network(bin)/bits? Works for v4 and v6 (same address family). */
    private static function _inCidrBin($ipBin, $netBin, $bits)
    {
        $len = strlen($ipBin);
        if ($len !== strlen($netBin)) { return false; }            // different family (v4 vs v6)
        if ($bits < 0) { return false; }
        $bytes = intdiv($bits, 8);
        $rem   = $bits % 8;
        if ($bytes > 0 && strncmp($ipBin, $netBin, $bytes) !== 0) { return false; }
        if ($rem === 0) { return true; }
        if ($bytes >= $len) { return true; }
        $mask = 0xFF << (8 - $rem) & 0xFF;
        return (ord($ipBin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask);
    }
}
