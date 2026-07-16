<?php
// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 WebTigers. Tiger™ and WebTigers™ are trademarks of WebTigers.
/**
 * Tigershield_Service_RateLimit — a fixed-window request counter for general per-request throttling.
 *
 * Internal engine (NOT a /api service — doesn't extend Tiger_Service_Service, so the gateway never
 * dispatches it). Needs a FAST, cross-worker counter store: **APCu** today (Redis later). Without one
 * it is a graceful **no-op** — general per-request limiting simply doesn't run (a DB write per request
 * would be worse than the disease), while login protection (audit-log based, no cache) still works.
 */
class Tigershield_Service_RateLimit
{
    /** Is a fast, cross-worker counter store present? (APCu; Redis later.) */
    public function available()
    {
        return function_exists('apcu_inc') && function_exists('apcu_fetch') && (bool) ini_get('apc.enabled');
    }

    /**
     * Count a hit against $key's current fixed window. Returns ['count' => int, 'over' => bool].
     * No-op (over=false) when there's no fast cache, or a non-positive limit/window.
     *
     * @param  string $key
     * @param  int    $limit
     * @param  int    $window seconds
     * @return array
     */
    public function hit($key, $limit, $window)
    {
        if (!$this->available() || $limit <= 0 || $window <= 0) {
            return ['count' => 0, 'over' => false];
        }
        $k = self::_bucketKey($key, $window);
        $success = false;
        $count = @apcu_inc($k, 1, $success, $window);
        if ($count === false || !$success) {          // first hit in this window → seed with the TTL
            @apcu_store($k, 1, $window);
            $count = 1;
        }
        return ['count' => (int) $count, 'over' => (int) $count > (int) $limit];
    }

    /** Read the current count for a key's window without incrementing. */
    public function peek($key, $window)
    {
        if (!$this->available() || $window <= 0) { return 0; }
        $v = @apcu_fetch(self::_bucketKey($key, $window));
        return $v === false ? 0 : (int) $v;
    }

    private static function _bucketKey($key, $window)
    {
        return 'tsrl:' . md5((string) $key) . ':' . (int) floor(time() / $window);
    }
}
