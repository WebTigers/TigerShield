# Changelog

All notable changes to TigerShield. Format follows [Keep a Changelog](https://keepachangelog.com);
this project uses [SemVer](https://semver.org) with a `-beta` stability suffix.

## [Unreleased]

## [0.3.0-beta] — 2026-07-16

### Added
- **Captcha gating (phase 4)** — `Tigershield_Service_Challenge`: a `captcha` verdict (CrowdSec
  captcha-remediation, or `login.action = captcha`) now shows an **interstitial challenge** instead of a
  flat block. Reuses Tiger's reCAPTCHA (v2 checkbox / v3 score); the gate presents the page, verifies the
  solved POST up front, and 302s the visitor back to their destination.
- **Signed clearance cookie** — a pass issues a short-lived, **HMAC-signed, IP-bound** cookie
  (`tigershield_clear`, no server-side state) that the gate honors to skip re-challenging that browser
  for a window (`captcha.window`, default 1h). Replay from another IP fails the signature.
- **Admin Captcha card** — provider status + the no-provider fallback policy.

### Security
- Redirect target is restricted to same-site paths (open-redirect + CRLF guarded).
- Fail-open: no provider configured → fall back per `captcha.fallback` (default allow); a reCAPTCHA
  outage honors reCAPTCHA's own `fail_open`.

## [0.2.0-beta] — 2026-07-16

### Added
- **CrowdSec CAPI client (phase 3)** — `Tigershield_Service_Crowdsec`: a dependency-free (no SDK)
  Central-API client that self-registers a machine, logs in for a short-lived JWT, pulls the community
  blocklist (decisions stream + downloadable blocklist links), and can enroll into a CrowdSec console
  and push signals back (opt-in). All plain curl + JSON.
- **Local decision cache** — `Tigershield_Service_Blocklist`: an atomic JSON file under
  `storage/cache/tigershield/` (memoized per request + mtime-keyed APCu warm on FPM); exact-IP O(1) plus
  CIDR v4/v6 matching. The firewall gate enforces `ban`→block / `captcha`→challenge from it — a pure
  cache lookup, never a network call on the hot path.
- **Out-of-band refresh** — a self-contained module CLI (`bin/tigershield.php refresh|status|provision|enroll`)
  for cron, plus a throttled, lock-guarded post-response (`fastcgi_finish_request`) lazy refresh for
  hosts without cron.
- **Admin CrowdSec card** — enable toggle, enrollment-key field, contribute-back opt-in, and a live
  status readout (registered / enrolled / cache size / last sync).

### Security
- CrowdSec machine credentials are stored **encrypted at rest** in the config tier (`Tiger_Crypto`);
  never plaintext in the DB, and no local.ini write required.
- Fail-soft throughout: any CAPI error leaves the last-good cache in place and never blocks the site.

## [0.1.0-beta] — 2026-07-16

Initial public release: scaffold + the first protection engines.

### Added
- Public release under the **BSD 3-Clause** license; `TRADEMARKS.md` split out of `LICENSE` (clean SPDX
  detection); `media/` store assets, `AGENTS.md`.
- Dashboard widget scaffold (`Tigershield_Widget_Shield`) — registers against the forthcoming Tiger
  dashboard-widget API when present; a no-op until then (FEATURES.md §15.6).
- **Front-controller firewall gate** (`Tigershield_Plugin_Firewall`) — runs before dispatch on every
  request, **fail-open**, ships in **learn mode** (logs, never blocks, until an operator enforces).
- **Login protection** — per-IP (distributed brute force) and per-account (credential stuffing)
  detection off Tiger's login audit log; works on any host, no cache needed. Complements Tiger's
  per-account lockout with a per-IP dimension.
- **Rate limiting** — general per-request fixed-window limiter (APCu-backed; a graceful no-op without
  it). A real 429 block page on enforce.
- **Admin Security screen** (`/tigershield/admin/settings`) — Mode / CrowdSec / Rate-limit / WAF cards,
  saved over `/api` to the config tier.
- **Event log** (`tigershield_event`) + timestamp-versioned migration.

### Decided
- **No CrowdSec SDK** — CAPI pull (blocklist) and push (`POST /signals`, contribute-back) are both plain
  REST via a built-in lightweight client. Keeps the shared-hosting footprint tiny and dependency-free.

[Unreleased]: https://github.com/WebTigers/TigerShield/compare/v0.3.0-beta...HEAD
[0.3.0-beta]: https://github.com/WebTigers/TigerShield/compare/v0.2.0-beta...v0.3.0-beta
[0.2.0-beta]: https://github.com/WebTigers/TigerShield/compare/v0.1.0-beta...v0.2.0-beta
[0.1.0-beta]: https://github.com/WebTigers/TigerShield/releases/tag/v0.1.0-beta
