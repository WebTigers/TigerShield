# Changelog

All notable changes to TigerShield. Format follows [Keep a Changelog](https://keepachangelog.com);
this project uses [SemVer](https://semver.org) with a `-beta` stability suffix.

## [Unreleased]

## [0.6.0-beta] — 2026-07-16

### Added
- **Custom WAF rules (phase 5.1)** — a `tigershield_rule` store + a `/tigershield/admin/rules` editor
  (DataTables grid + create/edit modal). An admin authors their own signatures: match one request
  **surface** (path / query / path+query / User-Agent / method / **body**) by a literal substring or a
  regex, with the rule's **own action** (log / captcha / block — not tier-capped like the shipped soft
  heuristics). Rules run *after* the shipped ruleset (first match wins).
- **Cache-file architecture (no DB on the hot path)** — the DB is the source of truth; every write
  recompiles the active rules to `storage/cache/tigershield/waf-custom.json`, which the gate reads (with
  a one-shot lazy rebuild if missing) — the same "no I/O in the gate" discipline as the CrowdSec
  blocklist. `Tigershield_Service_Rules` (`datatable` / `save` / `toggle` / `delete`) recompiles on every
  mutation; regex rules are validated (must compile) on save.
- **POST-body scanning (opt-in)** — the content categories (traversal / RCE / SQLi / XSS) and any
  body-targeted custom rule also match form-field values. **Off by default** (`waf.body.enabled`) because
  legit fields carry rich content; a **skip list** (`waf.body.skip`, code-default of rich-content field
  names) plus always-skipped password / CSRF / captcha fields keep the false-positive rate down. A body
  custom rule turns body scanning on for itself even when the global toggle is off.

### Changed
- `Tigershield_Service_Waf::inspect()` now resolves the **action** itself (returns `{label, action}`);
  the gate uses it directly instead of re-deriving from tier. Body surface is built only when needed.

### Verified
- 17-assertion harness on tiger-dev: custom literal/regex matches + actions, disabled-rule skip, body
  scanning + skip-list + always-skip fields, shipped body categories, shipped-rule regression, and a
  benign-traffic battery — **0 false positives**.

## [0.5.0-beta] — 2026-07-16

### Added
- **Request WAF (phase 5)** — `Tigershield_Service_Waf` + `rules/default-waf.php`: a curated, high-signal
  rule engine that screens each request's **path / query / User-Agent / method** for attack signatures
  (sensitive-file & CMS probes, path traversal / LFI, command injection, null bytes, bad methods, scanner
  UAs, and — log-only — SQLi/XSS heuristics). Wired into the gate's `_decide` (runs last, skips assets).
- **9 per-category admin toggles** on the WAF card. High-confidence categories use `waf.action`
  (log / captcha / block); **soft SQLi/XSS heuristics are hard-capped at log-only** and never auto-block.
- A new `log` gate verdict (observe-only): recorded to the event log, never enforced even in enforce mode.

### Notes
- **v1 does not scan POST bodies** (the main false-positive source) — deferred to 5.1 along with a
  `tigershield_rule` custom-rule editor. Measured cost ~15µs/request (worst case); 0 false positives on a
  benign test battery.

## [0.4.0-beta] — 2026-07-16

### Added
- **Live Traffic view** (`/tigershield/admin/events`) — a server-side DataTables grid over the shield's
  event log (time, IP, country, action, reason, route) with a search box and an action filter. Fixes the
  dashboard widget's "View live traffic" link, which previously 404'd (the view didn't exist).
- `Tigershield_Model_Event::datatable()` + a real `Tigershield_Service_Events::datatable` (was a stub).
- **Dashboard widget — the "security is working" tables** (endpoint-security-plugin style): Top offending IPs (with
  geolocated country), Top countries, and Top targeted logins (account, tries, real-user flag) over the
  last 7 days — instead of a couple of stat numbers. Powered by `Event::topIps()`/`countSince()`,
  `Tiger_Model_Login::topFailures()` (tiger-core), and best-effort cached IP geolocation. Themed
  (light/dark) instead of hardcoded colors.

### Changed
- The dashboard widget now renders in the platform's dashboard grid (tiger-core ≥ 0.10.0-beta) with
  security-plugin-style chrome — the whole card header is the drag handle, with a collapse toggle.

## [0.3.0-beta] — 2026-07-16

### Added
- **Captcha gating (phase 4)** — `Tigershield_Service_Challenge`: a `captcha` verdict (CrowdSec
  captcha-remediation, or `login.action = captcha`) now shows an **interstitial challenge** instead of a
  flat block. Reuses Tiger's reCAPTCHA (v2 checkbox / v3 score); the gate presents the page, verifies the
  solved POST up front, and 302s the visitor back to their destination.
- **Signed clearance cookie** — a pass issues a short-lived, **HMAC-signed, IP-bound** cookie
  (`tigershield_clear`, no server-side state) that the gate honors to skip re-challenging that browser
  for a window (`captcha.window`, default 1h). Replay from another IP fails the signature.
- **Admin Captcha card** — provider status + the no-provider fallback policy, and (with tiger-core
  ≥ 0.9.0-beta) the reCAPTCHA controls themselves — enabled / version / site + secret key / min score /
  fail-open / hide-badge — saved through the shared `Tiger_Recaptcha::saveSettings()`; degrades to a
  status + link on an older platform. The interstitial honors the platform hide-badge setting.

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

[Unreleased]: https://github.com/WebTigers/TigerShield/compare/v0.5.0-beta...HEAD
[0.5.0-beta]: https://github.com/WebTigers/TigerShield/compare/v0.4.0-beta...v0.5.0-beta
[0.4.0-beta]: https://github.com/WebTigers/TigerShield/compare/v0.3.0-beta...v0.4.0-beta
[0.3.0-beta]: https://github.com/WebTigers/TigerShield/compare/v0.2.0-beta...v0.3.0-beta
[0.2.0-beta]: https://github.com/WebTigers/TigerShield/compare/v0.1.0-beta...v0.2.0-beta
[0.1.0-beta]: https://github.com/WebTigers/TigerShield/releases/tag/v0.1.0-beta
