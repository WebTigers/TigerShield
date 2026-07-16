# Changelog

All notable changes to TigerShield. Format follows [Keep a Changelog](https://keepachangelog.com);
this project uses [SemVer](https://semver.org) with a `-beta` stability suffix.

## [Unreleased]

### Added
- Public release under the **BSD 3-Clause** license.
- `TRADEMARKS.md` — trademark reservation split out of `LICENSE` so the license file is a clean,
  unmodified BSD-3-Clause grant (detected correctly by GitHub / SPDX tooling).
- `media/` store assets (icon, banner, screenshots) + `AGENTS.md`.
- Dashboard widget scaffold (`Tigershield_Widget_Shield`) — registers against the forthcoming Tiger
  dashboard-widget API when present; a no-op until then (FEATURES.md §15.6).

## [0.1.0-beta] — 2026-07-16

Initial scaffold + the first protection engines.

### Added
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

[Unreleased]: https://github.com/WebTigers/TigerShield/compare/v0.1.0-beta...HEAD
[0.1.0-beta]: https://github.com/WebTigers/TigerShield/releases/tag/v0.1.0-beta
