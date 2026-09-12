# TigerShield

A plugin-layer web application firewall for [Tiger](https://github.com/WebTigers/Tiger) — CrowdSec
malicious-IP blocking, captcha gating, rate-limiting, and login protection, all at the PHP layer (no
root, no daemon). Built for shared hosting.

> **Free, first-party, BSD-licensed.** One integrated shield instead of a stack of plugins. The full
> design + feature scope is in [FEATURES.md](FEATURES.md); notable changes are in [CHANGELOG.md](CHANGELOG.md).

## What's in it

- The **fail-open front-controller gate** — it ships in **learn mode**, logging everything and blocking
  nothing until you switch it to enforce.
- **Login protection** — per-IP and per-account, off Tiger's login audit log.
- **Rate limiting** — sliding-window buckets in APCu.
- **CrowdSec malicious-IP blocking** — a built-in CAPI client (no agent, no SDK, no root), cached
  locally and enforced as a pure lookup.
- **Captcha gating** — an interstitial and a signed clearance cookie instead of a flat block, so a
  suspicious-but-human visitor is challenged rather than locked out.
- **The request WAF** — a curated ruleset, log-only by default.
- The admin **Security** screen, the event log, and the dashboard widget.

See [FEATURES.md](FEATURES.md) for the design of record.

## Dev

It's a Tiger **module** — it installs as `application/modules/tigershield/`. Drop it into a Tiger app's
modules dir (dev), run `vendor/bin/tiger migrate`, and it self-registers (module scan). The Security
screen appears under admin Settings.

## License

[BSD 3-Clause](LICENSE) © 2026 WebTigers. Use, modify, and redistribute freely; the Tiger / TigerShield
/ WebTigers trademarks are reserved — see [TRADEMARKS.md](TRADEMARKS.md).
