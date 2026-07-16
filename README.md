# TigerShield

A plugin-layer web application firewall for [Tiger](https://github.com/WebTigers/Tiger) — CrowdSec
malicious-IP blocking, captcha gating, rate-limiting, and login protection, all at the PHP layer (no
root, no daemon). Built for shared hosting.

> **Free, first-party, BSD-licensed.** One integrated shield instead of a stack of plugins. The full
> design + feature scope is in [FEATURES.md](FEATURES.md); notable changes are in [CHANGELOG.md](CHANGELOG.md).

## Status

**Early beta.** Built and shipping: the fail-open front-controller gate (ships in **learn mode**),
**login protection** (per-IP + per-account, off Tiger's login audit log), general **rate limiting**
(APCu), the admin Security screen, and the event log. Landing next, per the build phases in
[FEATURES.md §15](FEATURES.md): CrowdSec CAPI → captcha gating → request WAF → dashboard widget.

## Dev

It's a Tiger **module** — it installs as `application/modules/tigershield/`. Drop it into a Tiger app's
modules dir (dev), run `vendor/bin/tiger migrate`, and it self-registers (module scan). The Security
screen appears under admin Settings.

## License

[BSD 3-Clause](LICENSE) © 2026 WebTigers. Use, modify, and redistribute freely; the Tiger / TigerShield
/ WebTigers trademarks are reserved — see [TRADEMARKS.md](TRADEMARKS.md).
