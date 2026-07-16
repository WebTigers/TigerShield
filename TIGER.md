# TigerShield

*Your site's shield — an all-in-one firewall for Tiger. Blocks malicious IPs, throttles
brute-force logins, screens requests, and challenges the suspicious with a captcha — all at the PHP
layer, on any shared host. One integrated shield instead of a stack of plugins.*

> **`TIGER.md` is the vendor description** — the pitch the Module Installer shows before you install.
> The machine-readable manifest is [`module.json`](module.json); the full design is
> [`FEATURES.md`](FEATURES.md).

## What it does

- **Blocks known-malicious IPs** using **CrowdSec's** crowd-sourced blocklist — pulled over the API and
  cached locally, so it works with **no agent and no root** (the CrowdSec agent needs a server daemon;
  TigerShield doesn't).
- **Protects your login** — attempt limits + credential-stuffing throttle, 2FA-aware, building on
  Tiger's existing lockout + audit log.
- **Rate-limits abuse** — throttle → captcha → block, so a bot stalls while a real visitor sails through.
- **Screens every request** — a firewall ruleset for the common injection / traversal / scanner attacks.
- **Challenges, doesn't just block** — a suspicious-but-maybe-human visitor gets a captcha, not a flat
  403, so you don't lock out real customers.
- **Shows you the traffic** — a live view of blocked / flagged / allowed events + a dashboard shield card.

## Built for shared hosting

Everything runs in PHP — no root, no daemon, no build step. It **fails open**: if anything goes wrong,
requests are allowed, never dropped. A kill-switch (and a break-glass file) can disable it instantly.

## Features

| | |
|---|---|
| **CrowdSec IP blocking** | Community blocklist over the API, cached locally — no agent/root. |
| **Login protection** | Attempt caps + throttle, per-IP and per-account, 2FA-aware. |
| **Rate limiting** | Sliding-window buckets; throttle → captcha → block. |
| **Request WAF** | Rules for SQLi / XSS / traversal / scanner probes; log, challenge, or block. |
| **Captcha gating** | reCAPTCHA challenge for the flagged, instead of a hard block. |
| **Live traffic** | Real-time, filterable event log + a dashboard shield widget. |
| **Learn mode** | Log-only first run, so it never false-positives your users before you're ready. |

## Requirements

- Tiger ≥ 0.8.0-beta, PHP ≥ 8.1 (see [`module.json`](module.json)).

## License

**Free** and **BSD 3-Clause** — a first-party module, yours to use, modify, and redistribute. The
Tiger / TigerShield / WebTigers trademarks are reserved. See [LICENSE](LICENSE).
