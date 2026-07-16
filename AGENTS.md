# AGENTS.md — TigerShield

Orientation for AI agents (and humans) working in this repo. Read this first, then
[`FEATURES.md`](FEATURES.md) — the design-of-record. If you change a decision, update FEATURES.md in the
same change; the "why" is the most perishable part.

## What this is

A **Tiger module** — a plugin-layer web application firewall. It installs as
`application/modules/tigershield/` inside a Tiger app and self-registers via the module scan. It is
pure PHP at the front-controller layer: **no root, no daemon, no build step** (built for shared
hosting). See [`README.md`](README.md) for the pitch, [`module.json`](module.json) for the manifest.

## Invariants — do not break these

- **Fail-OPEN, always.** Any error, outage, missing data, or bug **allows** the request (and logs it).
  Blocking is a *positive* decision from *fresh, local* data — never a side effect of a failure. The
  whole gate is wrapped in a `Throwable` catch (`plugins/Firewall.php`). A security layer must never
  take the site down.
- **Learn mode is the default.** A fresh install logs (`observed`) but blocks nothing until an operator
  flips `tiger.tigershield.mode` to `enforce`. Never change the shipped default to `enforce`.
- **No per-request network.** The hot path is a cache/DB-audit lookup, never a live API call. CrowdSec
  CAPI is touched only by an out-of-band refresh.
- **No heavy dependencies.** No CrowdSec SDK — CAPI pull *and* push (`POST /signals`) are plain REST via
  a built-in lightweight client (FEATURES.md §5). `module.json` carries no `crowdsec/*` requirement.
  Keep the shared-hosting footprint tiny and pure-PHP. Modules never phone home to third parties; the
  disclosed, opt-in exception is CrowdSec's CAPI (a security feed), documented in Settings.
- **Kill-switch / break-glass.** `tiger.tigershield.enabled = 0` (config, live) disables the plugin
  instantly; a `storage/.tigershield-off` file is the break-glass for a locked-out operator.

## Platform conventions (Tiger-native)

- **Migrations use timestamp versions** (`YYYYMMDDHHMMSS_*.php`), never `0001` — the `tiger_migration`
  ledger is one shared bare-version namespace across core + app + all modules, so `0001` collides with
  core's and silently no-ops.
- **`Tiger_Model_Table` subclasses must declare `protected $_primary = '<pk>'`** or the UUID mint
  targets the wrong column and the insert throws.
- **Services** validate → transaction; save over `/api` writing to the `config` tier
  (`$config->set('global', '', $key, $value)` — 4 args). Hot per-IP counters live in APCu / the lazy
  `option` tier, **never** the eager `config` table.
- **Forms** are `Zend_Form` built from array config; **i18n** keys are semantic (`tigershield.*`).
- **ACL:** only the admin surface (controller + `/api` services) is an ACL resource; the firewall gate
  is a front-controller plugin that runs for everyone before the ACL and needs no rule.

## Dev / test loop

It's a plain module — drop it into a Tiger app's `application/modules/tigershield/`, run
`vendor/bin/tiger migrate`, and it self-registers (the Security screen appears under admin Settings).
The dev/test host is **tiger-dev** (deploy code there only; operate as `ec2-user`, no root/sudo). Keep
the box in **learn mode** and clean up any seeded `login` / `tigershield_event` rows after testing.

## Layout

```
Bootstrap.php            registers the firewall plugin + admin Settings entry + dashboard widget
plugins/Firewall.php     Tigershield_Plugin_Firewall — the front-controller gate (fail-open)
services/                RateLimit (APCu), Settings (/api save), Events (/api datatable),
                         Crowdsec (CAPI client — no SDK), Blocklist (local decision cache the gate reads)
models/Event.php         the event log store (UUID PK, standard columns)
widgets/Shield.php        the dashboard widget (blocked on the platform widget API — see FEATURES §15.6)
bin/tigershield.php      module CLI (cron): refresh | status | provision | enroll — no module cmd registry
migrations/              timestamp-versioned schema
configs/  acl.ini module.ini
views/scripts/admin/     settings + events screens
languages/en/            semantic tigershield.* keys
media/                   store/marketing art (icon, banner, screenshots)
storage/cache/tigershield/  runtime cache (blocklist.json, token.json, refresh.lock) — NOT committed
```
