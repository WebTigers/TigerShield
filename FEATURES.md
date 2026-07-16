# TigerShield — Features & Design

*A plugin-layer web application firewall for Tiger, built for **shared hosting**: malicious-IP
blocking (CrowdSec), captcha gating, rate-limiting, and login protection — all at the PHP layer, with
no root and no daemon. One integrated shield instead of a stack of plugins.*

> **Status: design-of-record.** This records the decisions and the feature surface so we don't drift as
> the code lands. Built so far: the fail-open front-controller gate (learn mode), login protection,
> general rate limiting, the admin Security screen, and the events store (§15 phases 1–2). Everything
> below marked "planned" is the target. Free + BSD-licensed; see [CHANGELOG.md](CHANGELOG.md).

---

## 0. The one principle

**Everything happens at the PHP layer.** Endpoint security plugins prove the model — no root, no daemon,
no kernel modules, and still a real firewall, login security, and live traffic. TigerShield
is the same bet for Tiger: a front-controller **plugin** that gates every request *before* dispatch,
enforcing decisions computed from **cached** data. The shared-hosting CMS user ([[cpanel-hosting-
constraint]]) can't run the classic CrowdSec agent (a log-parsing daemon), so we never require one —
we consume CrowdSec's crowd-sourced intelligence over its **Central API (CAPI)**, cache it locally, and
enforce in pure PHP.

**Two non-negotiables that shape every decision below:**
1. **Fail-OPEN, always.** A security layer must never take the site down. Unreachable CrowdSec, a stale
   cache, a parse error, a slow network — every failure path **allows** the request (and logs it).
   Blocking is a *positive* decision from *fresh, local* data; absence of data is never a block. (We
   already learned this the hard way — the platform must survive its own guards.)
2. **Zero per-request network + tiny overhead.** The hot path is a **cache lookup**, never an API call.
   Blocklists refresh out-of-band (cron tick or a throttled lazy refresh); the gate itself is an
   in-memory/APCu set-membership test measured in microseconds. Security that adds latency gets turned
   off.

---

## 1. The shield in one request (the gate flow)

`Tigershield_Plugin_Firewall` runs at **`routeStartup`/`preDispatch`** (before the ACL gate, before any
controller). For each request, in order, short-circuiting on the first decision:

```
request → resolve real client IP (ALB/proxy-aware, reuses Tiger_Application::normalizeProxy)
        → allow-list?           → ALLOW (never touch trusted IPs / logged-in admins optionally)
        → hard block-list?      → 403 block page                       (manual, or country deny)
        → CrowdSec decision?    → ban → 403  |  captcha → challenge     (from the cached CAPI stream)
        → rate-limit exceeded?  → throttle → captcha → block            (per-IP + per-route buckets)
        → WAF rule match?       → block / log                          (injection/traversal/scanner sigs)
        → else                  → ALLOW (dispatch continues)
```

Every decision (allow-list hits excepted) writes a **row to the events log** (§10) for the live-traffic
view, and honors a global **learn/monitor mode** (log-only, block nothing) for a safe first run.

---

## 2. Feature surface (Tiger-native)

| Area | TigerShield | Reuses / builds on |
|---|---|---|
| **Malicious-IP blocking** | CrowdSec CAPI community blocklist, cached + enforced per request | §3, §5 |
| **Captcha gating** | Flagged-but-maybe-human IPs get a challenge, not a flat 403 | Tiger reCAPTCHA (`Tiger_Form_Element_Recaptcha`) |
| **Rate limiting** | Per-IP + per-route request buckets; throttle → captcha → block | lazy `option`/cache tier ([[config-discipline]]) |
| **Login protection** | Attempt limits, credential-stuffing throttle, 2FA-aware | existing brute-force lockout + login audit log |
| **Country / IP rules** | Allow/deny by IP, CIDR, or ISO country | `Tiger_Location` IP geolocation |
| **Request WAF** | Rule engine for common injection / traversal / scanner patterns | §7 |
| **Live traffic** | Real-time blocked/flagged/allowed events, filterable | admin shell + DataTables |
| **Dashboard widget** | at-a-glance shield status + recent blocks | Tiger dashboard widgets (module-registered) |
| **Learn / monitor mode** | Log-only first run so nothing false-positives your users offline | global config toggle |

---

## 3. CrowdSec integration — the shared-hosting way (BUILT 2026-07-16)

The crux: get CrowdSec's crowd-sourced threat intel onto a host that **can't run the agent**. Shipped in
§15 phase 3 — the shape below is what's implemented (`Tigershield_Service_Crowdsec` +
`Tigershield_Service_Blocklist`); credentials are stored **encrypted** in the config tier rather than
local.ini (so the web user needn't write local.ini), and the decision cache is the atomic JSON file
under `storage/cache/tigershield/` (the DB `tigershield_decision` table in §10 is deferred — the file
is the always-available store).

- **CAPI, not LAPI.** The classic setup is *agent* (parses logs → decisions) + *bouncer* (enforces). On
  shared hosting there's no agent. Instead we act as a **standalone bouncer** against the **Central API
  (CAPI)**: enroll a *watcher/machine*, obtain a token, and pull the **community blocklist** — the
  aggregated set of IPs the CrowdSec network is currently flagging.
- **Decision stream + local cache.** Pull `GET /decisions/stream` (a delta of new/expired decisions) on
  a schedule; merge into a **local cache** (a compact IP→decision map: file, APCu, or Redis if present).
  The gate reads only the cache. A decision carries a **type** (`ban` vs `captcha`) and a TTL, so
  expiry is automatic.
- **Refresh out-of-band.** A `bin/tiger tigershield:refresh` command (cron on capable hosts) or a
  **throttled lazy refresh** (at most once per N minutes, guarded by a lock file) on a live request —
  never on every request, never blocking the response.
- **Optional local signals feed back.** TigerShield's own detections (rate-limit trips, WAF hits, failed
  logins) can *locally* add short-lived decisions to the cache, so the shield reacts to an attack on
  *this* site immediately — without waiting for the community list. (Contributing signals *back* to
  CrowdSec's network — a `POST /signals` to the CAPI, **no SDK needed** (§5) — is a later, opt-in
  enhancement.)
- **Enrollment UX.** A no-shell operator pastes a CrowdSec **enrollment key** into Settings; the module
  registers the machine and stores the credentials in `local.ini`-style secret storage (never the DB in
  plaintext). Works with a free CrowdSec account.

---

## 4. Rate limiting (planned)

- **Buckets by (IP) and (IP + route-class).** A login POST, an `/api` call, and a page view have
  different sane limits; the classifier maps the request to a bucket.
- **Sliding-window counters** in the lazy scoped store (a `Tiger_Model_Option`-style tier / cache — NOT
  the eager `config` table; [[config-discipline]]). Cheap increment + read.
- **Escalation ladder, not a cliff.** Over soft limit → **slow** (tiny delay) or **captcha**; over hard
  limit → **block** for a cooldown. Captcha lets a real user through; a bot stalls.
- **Built on the audit substrate.** Login-specific limits read the existing login audit log (FEATURES:
  "the substrate for rate-limiting and anomaly detection"), so credential-stuffing is caught with data
  Tiger already records.

---

## 5. The CrowdSec client — built-in lightweight vs the SDK (a deliberate decision)

CrowdSec ships PHP libraries (`crowdsec/capi-client`, `crowdsec/bouncer-lib`), but they pull real deps
(HTTP client, Symfony cache/config, logger) — which fights Tiger's **tiny-pure-PHP, zero-build,
shared-hosting** ethos ([[install-distribution-model]]).

- **Default: a built-in lightweight CAPI client.** ~one class, **curl + JSON**, our own tiny file/APCu
  cache. No heavy deps, drops onto any shared host, matches the platform footprint. This is the shipped
  path — the CAPI surface we need (enroll, token, decisions stream) is small and stable.
- **No SDK dependency (decided 2026-07-16).** The whole CAPI surface we need is plain REST — enroll,
  obtain a token, `GET /decisions/stream` (pull the blocklist), and `POST /signals` (**contribute
  detections back** — §3). So the built-in client covers *both directions* with **no declared
  dependency**; the module's `module.json` carries no `crowdsec/*` requirement. The official SDK
  (`crowdsec/capi-client`) stays *documented as an option* an operator can add on a capable host (via
  `Tiger_Vendor`/`vendor-libs`, resolved off-box), and the bouncer is written against a small interface
  so the SDK can back it — but the plugin never requires it, which keeps the shared-hosting footprint
  tiny and the install dependency-free.

**Decision: ship the built-in lightweight client, no CrowdSec dependency.** Contribute-back does not
change this — it's just another REST endpoint.

---

## 6. Captcha gating (planned)

Blocking is blunt; a shared IP or a false-positive shouldn't 403 a real customer. So a `captcha`
decision (from CrowdSec, a rate-limit trip, or a WAF "suspicious" match) shows an **interstitial
challenge** instead:

- Reuses Tiger's **reCAPTCHA** (`Tiger_Form_Element_Recaptcha` + `Tiger_Validate_Recaptcha`) — v2
  checkbox or v3 score — config-driven, secret in `local.ini`. Pass → a short-lived **pass cookie/token**
  clears the IP for a window; fail/absent → stay challenged.
- Provider-agnostic seam so hCaptcha / Turnstile can slot in later (a `Tigershield_Challenge` interface).

---

## 7. The request WAF (planned)

A **rule engine** over the incoming request (URI, query, body, headers, UA) matching the common attack
classes an endpoint WAF covers:

- **Signatures:** SQLi, XSS, path traversal (`../`), PHP/LFI/RFI probes, known scanner user-agents,
  disallowed methods, oversized/garbage requests.
- **Rules as data.** A shipped default ruleset (a `rules/` file or seeded rows) + admin-editable
  enable/disable + custom rules, so it updates without a deploy (the live-override pattern).
- **Action per rule:** `block` | `captcha` | `log-only`. Ships mostly `log-only` on first install so it
  never false-positives a real site before the operator has watched the traffic (§0 fail-open ethos).
- **Never a bottleneck.** Rules run only after the (cheaper) IP checks pass, are compiled once, and are
  skipped entirely for allow-listed/static-asset requests.

---

## 8. Login protection (planned)

The single most-attacked surface. TigerShield hardens `/login` (`/auth/login`) specifically:

- **Attempt caps + throttle** per IP and per account (credential stuffing sprays many accounts from one
  IP — catch both dimensions), building on Tiger's existing lockout + audit log.
- **Captcha after N fails** on the login form (the reCAPTCHA element already supports this).
- **Optional country/allow-list for the admin login** (a common endpoint-firewall ask: "only let my country hit
  wp-admin").
- **2FA-aware:** never counts a legitimate post-password 2FA step as a failure.

---

## 9. Admin — settings page + shield dashboard (planned)

Built per Tiger's [ADMIN.md](https://github.com/WebTigers/Tiger) template (one shell, one save pattern):

- **Settings screen** (`/tigershield/admin/settings`) — cards for: **Mode** (Off / Learn / Enforce),
  **CrowdSec** (enroll key, refresh status + "last synced", blocklist size), **Rate limits** (the
  bucket thresholds), **Login protection**, **Country/IP rules**, **WAF ruleset** (toggle groups),
  **Captcha** (which provider). Saved over `/api` (validate → config tier), no deploy.
- **Live traffic / events** (`/tigershield/admin/events`) — a server-side DataTables grid of recent
  events (time, IP, country, action, reason, path), filterable by action — a "live traffic" view. Row actions: allow-list this IP, block this IP.
- **Dashboard widget** — a module-registered shield card (mode, blocks today, top offending IP, CrowdSec
  sync) on the main admin dashboard. TigerShield's side is built (`widgets/Shield.php` +
  `Bootstrap::_initDashboardWidget`); it registers only when the **platform** dashboard-widget API
  exists, so it's a safe no-op until that lands (§15.6 + the `backlog-dashboard-widgets` note).

---

## 10. Data model (planned)

Three tables (standard Tiger columns; migrations in `migrations/`):

| Table | Holds |
|---|---|
| `tigershield_event` | one row per blocked/flagged/captcha/allow-logged request: ip, country, action, reason, route, ua, at |
| `tigershield_rule` | WAF + IP/country rules: kind, pattern/target, action, enabled, source (`shipped`\|`user`) |
| `tigershield_decision` | the CrowdSec/local decision cache when APCu/Redis isn't available: ip/range, type, until |

The **decision cache** prefers APCu/Redis (fast, shared across FPM workers) and falls back to this table
+ a compact file so it works on the barest host. Events are pruned on a rolling window (config).

---

## 11. Performance & fail-open (the load-bearing constraints)

- **Gate cost budget: microseconds.** IP allow/block/decision checks are set-membership on a preloaded
  structure; the WAF only runs post-IP-checks and is compiled once. Static-asset and allow-listed
  requests skip the whole gate.
- **No network on the hot path.** CAPI is touched only by the refresh job/lazy-throttled tick, never by
  the gate.
- **Every failure ALLOWS.** Wrap the whole gate in a `Throwable` catch that logs and continues — a bug
  in TigerShield can never 500 or block the site. A kill-switch (`tiger.tigershield.enabled = 0`, config
  tier, live) disables the whole plugin instantly, and a `storage/.tigershield-off` file is the
  break-glass for a locked-out operator.

---

## 12. Config (live-override, per-org)

All settings live in the **`config` tier** (`tiger.tigershield.*`) — live-override, per-org capable, no
deploy ([[config-discipline]]) — *except* per-IP counters and the decision cache, which are hot,
high-churn state that belongs in the **lazy `option`/cache tier**, not the eager config table. Secrets
(the CrowdSec enrollment credentials) live in `local.ini`, never the DB in plaintext. Multi-tenant: the
shield can be tuned per-org (an org row overrides the global default), same mechanism as theming.

---

## 13. What the module ships (file layout)

```
TigerShield/                       (its own PUBLIC repo; installs as application/modules/tigershield/)
  module.json                      ; manifest (type via keywords: security/waf/plugin; pricing: free; BSD-3)
  FEATURES.md  TIGER.md  README.md  AGENTS.md  CHANGELOG.md  LICENSE  TRADEMARKS.md
  Bootstrap.php                    ; registers the firewall plugin + admin Settings entry + dashboard widget
  configs/  acl.ini  module.ini    ; admin-gated controller/services; defaults
  plugins/  Firewall.php           ; Tigershield_Plugin_Firewall — the front-controller gate (§1)
  services/ Settings.php Events.php ; /api: save settings (validate→config), events datatable
            Crowdsec.php RateLimit.php Waf.php   ; internal engines (NOT /api-dispatchable)
  models/   Event.php Rule.php Decision.php      ; the stores (§10)
  widgets/  Shield.php             ; Tigershield_Widget_Shield — the dashboard card (§15.6)
  migrations/ <timestamp>_create_tigershield_event.php   ; timestamp versions, never 0001 (§15.6 note)
  views/scripts/admin/ settings.phtml events.phtml
  assets/   css/ js/               ; the admin widget + challenge page (served via public/_<base> symlink)
  media/    icon-256.png banner-1544x500.png screenshot-*.png   ; store/listing art (not runtime)
  languages/en/tigershield.php     ; semantic keys (tigershield.*)
  rules/    default-waf.php        ; the shipped WAF ruleset (data, admin-overridable)
```

---

## 14. Rejected alternatives (so we don't relitigate)

| Rejected | Why | Chosen instead |
|---|---|---|
| Require the CrowdSec **agent** (daemon) | needs root + a long-running process — impossible on shared hosting | **CAPI standalone bouncer** (pure PHP, cached) |
| Per-request **CAPI call** in the gate | latency + a hard dependency on CrowdSec being up | cache-only gate; refresh out-of-band |
| Fail-**closed** (block on error/no-data) | a security bug or a CrowdSec outage would take the whole site down | **fail-open** always; blocking needs fresh local data (§0) |
| Ship the full **CrowdSec SDK** by default | heavy deps vs Tiger's tiny-pure-PHP shared-hosting footprint | built-in lightweight CAPI client; SDK opt-in behind an interface (§5) |
| Counters/decisions in the **`config` table** | hot, high-churn state pollutes the eager config load | lazy `option`/cache tier ([[config-discipline]]) |
| Block-only enforcement | false-positives 403 real customers | escalation ladder: allow → throttle → **captcha** → block |

---

## 15. Build order (phasing)

1. **Scaffold + the gate skeleton + events store** — the plugin registers, logs (learn mode), the admin
   Settings + events views render, migrations create the tables. *(This scaffold.)*
2. **Rate limiting + login protection** — **BUILT (2026-07-16).** Login protection reads the login
   audit log (`Tiger_Model_Login::recentFailuresFromIp`/`ForIdentifier`) — per-IP (distributed brute
   force) + per-account (credential stuffing), no cache, works on any host; complements Tiger's
   per-account lockout. General per-request rate limiting is APCu-backed (graceful no-op without it).
   Enforcement is a real 429 block page (learn mode logs only). No external dependency.
3. **CrowdSec CAPI client + cache + refresh** — **BUILT (2026-07-16).** `Tigershield_Service_Crowdsec`
   is a dependency-free CAPI client (register → login → `decisions/stream?startup=true` + downloadable
   blocklist links → optional `enroll` → optional `signals` push), all plain curl+JSON (no SDK).
   Machine credentials are stored **encrypted at rest** in the config tier (`Tiger_Crypto`; the key lives
   in local.ini) — no local.ini write needed, never plaintext in the DB. The community blocklist lands
   in `Tigershield_Service_Blocklist`, an atomic JSON file under `storage/cache/tigershield/` (memoized
   per-request + an mtime-keyed APCu warm on FPM; exact-IP O(1) + CIDR v4/v6 match). The gate's
   `_crowdsecDecision` is a pure cache lookup — `ban`→block, `captcha`→challenge — with its own
   `crowdsec.enabled` toggle (off by default, so zero cost until enrolled). Refresh runs **out of band**:
   a self-contained module CLI (`bin/tigershield.php refresh`, for cron) OR a throttled, lock-guarded
   `fastcgi_finish_request` lazy tick after the response (for no-cron hosts). Every network call is
   fail-soft; a CrowdSec outage leaves the last-good cache and never blocks the site.

   *Platform gap noted:* Tiger's console (`bin/tiger`) has **no module-command registry** — commands are
   a hardcoded switch in core, and a module shouldn't edit core. So the module ships its own CLI
   entrypoint. A future platform feature (a module command registry) would let `tigershield:refresh`
   live under `bin/tiger`; until then the module script + the lazy tick cover both host types.
4. **Captcha gating** — the interstitial challenge + pass-token, wired to reCAPTCHA.
5. **Request WAF** — the rule engine + shipped default ruleset (log-only first), admin toggles.
6. **Dashboard widget + polish** — the shield card, live-traffic filters, per-org tuning. *(Module side
   scaffolded; blocked on the platform dashboard-widget API — see §15.6.)*

### 15.6 Dashboard widget — module side built, platform side pending

The goal is WordPress-parity: a module surfaces its own at-a-glance card on the admin dashboard the same
way a WP plugin calls `wp_add_dashboard_widget()`. TigerShield's side is written and ready; the
**platform** registry + grid it plugs into **has not been built yet** (tracked in the
`backlog-dashboard-widgets` roadmap note — module-registered widgets, even-column widths, collapsible
drag-drop layout, per-user order in the lazy `option` tier).

**What the module ships now:**
- `widgets/Shield.php` — `Tigershield_Widget_Shield`: `title()`, `icon()`, `data()` (cheap, defensive,
  fail-open zero-state — mode, blocks today, events today, top IP, CrowdSec status), `render()`
  (self-contained card HTML), and `descriptor()` (the registration metadata: id, module, title, icon,
  widget class, ACL `resource`, grid `width`, `order`, `refresh`).
- `Bootstrap::_initDashboardWidget()` — registers the descriptor **only** `if (class_exists('Tiger_Dashboard'))`,
  so today it is a harmless no-op. Nothing to change here when the platform lands.

**What the platform must add (the ask for the `backlog-dashboard-widgets` build):**
- A **registry** — `Tiger_Dashboard::registerWidget(array $descriptor)` (module Bootstraps call it), and
  a dashboard controller/view that collects registered widgets, ACL-filters by each descriptor's
  `resource`, sorts by `order`, lays them out in the even-column grid, and renders each via its widget
  class (`data()`/`render()`), honoring `refresh` for client-side polling.
- Optional **`Tiger_Dashboard_Widget_Abstract`** base (caching of `data()`, `.phtml` partial rendering,
  a standard card chrome) — if it ships, `Tigershield_Widget_Shield` can `extends` it and drop its inline
  HTML; the descriptor shape stays the same, so it's non-breaking.
- The **descriptor contract** above is the interface to lock first; every module (not just TigerShield)
  registers against it.

---

## 16. Open questions (decide before build)

- **Default posture:** ship in **Learn mode** (log-only) so a new install never blocks a real user
  before the operator has watched traffic? (Recommended — safest, matches §0.)
- **CrowdSec enrollment:** free community CAPI only, or also support a paid CrowdSec subscription's
  richer feeds? And how to store the enroll key (Settings → `local.ini` secret) with no shell.
- **Cache backend detection:** APCu → Redis → table+file — auto-detect and pick the fastest present?
- **Contribute-back:** opt-in to push *this* site's detections back to CrowdSec's network (better
  community intel, but a privacy/disclosure decision).
- **Naming:** TigerShield vs TigerGuard vs TigerWAF (manifest currently `tigershield`).

---

*This document records decisions and their rationale. If you change a decision, update the relevant
section here in the same change — the "why" is the most valuable and most perishable part.*
