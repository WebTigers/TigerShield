# TigerShield — Features & Design

*A plugin-layer web application firewall for Tiger, built for **shared hosting**: malicious-IP
blocking (CrowdSec), captcha gating, rate-limiting, and login protection — all at the PHP layer, with
no root and no daemon. One integrated shield instead of a stack of plugins.*

> **Status: v1 built (v0.6.0-beta).** All six build phases have shipped: the fail-open front-controller
> gate (learn mode), login protection + rate limiting, the CrowdSec CAPI client + cached blocklist,
> captcha gating, the request WAF (v1 + custom rules + opt-in body scanning), the admin Security screen +
> Live Traffic, and the dashboard shield card. Remaining items are explicitly deferred (§16: per-row
> allow/deny on Live Traffic, per-org tuning). Free + BSD-licensed; see [CHANGELOG.md](CHANGELOG.md).

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

## 4. Rate limiting (BUILT 2026-07-16)

Two independent limiters (`Tigershield_Service_RateLimit` + the gate), both fail-open and learn-mode-aware:

- **Login protection** reads Tiger's **login audit log** (`Tiger_Model_Login`) — per-**IP** (distributed
  brute force) and per-**account** (credential stuffing), each with its own threshold/window. No cache
  required, so it works on any host; complements Tiger's own per-account lockout, and is **2FA-aware** (a
  legitimate post-password 2FA step is never counted as a failure). `login.action` = `block` (429) or
  `captcha`.
- **General per-request rate limiting** — **APCu-backed** fixed-window counters keyed by IP, a graceful
  no-op where APCu isn't present (no hard dependency). Over the limit → the configured action.
- **Enforcement is a real 429** block page; **learn mode logs only**. No external dependency.

Deferred (§16): route-class buckets and an optional per-admin country/allow-list.

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

## 6. Captcha gating (BUILT 2026-07-16)

Blocking is blunt; a shared IP or a false-positive shouldn't 403 a real customer. So a `captcha`
decision (from CrowdSec captcha-remediation, or `login.action = captcha`) shows an **interstitial
challenge** instead — `Tigershield_Service_Challenge`, wired into the gate's `_challenge`:

- Reuses Tiger's **reCAPTCHA** (`Tiger_Recaptcha`) — v2 checkbox or v3 score — config-driven
  (`tiger.recaptcha.*`), secret in `local.ini`. The gate handles the whole flow inline (like `_block`):
  present the interstitial → the visitor solves → the POST is verified up front in `routeStartup`.
- On a pass, a short-lived **HMAC-signed, IP-bound clearance cookie** (`tigershield_clear`) is issued —
  no server-side state, works on the barest host — and the visitor is 302'd back to their destination
  (open-redirect + CRLF guarded). The gate skips the challenge for any request carrying a valid cookie.
  A stolen cookie replayed from another IP fails the signature. Window is `captcha.window` (default 1h).
- **Fail-open:** no provider configured → a `captcha` verdict falls back per `captcha.fallback`
  (default `allow`); a reCAPTCHA transport outage honors reCAPTCHA's own `fail_open`.
- Provider-agnostic seam: `Tigershield_Service_Challenge` (available / verify / interstitial) — hCaptcha
  / Turnstile slot in behind the same three methods (the form already also reads `h-captcha-response`).

---

## 7. The request WAF (BUILT 2026-07-16 — v1 + 5.1)

A **rule engine** over the incoming request (`Tigershield_Service_Waf` + `rules/default-waf.php`) matching
the common attack classes an endpoint WAF covers. A curated, high-signal ruleset, not a ModSecurity-CRS
port. Measured cost: **~15µs/request** (worst case — a benign request running the whole ruleset).
Validated: attack classes caught, **0 false positives** on a benign battery. What shipped:

- **Signatures:** SQLi, XSS, path traversal (`../`), PHP/LFI/RFI probes, known scanner user-agents,
  disallowed methods, null bytes / control chars.
- **Surfaces:** path / query / path+query / User-Agent / method — and, **opt-in, the POST body** (5.1).
  Body scanning is off by default (`waf.body.enabled`) because legit form fields carry the very content
  the content-categories look for; a **skip list** (`waf.body.skip`, code-default of rich-content field
  names) plus always-skipped password / CSRF / captcha fields keep the false-positive rate down.
- **Rules as data.** The shipped `rules/default-waf.php` ruleset (per-category live enable/disable) **plus
  admin-authored custom rules** (5.1) — a `tigershield_rule` store + a `/tigershield/admin/rules` editor.
  A custom rule matches one surface by literal substring or regex and carries its own action. The DB is
  the source of truth; the gate reads a **compiled cache file** (`waf-custom.json`), rebuilt on every
  write — no DB query on the hot path (the CrowdSec-blocklist discipline). Custom rules run after the
  shipped ruleset (first match wins).
- **Action per rule:** `block` | `captcha` | `log` (observe-only). Shipped high-confidence categories use
  `waf.action`; the soft SQLi/XSS heuristics are hard-capped to log-only; custom rules carry their own
  action, un-capped. Ships `log` on first install so it never false-positives a real site before the
  operator has watched the traffic (§0 fail-open ethos).
- **Never a bottleneck.** Rules run only after the (cheaper) IP checks pass, are compiled once, and are
  skipped entirely for allow-listed/static-asset requests.

---

## 8. Login protection (BUILT 2026-07-16)

The single most-attacked surface, hardened at `/auth/login` (this is the login half of the §4 limiter):

- **Attempt caps + throttle** per IP and per account, from Tiger's login audit log; complements the
  platform's per-account lockout.
- **Captcha after N fails** (`login.action = captcha`) — the reCAPTCHA path in §6.
- **2FA-aware:** never counts a legitimate post-password 2FA step as a failure.

Deferred (§16): an optional country/allow-list for the admin login ("only let my country hit the admin").

---

## 9. Admin — settings page + shield dashboard (BUILT 2026-07-16)

Built per Tiger's [ADMIN.md](https://github.com/WebTigers/Tiger) template (one shell, one save pattern):

- **Settings screen** (`/tigershield/admin/settings`) — cards for: **Mode** (Off / Learn / Enforce),
  **CrowdSec** (enroll key, refresh status + "last synced", blocklist size), **Rate limits**, **WAF
  ruleset** (per-category toggles + body scanning + a link to the custom-rule editor), **Captcha**.
  Saved over `/api` (validate → config tier), no deploy.
- **Custom-rule editor** (`/tigershield/admin/rules`) — a DataTables grid + create/edit modal for
  admin-authored WAF rules (§7 / 5.1).
- **Live traffic / events** (`/tigershield/admin/events`) — a server-side DataTables grid of recent
  events (time, IP, country, action, reason, route), filterable by action. **Read-only** — per-row
  allow-list / block-this-IP actions are deferred (they land with a manual allow/deny store; see §16).
- **Dashboard widget** — a module-registered shield card (mode, blocks today, top offending IP, CrowdSec
  sync). Registers via `Bootstrap::_initDashboardWidget` when `Tiger_Dashboard` is present — which
  **shipped in tiger-core 0.10.0-beta** — so the card now renders live on the admin dashboard grid.

---

## 10. Data model (BUILT — event + rule; decision table not needed)

Standard Tiger columns; migrations in `migrations/` (timestamp-versioned):

| Table | Holds |
|---|---|
| `tigershield_event` (BUILT) | one row per blocked/flagged/captcha/allow-logged request: ip, country, action, reason, route, ua, at |
| `tigershield_rule` (BUILT 5.1) | admin custom WAF rules: label, target (surface), match_type (`contains`\|`regex`), pattern, action, enabled, sort_order |
| ~~`tigershield_decision`~~ (dropped) | not built — the CrowdSec blocklist lives in an atomic JSON **file cache** (`Tigershield_Service_Blocklist`, memoized + APCu-warmed), which serves the gate with no DB row at all |

Events are pruned on a rolling window (config).

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
  services/ Settings.php Events.php Rules.php ; /api: save settings, events datatable, custom-rule CRUD
            Crowdsec.php RateLimit.php Waf.php   ; internal engines (NOT /api-dispatchable)
  models/   Event.php Rule.php Decision.php      ; the stores (§10)
  widgets/  Shield.php             ; Tigershield_Widget_Shield — the dashboard card (§15.6)
  migrations/ <timestamp>_create_tigershield_event.php <timestamp>_create_tigershield_rule.php   ; timestamp versions, never 0001
  views/scripts/admin/ settings.phtml events.phtml rules.phtml
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
4. **Captcha gating** — **BUILT (2026-07-16).** `Tigershield_Service_Challenge` + the gate's
   `_challenge`/`_handleChallenge`: an interstitial (reCAPTCHA v2/v3), a solved POST verified up front,
   and an HMAC-signed, IP-bound clearance cookie that skips re-challenging for a window. Fail-open
   (fallback allow / provider fail-open). Provider-agnostic seam for hCaptcha/Turnstile. See §6.
5. **Request WAF** — **BUILT (2026-07-16, v1 + 5.1).** `Tigershield_Service_Waf` + `rules/default-waf.php`:
   9 curated categories over path/query/UA/method, per-category admin toggles, high-confidence →
   `waf.action`, soft SQLi/XSS heuristics capped at log-only. ~15µs/request, 0 FP on the benign battery.
   **5.1:** admin custom rules (`tigershield_rule` + `/tigershield/admin/rules` editor, compiled to a
   `waf-custom.json` cache the gate reads — no DB on the hot path) + opt-in POST-body scanning with a
   skip list. 17-assertion harness green.
6. **Dashboard widget + polish** — **BUILT (2026-07-16).** The shield card renders on the platform
   dashboard grid (the platform API landed — see §15.6) and the live-traffic view has an action filter.
   Deferred (not creep for v1): per-row allow/deny actions on Live Traffic + per-org tuning (§16).

### 15.6 Dashboard widget — BUILT (platform API shipped in tiger-core 0.10.0-beta)

The goal was WordPress-parity: a module surfaces its own at-a-glance card on the admin dashboard the same
way a WP plugin calls `wp_add_dashboard_widget()`. **Both sides now exist** — the platform registry + grid
shipped in **tiger-core 0.10.0-beta** (`Tiger_Dashboard` + the lazy `Tiger_Model_Option` layout store +
the Muuri drag-drop grid), so TigerShield's card renders live.

**What the module ships:**
- `widgets/Shield.php` — `Tigershield_Widget_Shield`: `title()`, `icon()`, `data()` (cheap, defensive,
  fail-open zero-state — mode, blocks today, events today, top IP, CrowdSec status), `render()`
  (self-contained card HTML), and `descriptor()` (registration metadata: id, module, title, icon, widget
  class, ACL `resource`, grid `width`, `order`, `refresh`).
- `Bootstrap::_initDashboardWidget()` — registers the descriptor `if (class_exists('Tiger_Dashboard'))`.
  On tiger-core ≥ 0.10.0-beta that's now true, so the card appears; on an older core it stays a harmless
  no-op. Nothing to change here.

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
