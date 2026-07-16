# media/ — store & marketing assets

The visual identity for TigerShield's listing surfaces. These are **not** runtime assets (the module's
admin CSS/JS lives under `assets/`); they're the art the platform and the marketplace show *about* the
module — the WordPress `/assets` convention, adapted for Tiger.

## Where they surface

- **The Module Installer card** — Tiger shows the icon + banner alongside the [`TIGER.md`](../TIGER.md)
  pitch before an operator installs.
- **The Vendors / module marketplace listing** ([module-taxonomy-registry]) — icon, banner, screenshots.
- **The GitHub repo social preview** — the banner.

Referenced by the `media` block in [`module.json`](../module.json).

## Spec (drop the files here; keep the exact names)

| File | Size | Purpose |
|---|---|---|
| `icon-256.png` | 256×256 | primary icon (installer, listing, favicons) |
| `icon-128.png` | 128×128 | small icon (compact lists) |
| `banner-1544x500.png` | 1544×500 | retina banner (listing header, social preview) |
| `banner-772x250.png` | 772×250 | standard banner |
| `screenshot-1.png` … | ~1280 wide | admin Security screen, live-traffic view, dashboard widget |

Guidance: PNG (or SVG for the icon if you also export a PNG), transparent where it helps, the shield
mark on-brand with the rest of Tiger. Name screenshots in display order; caption them in `module.json`
or the listing. Keep files reasonably small — they ship in the repo and the module bundle.

> **Placeholders for now.** Real art is a design task (see the theme/brand backlog). Until the files
> exist, the installer/listing fall back to the name + `TIGER.md` text — nothing breaks.
