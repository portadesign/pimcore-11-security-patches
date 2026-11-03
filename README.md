# pimcore-11-security-patches

Security patches for `pimcore/pimcore` 11.5.4–11.5.14.1 and `pimcore/admin-ui-classic-bundle` 1.7.6–1.7.16, applied by [cweagans/composer-patches](https://github.com/cweagans/composer-patches) 2.

## Install

Needs Composer 2 and PHP ≥ 8.2. Not on Packagist.

```bash
composer config repositories.pimcore-11-security-patches vcs https://github.com/portadesign/pimcore-11-security-patches
composer config allow-plugins.cweagans/composer-patches true
composer config allow-plugins.portadesign/pimcore-11-security-patches true
composer require portadesign/pimcore-11-security-patches
bin/console cache:clear
```

Commit `composer.json`, `composer.lock` and `patches.lock.json`. Every `composer install`/`update` verifies the patches and re-applies them when needed.

- Composer 2.10+ blocks `pimcore/pimcore` because of open advisories: put the `config.policy` part of `audit-ignore.json` into `composer.json` before `composer require`.
- Project on `cweagans/composer-patches` 1.x: `composer remove cweagans/composer-patches`, delete `patches.lock.json`, then the steps above.

## Patches

| CVE | Package | What changes |
| --- | --- | --- |
| CVE-2026-27461 | pimcore | Dependency filter value is bound as a parameter (literal substring match, no `RLIKE`) |
| CVE-2026-55634 | pimcore | `Data::setName()` accepts only `^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`; classification store key names stay free text |
| CVE-2026-11407, CVE-2026-115894 | pimcore | Twig sandbox policy: blocked classes (user, token, session, request bags, DAO, listings, DBAL, PDO, container, kernel, process, Twig, class/brick/field-collection/custom-layout definitions), blocked `pimcore_*` functions that read files or dump objects, no static calls or `__call` forwarding on models, hard-blocked mutators (`save*`, `delete*`, `set*`, …) and secret getters. `objectTypes` arguments restricted to object/variant/folder; array thumbnail configs rejected in a sandbox. Config: `pimcore.templating_engine.twig.sandbox_security_policy.{blocked_classes,allowed_classes,blocked_functions,hard_blocked_methods}` |
| CVE-2026-5394 | pimcore | Composite index keys `^[a-zA-Z0-9_+-]{1,64}$` and columns `^[a-zA-Z][a-zA-Z0-9_-]{0,63}$` checked before SQL; empty key skipped with a warning |
| CVE-2026-44739 | pimcore | Custom report SQL keyword guard sees through comments |
| CVE-2026-55416 | pimcore | Report fragments may not contain `;`, `#`, `--`, `/* */`, `INTO OUTFILE`, `INTO DUMPFILE`, `LOAD_FILE(` outside quotes or start with a write statement; filter/sort/drill-down fields are quoted |
| CVE-2026-55220, CVE-2026-45162 | pimcore | `unserialize()` with class allowlists where data comes from the database or files (Site, CustomLayout, TmpStore, Hotspotimage, WebDAV delete log, Table, Block, editables, Link, Geo, asset custom settings, SEO error log); Version, Recyclebin, Hardlink upcast and EncryptedField stay unrestricted by design. Session elements in `tmp_store` are HMAC-signed, so editors open during the deploy lose unsaved edits once. Config: `pimcore.tmp_store.unserialize_allowed_classes`. Legacy Block/Video data or custom settings holding other objects load as incomplete classes; a WebDAV delete-log entry holding other objects is dropped, so the restore creates an asset with a new ID |
| CVE-2026-58401 | pimcore | Admin session token class allowlist. Config: `pimcore.security.session_token_allowed_classes` |
| CVE-2026-55072 | pimcore | Class definition ID regex anchored (`/D`), name checked, `Block::load()` quotes table names |
| CVE-2026-45260 | pimcore | WebDAV MOVE needs `create` on the destination, `publish` on the asset, `delete` when overwriting/restoring, `rename` for a rename; a failed save returns 500 |
| CVE-2026-45703 | pimcore | WordExport skips elements the user may not `view` (no 403) |
| CVE-2026-45704 | pimcore | Custom report detail, data, chart, drill-down and CSV endpoints enforce the listing sharing rule; `reports_config` users and admins keep full access |
| CVE-2026-44741 | admin-ui-classic-bundle | Translation grid filter: column allowlist, quoted identifiers |
| CVE-2026-45162 | admin-ui-classic-bundle | Dashboard config deserialised without classes |

All patches are verified on 11.5.4, 11.5.14.1 / 1.7.6, 1.7.16. Each patch file starts with a header (CVE, advisory, verified versions, summary).

## Scanners

- Composer: copy `audit-ignore.json` into `composer.json` `config` (`audit.ignore`, and `policy.advisories.ignore-id` on 2.10+).
- Trivy: `vex.openvex.json` (OpenVEX, matches the `composer.lock` PURL with and without the `v` prefix) hides every CVE above.

```yaml
# GitHub Actions
- uses: aquasecurity/trivy-action@0.28.0
  with: { scan-type: fs, scan-ref: ., scanners: vuln, severity: "HIGH,CRITICAL", exit-code: "1" }
  env:
    TRIVY_VEX: vendor/portadesign/pimcore-11-security-patches/vex.openvex.json
```

```yaml
# trivy.yaml for CLI runs
vulnerability:
  vex: [vendor/portadesign/pimcore-11-security-patches/vex.openvex.json]
```

Without `vendor/` in CI, copy `vex.openvex.json` into the project and point `TRIVY_VEX` there. Both lists hold only while the package is installed and its patches are applied.

## Maintain

- `./verify.sh [pimcore-tag] [admin-ui-tag]`: every patch applies to pristine release tarballs (needs `gh`); CI runs it on push and weekly.
- New patch: failing test in `tests/`, patch with header, entry in `extra.patches`, table row, `./verify.sh`.
- Status in `advisories.json`; `php bin/build-vex.php` regenerates `vex.openvex.json` and `audit-ignore.json`.
- Release: `./release.sh <version>` (pins patch URLs to the tag, syncs `sha256`, rebuilds the VEX, commits, tags, pushes).

## Tests

Exploit tests need a host project with a database (dist install omits `tests/`: clone the repo or `composer reinstall portadesign/pimcore-11-security-patches --prefer-source`). They create and remove their own fixtures.

```bash
T="-c vendor/portadesign/pimcore-11-security-patches/phpunit.xml.dist"; vendor/bin/phpunit $T
(cd vendor/pimcore/pimcore && git apply -R ../../portadesign/pimcore-11-security-patches/patches/pimcore-CVE-2026-27461-dependency-rlike.patch) && vendor/bin/phpunit $T --group CVE-2026-27461   # must fail
composer patches-repatch && vendor/bin/phpunit $T --group CVE-2026-27461   # must pass
```

Plugin unit tests: `vendor/bin/phpunit -c phpunit.unit.xml.dist`.
