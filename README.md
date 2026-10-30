# pimcore-11-security-patches

Backports of public Pimcore 2026.x security fixes for `pimcore/pimcore` 11.5.4–11.5.14.1 and `pimcore/admin-ui-classic-bundle` 1.7.6–1.7.16, applied by [cweagans/composer-patches](https://github.com/cweagans/composer-patches) 2.

## Install

```bash
composer config repositories.pimcore-11-security-patches vcs https://github.com/portadesign/pimcore-11-security-patches
composer require portadesign/pimcore-11-security-patches
bin/console cache:clear
```

Composer asks once to trust the plugin (`allow-plugins`). On every `composer require`, `install` and `update` the plugin checks that each patch is applied to the installed package and relocks and re-applies them when the patch set changed or a patch is missing. Commit `composer.json`, `composer.lock`, `patches.lock.json`.

## Patches

| CVE | Package | Upstream commit | Verified | Notes |
| --- | --- | --- | --- | --- |
| CVE-2026-27461 | pimcore | `1c3925fbec` | 11.5.4, 11.5.14.1 | Dependency Dao RLIKE SQLi |
| CVE-2026-55634 | pimcore | `a4f8c3cfee` | 11.5.4, 11.5.14.1 | Field name RCE; test file omitted. `Data::setName()` now throws for names outside `^[a-zA-Z_][a-zA-Z0-9_]{0,62}$` |
| CVE-2026-11407, CVE-2026-115894 | pimcore | `fffa7f6396`, `ed8617f869`, `16486afce8` | 11.5.4, 11.5.14.1 | Twig sandbox, squashed with the 12.3.12 follow-up (GHSA-7gfm-v2fx-xrxm). `pimcore_user()` is blocked and `User`/`Asset` secret getters are hard-blocked in sandboxed templates. Adds `sandbox_security_policy.{blocked_classes,allowed_classes,blocked_functions,hard_blocked_methods}` |
| CVE-2026-5394 | pimcore | `6df625ff74` | 11.5.4, 11.5.14.1 | Composite index SQLi. Index keys and columns must match `^[a-zA-Z][a-zA-Z0-9_-]{0,63}$` |
| CVE-2026-44739 | pimcore | `3fd7733464` | 11.5.4, 11.5.14.1 | Custom Reports keyword guard |
| CVE-2026-55416 | pimcore | `1999fee27e` | 11.5.4, 11.5.14.1 | Manually rebased (signature formatting only). Report `sql`/`from`/`where`/`groupby` fragments containing `;`, `#`, `--`, `/*` or `*/` outside quoted strings are rejected |
| CVE-2026-55220, CVE-2026-45162 | pimcore | `b184c01bf1`, `4788bf3a3a`, `c7fa99aa7e`, `aa282383b8` | 11.5.4, 11.5.14.1 | Safe subset: `Serialize::unserialize()` `$allowedClasses`, Hotspotimage, Site, CustomLayout, TmpStore. Adds `pimcore.tmp_store.unserialize_allowed_classes`. `Serialize::unserialize()` keeps the permissive default |
| CVE-2026-58401 | pimcore | `397b881113` | 11.5.4, 11.5.14.1 | Admin session token class allowlist. Custom token classes go to `pimcore.security.session_token_allowed_classes` |
| CVE-2026-55072 | pimcore | `33a0e1887e` | 11.5.4, 11.5.14.1 | Manual: ID regex anchored with `/D`, anchored name check added after the ID check (the existing name regex differs between 11.5.4 and 11.5.14.1). Block hunk verbatim |
| CVE-2026-44741 | admin-ui-classic-bundle | `b5b987c712` (bundle repo) | 1.7.6, 1.7.16 | Translation grid SQLi |

Patch files carry a header with CVE, advisory, upstream commit and verified versions.

## Maintain

- `./verify.sh [pimcore-tag] [admin-ui-tag]`: every patch applies to pristine upstream tarballs (needs `gh`).
- New patch: diff from upstream `2026.x`, header, entry in `extra.patches`, table row, `./verify.sh`.
- Release: `./release.sh <version>` (rewrites patch URLs to the tag, refreshes `vex.openvex.json`, commits, tags, pushes).
- Advisory status lives in `advisories.json`; `php bin/build-vex.php` regenerates `vex.openvex.json` and `audit-ignore.json`.
- CI runs `verify.sh` only; the exploit tests in `tests/` need a full Pimcore and a database and are not run there yet.
- Patch already in a new Pimcore release (`git apply --check -R` passes): delete it.

## Tests

Run from a host project: uses its database and removes its fixtures; `--group CVE-2026-27461` selects one patch; revert the admin-ui patch with `patch -p1 -R` in its bundle directory.
```bash
T="-c vendor/portadesign/pimcore-11-security-patches/phpunit.xml.dist"; vendor/bin/phpunit $T
(cd vendor/pimcore/pimcore && git apply -R ../../portadesign/pimcore-11-security-patches/patches/pimcore-CVE-2026-27461-dependency-rlike.patch) && vendor/bin/phpunit $T --group CVE-2026-27461   # must fail
composer patches-repatch && vendor/bin/phpunit $T --group CVE-2026-27461   # must pass
```

## Skipped

The VEX and `audit-ignore.json` mark these as handled only under the stated precondition. Check each one before copying the ignore list into a project; drop the entry where the precondition does not hold.

| CVE | Precondition |
| --- | --- |
| CVE-2026-45260, CVE-2026-45162 | `/admin/asset/webdav` is blocked at the reverse proxy |
| CVE-2026-45704 | CustomReports share bypass accepted (admin-only impact) |
| CVE-2026-45703 | `pimcore/word-export-bundle` is not installed |
| CVE-2026-45162 WebDAV, Table, `DataObject\Service` hunks | WebDAV and Block hardening was walked back upstream in #19345; Table and `DataObject\Service` changes were outside the requested subset |

## Silencing scanners

`trivy fs --scanners vuln --vex vendor/portadesign/pimcore-11-security-patches/vex.openvex.json .` drops the advisories fixed by this package.
Copy the entries of `audit-ignore.json` into `config.audit.ignore` (and `config.policy.advisories.ignore-id` on Composer 2.10+) to silence `composer audit` and update blocking.
Both hold only while this package is installed and its patches are applied.
