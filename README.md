# pimcore-11-security-patches

Backports of public Pimcore 2026.x security fixes for `pimcore/pimcore` 11.5.4–11.5.14.1 and `pimcore/admin-ui-classic-bundle` 1.7.6–1.7.16, applied by [cweagans/composer-patches](https://github.com/cweagans/composer-patches) 2.

## Install

```bash
composer config -g github-oauth.github.com <token>
composer config -g github-oauth.raw.githubusercontent.com <token>
composer config repositories.pimcore-11-security-patches vcs https://github.com/portadesign/pimcore-11-security-patches
composer require portadesign/pimcore-11-security-patches:^1.0
composer patches-relock && composer patches-repatch
bin/console cache:clear
```

Commit `composer.json`, `composer.lock`, `patches.lock.json`. After every update of this package: `composer patches-relock && composer patches-repatch`.

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
- Release: `./release.sh <version>` (rewrites patch URLs to the tag, commits, tags, pushes).
- Patch already in a new Pimcore release (`git apply --check -R` passes): delete it.

## Skipped

| CVE | Reason |
| --- | --- |
| CVE-2026-45260 | WebDAV; blocked at the reverse proxy |
| CVE-2026-45704 | Risk accepted |
| CVE-2026-45703 | Affected bundle not installed |
| CVE-2026-45162 WebDAV, Table, `DataObject\Service` hunks | WebDAV and Block hardening was walked back upstream in #19345; Table and `DataObject\Service` changes were outside the requested subset |
