# pimcore-11-security-patches

Backports of public Pimcore 2026.x security fixes to `pimcore/pimcore` 11.5.x and `pimcore/admin-ui-classic-bundle` 1.7.x. Installing this package applies every patch automatically through [cweagans/composer-patches](https://github.com/cweagans/composer-patches) 2.x, so a project needs no `extra.patches` of its own.

Each file in `patches/` is a unified diff relative to the package root (`-p1`, no `vendor/` prefix) with a metadata header (CVE, advisory, upstream commit, verified versions) before the first `diff --git`.

Verified with `git apply --check` and `patch -p1 --dry-run` against pristine 11.5.4 and 11.5.14.1 (`pimcore/pimcore`) and 1.7.6 and 1.7.16 (`pimcore/admin-ui-classic-bundle`), individually and applied in order.

## Install

1. Allow the plugin and add the repository (private GitHub repo, so Composer needs GitHub auth: `composer config github-oauth.github.com <token>` or an SSH key):

   ```bash
   composer config allow-plugins.cweagans/composer-patches true
   composer config repositories.pimcore-11-security-patches vcs https://github.com/portadesign/pimcore-11-security-patches
   composer require portadesign/pimcore-11-security-patches:^1.0
   composer patches-relock
   composer patches-repatch
   bin/console cache:clear
   ```

2. Commit `composer.json`, `composer.lock` and `patches.lock.json`.

`composer install` alone does not patch packages that are already installed; `patches-repatch` reinstalls `pimcore/pimcore` and `pimcore/admin-ui-classic-bundle` and applies every patch. Patches are resolved from the package's `composer.json` as recorded in `composer.lock`, so after every update of this package run `composer patches-relock && composer patches-repatch` again.

Patch files are fetched from `raw.githubusercontent.com` at the tag recorded in this package's `composer.json` (composer-patches resolves dependency patches before the dependency itself is extracted, so a path inside `vendor/` cannot work). Because the repository is private, Composer also needs the token for that host once per machine or CI runner:

```bash
composer config -g github-oauth.raw.githubusercontent.com <token>
```

or `COMPOSER_AUTH='{"github-oauth":{"github.com":"<token>","raw.githubusercontent.com":"<token>"}}'`. `patches.lock.json` pins every file by sha256.

To skip a single patch in one project, drop it from the resolved set with the plugin's `ignore-dependency-patches` config or override it in the project's `extra.patches` under the same package key.

## Update

```bash
composer update portadesign/pimcore-11-security-patches
composer patches-relock && composer patches-repatch
bin/console cache:clear && bin/console lint:container
```

## Config keys added by the patches

Under `pimcore:` — `tmp_store.unserialize_allowed_classes`, `security.session_token_allowed_classes`, `templating_engine.twig.sandbox_security_policy.{blocked_classes,allowed_classes,blocked_functions,hard_blocked_methods}`. Check with `bin/console debug:container --parameters | grep -E 'tmp_store|session_token|sandbox_security_policy'`.

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

## Verify against pristine sources

```bash
./verify.sh                      # 11.5.14.1 / 1.7.16
./verify.sh v11.5.4 v1.7.6
```

Needs the `gh` CLI. Every line must read `OK`; the sequential pass catches conflicts between patches touching the same file (`Configuration.php`, `PimcoreCoreExtension.php`, `ClassDefinition.php`, `Sql.php`).

## After a Pimcore release

1. Run `verify.sh` with the new tags.
2. A patch that fails with "already applied" (`git apply --check -R` passes) is in the release: delete the file and its `extra.patches` entry, add a `conflict` lower bound if needed.
3. A patch that fails otherwise needs a manual rebase: `gh api -H "Accept: application/vnd.github.v3.diff" repos/pimcore/pimcore/commits/<sha>`, keep the header, re-verify on every supported version.
4. `./release.sh <version>` (rewrites the patch URLs to the new tag, commits, tags, pushes). Semver: new patch = minor, removed or changed patch = major if a project could break.

## Adding a patch

1. Find the fix on upstream branch `2026.x` (`gh api repos/pimcore/pimcore/security-advisories`, then the referenced commit).
2. Save the diff as `patches/<package>-<CVE>-<topic>.patch`, paths relative to the package root, header lines before the first `diff --git`.
3. Add the `extra.patches` entry (key `pimcore/pimcore` or `pimcore/admin-ui-classic-bundle`, URL in the same form as the existing ones; `release.sh` fixes the tag).
4. `./verify.sh` for every supported version pair, add the table row above, then `./release.sh <version>`.

## Skipped

| CVE | Reason |
| --- | --- |
| CVE-2026-45260 | WebDAV; blocked at the reverse proxy |
| CVE-2026-45704 | Risk accepted |
| CVE-2026-45703 | Affected bundle not installed |
| CVE-2026-45162 WebDAV, Table, `DataObject\Service` hunks | WebDAV and Block hardening was walked back upstream in #19345; Table and `DataObject\Service` changes were outside the requested subset |

## Not assessed

Later security commits on upstream `2026.x`: #19496 (Twig sandbox content-model mutation methods), #19549 (`parentClass` validation in `generateClassFiles()`), #19560 (Ghostscript filename), #19583 (Block unserialize), #19590 (Twig `request`/`pimcore_dump`).
