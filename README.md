# pimcore-11-security-patches

Security hardening for `pimcore/pimcore` 11.5.4–11.5.14.1 and `pimcore/admin-ui-classic-bundle` 1.7.6–1.7.16 against published CVEs, applied by [cweagans/composer-patches](https://github.com/cweagans/composer-patches) 2..

## Install

Public GitHub repository, not on Packagist. Requires `pimcore/pimcore` ≥ 11.5.4, Composer 2 and PHP ≥ 8.2 (8.3 recommended, the version the exploit tests run on).

```bash
composer config repositories.pimcore-11-security-patches vcs https://github.com/portadesign/pimcore-11-security-patches
composer config allow-plugins.cweagans/composer-patches true
composer config allow-plugins.portadesign/pimcore-11-security-patches true
composer require portadesign/pimcore-11-security-patches
bin/console cache:clear
```

The two `allow-plugins` lines keep non-interactive installs (CI, Docker build) from stopping at the trust prompt. On every `composer require`, `install` and `update` the plugin checks that each patch is applied and relocks and re-applies them when the patch set changed or a patch is missing. Commit `composer.json`, `composer.lock`, `patches.lock.json`.

Project on `cweagans/composer-patches` 1.x: run `composer remove cweagans/composer-patches`, delete `patches.lock.json`, then the steps above. Project patches in `extra.patches` keep working.

Scanners: copy `audit-ignore.json` into `composer.json` `config` and point Trivy at `vendor/portadesign/pimcore-11-security-patches/vex.openvex.json`, see [Silencing scanners](#silencing-scanners). Check the [Skipped](#skipped) preconditions first. Composer 2.10+ refuses to install `pimcore/pimcore` with open advisories (`policy.advisories.block`), so the `config.policy` part of `audit-ignore.json` has to be in `composer.json` before `composer require`.

## Patches

| CVE | Package | Verified | Notes |
| --- | --- | --- | --- |
| CVE-2026-27461 | pimcore | 11.5.4, 11.5.14.1 | Dependency Dao RLIKE SQLi |
| CVE-2026-55634 | pimcore | 11.5.4, 11.5.14.1 | Field name RCE. `Data::setName()` throws for names outside `^[a-zA-Z_][a-zA-Z0-9_]{0,62}$`; classification store key names stay free text |
| CVE-2026-11407, CVE-2026-115894 | pimcore | 11.5.4, 11.5.14.1 | Twig sandbox (also GHSA-7gfm-v2fx-xrxm). Sandboxed templates cannot call blocked functions (`pimcore_user`, `pimcore_dump`, `pimcore_asset_version_preview`, `pimcore_image_version_preview`, `pimcore_file_exists`, `pimcore_inc`, `pimcore_website_config`, `pimcore_renderlet`, `pimcore_snippet`), static methods through an instance (`getList`, `getById`, …), undeclared model methods forwarded to the Dao through `__call`, methods or properties of blocked classes (user, token, session, request bags, DAO, listings, DBAL, PDO, container, kernel, process, Twig, class/brick/field-collection/custom-layout definitions) and hard-blocked methods: every mutator of `AbstractModel`/`ElementInterface` (`save*`, `delete*`, `set*`, `publish`, `move*`, …, wildcards allowed) and the secret getters of `User`, `Asset`, `Asset\Document`, thumbnails, `Version` and `Request`. Iterating a blocked listing still works. `$objectTypes` of `hasChildren()`/`getChildren()`/`hasSiblings()`/`getChildAmount()` and object listings is restricted to object/variant/folder; array thumbnail configs are rejected while a sandbox is active (named configs work). Config: `pimcore.templating_engine.twig.sandbox_security_policy.{blocked_classes,allowed_classes,blocked_functions,hard_blocked_methods}`; `allowed_classes` lifts a class block, never a hard-blocked method |
| CVE-2026-5394 | pimcore | 11.5.4, 11.5.14.1 | Composite index SQLi. Before any SQL, index keys must match `^[a-zA-Z0-9_+-]{1,64}$` and column names `^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`; an empty key is skipped with a warning so existing definitions keep loading |
| CVE-2026-44739 | pimcore | 11.5.4, 11.5.14.1 | Custom Reports keyword guard |
| CVE-2026-55416 | pimcore | 11.5.4, 11.5.14.1 | Report `sql`/`from`/`where`/`groupby` fragments must be strings and may not contain `;`, `#`, `--`, `/*`, `*/`, `INTO OUTFILE`, `INTO DUMPFILE` or `LOAD_FILE(` outside quoted strings, nor start with a write statement; filter, sort and drill-down field names are quoted and may not contain a backtick |
| CVE-2026-55220, CVE-2026-45162 | pimcore | 11.5.4, 11.5.14.1 | Safe subset: `Serialize::unserialize()` `$allowedClasses`, Hotspotimage, Site, CustomLayout, TmpStore. Adds `pimcore.tmp_store.unserialize_allowed_classes`. `Serialize::unserialize()` keeps the permissive default |
| CVE-2026-58401 | pimcore | 11.5.4, 11.5.14.1 | Admin session token class allowlist. Custom token classes go to `pimcore.security.session_token_allowed_classes` |
| CVE-2026-55072 | pimcore | 11.5.4, 11.5.14.1 | Class definition ID regex anchored (`/D`) with an anchored name check after it; `Block::load()` quotes the table names built from the class ID |
| CVE-2026-45260 | pimcore | 11.5.4, 11.5.14.1 | WebDAV MOVE authorization: requires an authenticated user with `create` on the destination folder, `publish` on the asset, `delete` on an overwritten or restored source, `rename` for a same-folder rename. A failing save of an authorised move surfaces as HTTP 500 |
| CVE-2026-45703 | pimcore | 11.5.4, 11.5.14.1 | WordExport authorization bypass: elements without `view` permission for the user are skipped from the export instead of being exported. Skipped silently, no 403 |
| CVE-2026-44741 | admin-ui-classic-bundle | 1.7.6, 1.7.16 | Translation grid SQLi |

Patch files carry a header with CVE, advisory and verified versions.

## Maintain

- `./verify.sh [pimcore-tag] [admin-ui-tag]`: every patch applies to pristine release tarballs (needs `gh`).
- New patch: written from the advisory and a failing test, header, entry in `extra.patches`, table row, `./verify.sh`.
- Release: `./release.sh <version>` (rewrites patch URLs to the tag, regenerates `sha256` values, refreshes `vex.openvex.json`, commits, tags, pushes).
- Advisory status lives in `advisories.json`; `php bin/build-vex.php` regenerates `vex.openvex.json` and `audit-ignore.json`.
- CI runs `verify.sh` only; the exploit tests in `tests/` need a full Pimcore and a database and are not run there yet.
- Patch no longer needed (`git apply --check -R` passes on the installed version): delete it.

## Tests

The dist install omits `tests/`; clone the repository next to the project or run `composer reinstall portadesign/pimcore-11-security-patches --prefer-source`. Run from a host project: uses its database and removes its fixtures; `--group CVE-2026-27461` selects one patch; revert the admin-ui patch with `patch -p1 -R` in its bundle directory. Reverting with `patch -R` can leave `*.orig` files; run `find vendor/pimcore -name '*.orig' -delete` afterwards.
```bash
T="-c vendor/portadesign/pimcore-11-security-patches/phpunit.xml.dist"; vendor/bin/phpunit $T
(cd vendor/pimcore/pimcore && git apply -R ../../portadesign/pimcore-11-security-patches/patches/pimcore-CVE-2026-27461-dependency-rlike.patch) && vendor/bin/phpunit $T --group CVE-2026-27461   # must fail
composer patches-repatch && vendor/bin/phpunit $T --group CVE-2026-27461   # must pass
```

## Skipped

The VEX and `audit-ignore.json` mark these as handled only under the stated precondition. Check each one before copying the ignore list into a project; drop the entry where the precondition does not hold.

| CVE | Precondition |
| --- | --- |
| CVE-2026-45162 | `/asset/webdav` is blocked at the reverse proxy |
| CVE-2026-45704 | CustomReports share bypass accepted (admin-only impact) |
| CVE-2026-45162 WebDAV, Table, `DataObject\Service` paths | Not covered: WebDAV beyond MOVE (CVE-2026-45260) is behind the proxy precondition, Table and `DataObject\Service` are not hardened |

## Silencing scanners

Trivy reads the VEX from `--vex`, `TRIVY_VEX` or `trivy.yaml`. The statements match the `composer.lock` PURLs `pkg:composer/pimcore/pimcore@v11.5.14.1` (both `v`-prefixed and plain versions are listed). `fixed` and `not_affected` statements hide the finding; CVE-2026-45162 stays `affected` (partial fix) and CVE-2026-45704 (accepted, not in the VEX) needs a `.trivyignore.yaml`.

```yaml
# .trivyignore.yaml
vulnerabilities:
  - id: CVE-2026-45704
    statement: CustomReports share bypass accepted, admin-only impact
```

GitHub Actions with [aquasecurity/trivy-action](https://github.com/aquasecurity/trivy-action):

```yaml
- uses: aquasecurity/trivy-action@0.28.0
  with:
    scan-type: fs
    scan-ref: .
    scanners: vuln
    severity: HIGH,CRITICAL
    exit-code: '1'
  env:
    TRIVY_VEX: vendor/portadesign/pimcore-11-security-patches/vex.openvex.json
    TRIVY_IGNOREFILE: .trivyignore.yaml
```

The step needs `vendor/` from `composer install` first; without it copy `vex.openvex.json` to `.trivy/vex.openvex.json` in the project and point `TRIVY_VEX` there. For a CLI run or CI templates that call `trivy` without flags put a `trivy.yaml` in the project root:

```yaml
ignorefile: .trivyignore.yaml
vulnerability:
  vex:
    - vendor/portadesign/pimcore-11-security-patches/vex.openvex.json
```

Verified with Trivy 0.76 on a `composer.lock` with pimcore 11.5.14.1: 13 pimcore findings without the VEX, CVE-2026-45162 only with the VEX and ignore file.

Copy the entries of `audit-ignore.json` into `config.audit.ignore` (and `config.policy.advisories.ignore-id` on Composer 2.10+) to silence `composer audit` and update blocking.
Both hold only while this package is installed and its patches are applied.
