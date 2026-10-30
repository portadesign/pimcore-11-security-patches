# Agent context

Read this first. It explains why the package exists, how it works, which decisions are settled and what is open.

## Purpose

Pimcore 11 reached end of life with 11.5.14.1 (admin-ui-classic-bundle 1.7.16). Pimcore fixed a batch of 2026 CVEs only in 2026.x and 12.x, which need a license. PORTA DESIGN runs several Pimcore 11 projects (suys-pim11, stock, more) on the same base image (`portadev/pimcore-php`, Alpine, ships `git` and `patch`). This package backports the public fixes and applies them from Composer, so each project needs only `composer require` and gets the same patch set, verification and scanner silencing.

Public GitHub repository, not on Packagist. Installation is documented in `README.md` and must stay at a handful of copy-paste commands.

## How it works

- `composer.json` is a `composer-plugin` that requires `cweagans/composer-patches` 2.x. Patches live in `patches/` and are referenced in `extra.patches` by raw GitHub URL pinned to the release tag plus `sha256`. cweagans reads dependency patches only from `composer.lock`, so the URLs must be absolute; relative vendor paths do not work.
- `src/ComposerPlugin.php` subscribes to `post-install-cmd` and `post-update-cmd`. `detectDrift()` compares `patches.lock.json` with the resolved patch set; `InstalledPatchInspector` checks that each locked patch is applied (`patch -R --dry-run`, fallback `git apply --check -R` with `GIT_CEILING_DIRECTORIES`; both missing → warning, no repatch). Drift or a missing patch triggers `patches-relock` and `patches-repatch` in a child Composer process (`ComposerProcessRunner`), guarded against recursion by `PORTADESIGN_PATCHES_SYNC`. Running cweagans in-process fails because Composer loads the plugin class twice.
- Bundled `patches/*` with a matching `sha256` are used for verification instead of a download; download failures warn and skip.
- `advisories.json` is the single source for advisory status. `bin/build-vex.php` generates `vex.openvex.json` (OpenVEX 0.2.0, for Trivy `--vex`) and `audit-ignore.json` (for Composer `config.audit.ignore` and `config.policy.advisories.ignore-id`). Statuses: `fixed`, `affected` (partial backport, 45162), `not_affected` with precondition, `accepted`.
- `release.sh <version>` rewrites patch URLs to the tag, regenerates hashes (`bin/sync-patch-hashes.php`) and the VEX, commits, tags, pushes. Push over SSH; the HTTPS OAuth token lacks the `workflow` scope.
- `verify.sh [pimcore-tag] [admin-tag]` applies every patch to pristine upstream tarballs (needs `gh`); `.github/workflows/verify.yml` runs it on push, PR and weekly for the 11.5.4/11.5.14.1 × 1.7.6/1.7.16 matrix.

## Tests

- `tests/*Test.php`: exploit regression tests, one group per CVE. They need a host project with a database. Run inside the project container: copy the repo (without `vendor/`) into the project, e.g. `var/tmp/security-patches`, then `PIMCORE_PROJECT_ROOT=/app vendor/bin/phpunit -c var/tmp/security-patches/phpunit.xml.dist`. Last run: 215 tests green on suys-pim11 (11.5.4, PHP 8.3.36). Running them from the host without a database produces hundreds of errors; that is not a regression.
- `tests/Unit`: plugin unit tests, `vendor/bin/phpunit -c phpunit.unit.xml.dist`, no host needed.
- `composer phpstan` must be clean.

## Settled decisions

- Skipped advisories (45260, 45162 WebDAV hunks, 45703, 45704) stay in the shipped VEX and ignore list with their precondition stated in `README.md` "Skipped" and in `advisories.json`. Projects verify the precondition before copying the ignore list. Approved by the owner for all PORTA DESIGN projects on 2026-10-30.
- The VEX tells the truth: 45162 is `affected`, not `fixed`.
- Verification runs on every install; the cost of downloading is avoided by the bundled files.
- No Packagist publication; vcs repository line in the README.

## Open items (reviewer backlog, non-blocking)

1. `composer.json` conflict range allows unverified enterprise releases ≥ 11.5.15 / admin-ui ≥ 1.7.17; VEX lists only 11.5.4 and 11.5.14.1, so Trivy will not match 11.5.5–11.5.13. List every version or verify them with `verify.sh`.
2. If cweagans is not active (not allowed, or 1.x) the plugin returns silently; print an error.
3. The child `install` dumps a non-optimized autoloader over the parent's `-o`/`-a` one and runs under Composer's 300 s process timeout.
4. `release.sh` has no clean-tree or `main` guard and does not run `verify.sh` before tagging.
5. Two data providers in `tests/ClassDefinitionIdentifierTest.php` are empty on a host without classes or reports.
6. Consider `/D` in the `Data::setName` regex (tester finding on CVE-2026-55634).
7. The exploit tests have not run on stock (11.5.14.1) yet.

## Conventions

`declare(strict_types=1)`, FQCN without `use`, named arguments, `readonly`, no comments. Conventional Commits, no tool attribution. Every change gets a line in `docs/CHANGELOG.md` (newest on top, local date and time). Never read `.env*` of a host project.

## Related

- Projects: `suys-pim11` (branch `feat/php83`, on v1.1.0), `stock` (11.5.14.1, cweagans 2, not yet switched to the package).
- `portadesign/docker-library` PR #6 pins `git` and `patch` in `pimcore-php`.
- [`security-template`](https://github.com/portadesign/security-template): security.txt with expiry checks; scanner silencing is documented here, not there.
