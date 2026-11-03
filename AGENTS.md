# Agent context

Read this first. It explains why the package exists, how it works, which decisions are settled and what is open.

## Purpose

Pimcore 11 reached end of life with 11.5.14.1 (admin-ui-classic-bundle 1.7.16) while CVEs against it kept being published. Portadesign runs several Pimcore 11 projects (suys-pim11, stock, more) on the same base image (`portadev/pimcore-php`, Alpine, ships `git` and `patch`). This package carries Portadesign's own fixes for those CVEs, written from the public advisories and this package's regression tests, and applies them from Composer, so each project needs only `composer require` and gets the same patch set, verification and scanner silencing.

Public GitHub repository, not on Packagist. Installation is documented in `README.md` and must stay at a handful of copy-paste commands.

## Provenance

Every patch is an independent implementation. The inputs were the public advisory text (GHSA/NVD), the GPLv3 Pimcore 11.5.4 and 11.5.14.1 sources and the exploit tests in `tests/`. No other implementation of a fix, no newer Pimcore release and no third-party fork was consulted. Keep it that way: a new patch starts from the advisory and a failing test, never from somebody else's diff. Do not add references to other implementations to patch headers, README, CHANGELOG or VEX.

## How it works

- `composer.json` is a `composer-plugin` that requires `cweagans/composer-patches` 2.x. Patches live in `patches/` and are referenced in `extra.patches` by raw GitHub URL pinned to the release tag plus `sha256`. cweagans reads dependency patches only from `composer.lock`, so the URLs must be absolute; relative vendor paths do not work.
- `src/ComposerPlugin.php` subscribes to `post-install-cmd` and `post-update-cmd`. `detectDrift()` compares `patches.lock.json` with the resolved patch set; `InstalledPatchInspector` checks that each locked patch is applied (`patch -R --dry-run`, fallback `git apply --check -R` with `GIT_CEILING_DIRECTORIES`; both missing → warning, no repatch). Drift or a missing patch triggers `patches-relock` and `patches-repatch` in a child Composer process (`PatchCommandRunner` over `ComposerProcessRunner`, in the project directory, forwarding `--ignore-platform-req[s]` as `COMPOSER_IGNORE_PLATFORM_REQ[S]`), guarded against recursion by `PORTADESIGN_PATCHES_SYNC`. Running cweagans in-process fails because Composer loads the plugin class twice. A non-zero child exit throws with the child output. After the run `PatchInspectionGuard` re-inspects every patch from the fresh lock and checks the patched package directories; it throws when a patch is still missing or when nothing could be verified (neither `patch` nor `git`), because `patches-repatch` in composer-patches 2 exits 0 even when its inner `install` fails.
- Bundled `patches/*` with a matching `sha256` are used for verification instead of a download; download failures warn and skip.
- `advisories.json` is the single source for advisory status. `bin/build-vex.php` generates `vex.openvex.json` (OpenVEX 0.2.0, for Trivy `--vex`) and `audit-ignore.json` (for Composer `config.audit.ignore` and `config.policy.advisories.ignore-id`). Statuses: `fixed`, `affected`, `not_affected` with precondition, `accepted` (not in the VEX, needs `.trivyignore.yaml`). Products are listed with and without the `v` prefix because Trivy takes the PURL version from `composer.lock` (`v11.5.14.1`).
- `release.sh <version>` rewrites patch URLs to the tag, regenerates hashes (`bin/sync-patch-hashes.php`) and the VEX, commits, tags, pushes. Push over SSH; the HTTPS OAuth token lacks the `workflow` scope.
- `verify.sh [pimcore-tag] [admin-tag]` applies every patch to pristine release tarballs (needs `gh`); `.github/workflows/verify.yml` runs it on push, PR and weekly for the 11.5.4/11.5.14.1 × 1.7.6/1.7.16 matrix.

## Tests

- `tests/*Test.php`: exploit regression tests, one group per CVE. They need a host project with a database. Run inside the project container: copy the repo (without `vendor/`) into the project, e.g. `var/tmp/security-patches`, then `PIMCORE_PROJECT_ROOT=/app vendor/bin/phpunit -c var/tmp/security-patches/phpunit.xml.dist`. Last run (2026-11-03, v1.0.1): 542 tests green on stock (11.5.14.1), 535 on suys-pim11 (11.5.4), both PHP 8.3.36. Reverting a patch with `patch -R` can leave `*.orig` files; run `find vendor/pimcore -name '*.orig' -delete` afterwards. Hosts set `SET time_zone` to PHP's offset in `TranslationGridFilterTest`; `TwigSandboxTest` accepts the 11.5.14.1 `TypeError` from `Mail::renderParams()` (the message is cut at `' in "__string'` although the template is named `pimcore_email_subject`). Running them from the host without a database produces hundreds of errors; that is not a regression.
- `tests/Unit`: plugin unit tests, `vendor/bin/phpunit -c phpunit.unit.xml.dist`, no host needed.
- `composer phpstan` must be clean.

## Settled decisions

- CVE-2026-45704 stays `accepted` (admin-only impact) and is the only entry outside the VEX; WebDAV must stay fully functional, no proxy precondition (owner decision 2026-11-03).
- The VEX tells the truth: a CVE is `fixed` only when every path in its advisory is patched.
- Verification runs on every install; the cost of downloading is avoided by the bundled files.
- No Packagist publication; vcs repository line in the README.
- Patches are independent implementations (see Provenance); the repository history starts at v1.0.0 of 2026-11-02.

## Open items (reviewer backlog, non-blocking)

1. `composer.json` conflict range allows unverified enterprise releases ≥ 11.5.15 / admin-ui ≥ 1.7.17; VEX lists only 11.5.4 and 11.5.14.1, so Trivy will not match 11.5.5–11.5.13. List every version or verify them with `verify.sh`.
2. If cweagans is not active (not allowed, or 1.x) the plugin returns silently; print an error.
3. The child `install` dumps a non-optimized autoloader over the parent's `-o`/`-a` one and runs under Composer's 300 s process timeout.
4. `release.sh` has no clean-tree or `main` guard and does not run `verify.sh` before tagging.
5. Two data providers in `tests/ClassDefinitionIdentifierTest.php` are empty on a host without classes or reports.
6. CVE-2026-45703: elements without `view` permission are skipped silently (200, element omitted); no 403.
7. CVE-2026-45260 known gap kept for compatibility with the tests: Sabre deletes the destination before `Tree::move()` runs, so a failed `publish` check leaves the destination deleted.
8. `ComposerPlugin` itself has no unit test.
9. Characterisation tests that cannot fail against the patches: signed-length payloads in `tests/Support/RejectedSerializedPayloads.php` (PHP 8.3 rejects them itself), the assignment-path cases in `tests/CompositeIndexTest.php` and `tests/CompositeIndexLegacyKeyTest.php` load test; `tests/TwigSandboxTest.php` accepts any `substr(): Argument #3` TypeError on 11.5.14.1. Exploit tests leave orphan `versions` rows on the host; run the versions cleanup afterwards.

## Conventions

`declare(strict_types=1)`, FQCN without `use`, named arguments, `readonly`, no comments. Conventional Commits, no tool attribution. Every change gets a line in `docs/CHANGELOG.md` (newest on top, local date and time). Never read `.env*` of a host project.

## Related

- Projects: `suys-pim11` (branch `feat/php83`), `stock` (11.5.14.1, cweagans 2).
- `portadesign/docker-library` PR #6 pins `git` and `patch` in `pimcore-php`.
- [`security-txt`](https://github.com/portadesign/security-txt): Composer package creating and checking security.txt; unrelated to patches.
