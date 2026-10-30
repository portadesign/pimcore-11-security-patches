#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
pimcore_tag=${1:-v11.5.14.1}
admin_tag=${2:-v1.7.16}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fetch() { mkdir -p "$3" && gh api "repos/$1/tarball/$2" | tar xz --strip-components=1 -C "$3"; }
check() {
  local fail=0
  for p in "$root"/patches/"$2"-CVE-*.patch; do
    if (cd "$1" && git apply --check "$p" && patch -p1 --dry-run -s < "$p" > /dev/null); then
      echo "OK   $(basename "$p")"
    else
      echo "FAIL $(basename "$p")"; fail=1
    fi
  done
  echo "-- sequential apply ($3)"
  (cd "$1" && git init -q && for p in "$root"/patches/"$2"-CVE-*.patch; do git apply "$p" || { echo "FAIL sequential $(basename "$p")"; fail=1; }; done)
  return $fail
}
fetch pimcore/pimcore "$pimcore_tag" "$work/pimcore"
fetch pimcore/admin-ui-classic-bundle "$admin_tag" "$work/admin"
status=0
check "$work/pimcore" pimcore "pimcore/pimcore $pimcore_tag" || status=1
check "$work/admin" admin-ui-classic-bundle "pimcore/admin-ui-classic-bundle $admin_tag" || status=1
exit $status
