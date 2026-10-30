#!/usr/bin/env bash
set -euo pipefail
v=${1:?version, e.g. 1.2.0}
cd "$(dirname "$0")"
sed -i.bak -E "s#(raw.githubusercontent.com/portadesign/pimcore-11-security-patches/)v[0-9]+\.[0-9]+\.[0-9]+/#\1v${v}/#" composer.json && rm composer.json.bak
for f in patches/*.patch; do grep -q "^diff --git" "$f" || { echo "no diff in $f"; exit 1; }; done
php bin/build-vex.php --bump --tooling="v${v}"
git add composer.json vex.openvex.json audit-ignore.json
git commit -qm "chore: release v${v}"
git tag "v${v}"
git push -q origin main "v${v}"
echo "released v${v}"
