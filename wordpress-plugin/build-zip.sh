#!/usr/bin/env bash
# Build du plugin WordPress installable (keyso-waf.zip)
# Usage : bash wordpress-plugin/build-zip.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
rm -f keyso-waf.zip
zip -r -q keyso-waf.zip keyso-waf -x '*.DS_Store'
echo "✅ Plugin packagé : $ROOT/keyso-waf.zip"
