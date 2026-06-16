#!/usr/bin/env bash
# Build du plugin WordPress installable (keyso-waf.zip)
# Usage : bash wordpress-plugin/build-zip.sh
#
# Préfère Python (zipfile) pour garantir des chemins POSIX (slashes avant) :
# Compress-Archive (PowerShell) écrit des antislashs que WordPress extrait mal
# sous Linux. Le binaire `zip` (POSIX) est également correct s'il est présent.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if command -v zip >/dev/null 2>&1; then
    rm -f keyso-waf.zip
    zip -r -q keyso-waf.zip keyso-waf -x '*.DS_Store'
    echo "✅ Plugin packagé (zip) : $ROOT/keyso-waf.zip"
elif command -v python >/dev/null 2>&1; then
    python build-zip.py
elif command -v py >/dev/null 2>&1; then
    py build-zip.py
else
    echo "❌ Ni 'zip' ni 'python' disponibles." >&2
    exit 1
fi
