#!/bin/bash
# Build and run the debug-logging runtime regression (A04) in a scratch dir.
# usage: run-auth-debug-logging-test.sh [authbasic.cc [authenticate.cc]]
set -e
here=$(cd "$(dirname "$0")" && pwd -P)
src=${1:-$here/../src/server/authbasic.cc}
authn=${2:-$here/../src/server/authenticate.cc}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
g++ -std=gnu++17 -Wall -include "$here/stubs/compat.h" -I"$here/stubs" -I"$here/../src/server" \
    "$here/auth_debug_logging_test.cc" "$src" "$authn" -lssl -lcrypto -o "$out/t"
"$out/t"
