#!/bin/bash
# Source-level guard (A04): no log statement in the Basic auth handler may
# receive the decoded credentials, the password, or the raw/decoded header.
# This inspects source text, not runtime output; it fails on the pre-fix code.
f=${1:-$(dirname "$0")/../src/server/authbasic.cc}
python3 - "$f" <<'P'
import re, sys
src = open(sys.argv[1]).read()
# join each log call (may span lines) into one statement
calls = re.findall(r'\b(?:dsyslog|syslog)\s*\((?:[^;]*?)\);', src, re.S)
bad = [c for c in calls
       if re.search(r'\bpassword\b|\bpasswd\b|\bout\b|\bstr_out\b|\bauth\b|\bval\b', c)]
# vyatta_debug() text is returned to the client and logged by main.cc (AUTHFAILED):
# it must not be built from the Authorization header or the cookie either.
dbg = re.findall(r'\bvyatta_debug\s*\((?:[^;]*?)\);', src, re.S)
bad += [c for c in dbg if re.search(r'\bauth\b|\bcookie\b|\bval\b|\bpassword\b', c)]
for c in bad:
    print("credential-bearing log call:", " ".join(c.split()))
print("log calls inspected:", len(calls), "vyatta_debug calls inspected:", len(dbg))
sys.exit(1 if bad else 0)
P
