#!/usr/bin/env bash
# Pi-1 — the attacker HAS the password. A handful of wrong guesses, then the REAL login.
# The hub sees a successful login inside a brute-force window and flags a BREAK-IN.
set -euo pipefail
cd "$(dirname "$0")"

: "${PI_OWNED:?set PI_OWNED to the owned Pi's IP, e.g. export PI_OWNED=192.168.1.21}"
: "${DEVMON_DEMO_PASSWORD:?set DEVMON_DEMO_PASSWORD to that Pi's password}"
USER_NAME="${DEMO_USER:-pidemo}"

echo "==> Pi-1 ($PI_OWNED): ${SPRAY:-6} wrong guesses, then logging in as $USER_NAME with the real password"
python3 attacks.py ssh-login \
  --target "$PI_OWNED" --user "$USER_NAME" \
  --spray "${SPRAY:-6}" \
  --csv "${CSV:-demo-timeline.csv}" \
  --i-own-this-cluster
