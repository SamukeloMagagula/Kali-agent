#!/usr/bin/env bash
# Pi-2 — the attacker does NOT know the password. Pure brute force with a junk wordlist.
# Every attempt fails: the hub raises a brute-force incident and, if self-healing blocking
# is on, blocks this attacker. There is no way in.
set -euo pipefail
cd "$(dirname "$0")"

: "${PI_LOCKED:?set PI_LOCKED to the locked Pi's IP, e.g. export PI_LOCKED=192.168.1.22}"

echo "==> Pi-2 ($PI_LOCKED): ${ATTEMPTS:-15} brute-force attempts (all wrong) — expect a block"
python3 attacks.py ssh-bruteforce \
  --target "$PI_LOCKED" \
  --attempts "${ATTEMPTS:-15}" \
  --csv "${CSV:-demo-timeline.csv}" \
  --i-own-this-cluster
