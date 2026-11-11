#!/usr/bin/env bash
# WindPulse red-team demo — the whole show, run from Kali.
#
# Two Raspberry Pis, one attacker:
#   Pi-1 (PI_OWNED)  — Kali HAS the password  -> breaks in  (a BREAK-IN alert on the hub)
#   Pi-2 (PI_LOCKED) — Kali does NOT know it  -> locked out (a brute-force block on the hub)
#
# Pi-1 runs FIRST, on purpose: if Pi-2's brute force gets this attacker auto-blocked across
# the cluster, we still want the Pi-1 break-in to land cleanly first.
set -euo pipefail
cd "$(dirname "$0")"

: "${PI_OWNED:?set PI_OWNED (the Pi whose password you know)}"
: "${PI_LOCKED:?set PI_LOCKED (the Pi whose password you do NOT know)}"
: "${DEVMON_DEMO_PASSWORD:?set DEVMON_DEMO_PASSWORD (Pi-1's password)}"
export CSV="${CSV:-demo-timeline.csv}"
: > "$CSV"   # fresh timeline

echo "##############################################################"
echo "#  ACT 1 — Pi-1 ($PI_OWNED): the attacker HAS the password   #"
echo "#          expect a BREAK-IN on the hub                      #"
echo "##############################################################"
./demo-pi1-owned.sh

echo
echo "   ...pausing ${GAP:-8}s so the hub correlates Act 1..."
sleep "${GAP:-8}"

echo "##############################################################"
echo "#  ACT 2 — Pi-2 ($PI_LOCKED): the attacker does NOT know it  #"
echo "#          expect a brute-force block on the hub            #"
echo "##############################################################"
./demo-pi2-bruteforce.sh

cat <<EOF

================================ DONE ================================
Now look at the hub dashboard (https://sxmukelo.co.za) and the /demo page:
  - Pi-1 ($PI_OWNED):  BREAK-IN  — a successful login during an attack
  - Pi-2 ($PI_LOCKED): ATTACK    — brute force, attacker blocked

Confirm it from the hub's own database (run on the hub):
  python3 verify.py --db <hub-data-dir>/hub.db --timeline $CSV --watch

Timeline of what Kali did: $CSV
=====================================================================
EOF
