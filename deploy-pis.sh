#!/usr/bin/env bash
# WindPulse red-team demo — one-shot deploy to BOTH Raspberry Pis, run from Kali.
#
# It does the fiddly set-up for you:
#   1. checks Kali can reach each Pi,
#   2. copies pi-demo-setup.sh to each Pi and runs it (creates the pidemo login,
#      enables password SSH) with the password you chose for that Pi,
#   3. teaches the two Pis each other's name + IP (/etc/hosts) so they can talk by name,
#   4. writes demo.env with the exports the demo needs — `source demo.env` and go.
#
#   FOR YOUR OWN DEMO CLUSTER ONLY.
#
# You give it: each Pi's IP, the Pi's *admin* login (a sudo account already on the Pi),
# and the demo password to set on each Pi. Pi-1's password is the one you hand to Kali;
# Pi-2's stays secret.
#
# Usage:
#   export PI_OWNED=192.168.1.21            # Pi-1: Kali WILL know this password
#   export PI_LOCKED=192.168.1.22           # Pi-2: Kali will NOT know this one
#   export PI1_PASSWORD='pi1-demo-pass'     # demo password set on Pi-1 (given to Kali)
#   export PI2_PASSWORD='pi2-SECRET-pass'   # demo password set on Pi-2 (kept secret)
#   export ADMIN_USER=pi                    # a sudo account already on both Pis
#   # optional: export ADMIN_PASSWORD='...' # admin SSH password (else SSH keys are used)
#   # optional: export DEMO_USER=pidemo     # demo account name (default pidemo)
#   ./deploy-pis.sh
set -euo pipefail
cd "$(dirname "$0")"

# --- inputs ---------------------------------------------------------------
: "${PI_OWNED:?set PI_OWNED to Pi-1's IP (the one Kali knows)}"
: "${PI_LOCKED:?set PI_LOCKED to Pi-2's IP (the one Kali does NOT know)}"
: "${PI1_PASSWORD:?set PI1_PASSWORD (demo password for Pi-1, handed to Kali)}"
: "${PI2_PASSWORD:?set PI2_PASSWORD (demo password for Pi-2, kept secret)}"
ADMIN_USER="${ADMIN_USER:-pi}"
DEMO_USER="${DEMO_USER:-pidemo}"

# --- ssh/scp helpers (use sshpass only if an admin password was given) -----
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=8)
if [ -n "${ADMIN_PASSWORD:-}" ]; then
  command -v sshpass >/dev/null || { echo "sshpass needed for password login — run ./demo-00-prep.sh first" >&2; exit 2; }
  SSH=(sshpass -p "$ADMIN_PASSWORD" ssh "${SSH_OPTS[@]}")
  SCP=(sshpass -p "$ADMIN_PASSWORD" scp "${SSH_OPTS[@]}")
else
  SSH=(ssh "${SSH_OPTS[@]}")
  SCP=(scp "${SSH_OPTS[@]}")
fi

# deploy_one <ip> <demo-password> <this-name> <other-name> <other-ip>
deploy_one() {
  local ip="$1" demo_pw="$2" name="$3" other="$4" other_ip="$5"
  echo
  echo "=== ${name} (${ip}) ============================================"

  echo "[1/4] reachability ..."
  ping -c1 -W2 "$ip" >/dev/null 2>&1 && echo "      ping ok" || echo "      ping blocked (continuing; ICMP is often filtered)"
  "${SSH[@]}" "${ADMIN_USER}@${ip}" 'echo "      ssh ok as $(whoami) on $(hostname)"' \
    || { echo "      ! cannot SSH to ${ADMIN_USER}@${ip} — check the IP, ADMIN_USER, and keys/ADMIN_PASSWORD" >&2; return 1; }

  echo "[2/4] copying pi-demo-setup.sh ..."
  "${SCP[@]}" pi-demo-setup.sh "${ADMIN_USER}@${ip}:/tmp/pi-demo-setup.sh"

  echo "[3/4] running setup (creates ${DEMO_USER}, enables password SSH) ..."
  # pass the demo password via env so it never lands in the process list / shell history
  "${SSH[@]}" "${ADMIN_USER}@${ip}" \
    "chmod +x /tmp/pi-demo-setup.sh && sudo DEMO_PW=$(printf %q "$demo_pw") /tmp/pi-demo-setup.sh $(printf %q "$DEMO_USER")"

  echo "[4/4] teaching it about ${other} (${other_ip}) so the Pis can talk by name ..."
  "${SSH[@]}" "${ADMIN_USER}@${ip}" \
    "grep -q ' ${other}\$' /etc/hosts || echo '${other_ip} ${other}' | sudo tee -a /etc/hosts >/dev/null"

  echo "    ${name} ready."
}

deploy_one "$PI_OWNED"  "$PI1_PASSWORD" "pi-owned"  "pi-locked" "$PI_LOCKED"
deploy_one "$PI_LOCKED" "$PI2_PASSWORD" "pi-locked" "pi-owned"  "$PI_OWNED"

# --- make sure the attack scope covers both Pis --------------------------
if [ ! -f redteam.ini ]; then
  cp redteam.example.ini redteam.ini
  echo
  echo "[*] wrote redteam.ini (edit [cluster] allow if your range differs from the default)"
fi

# --- write the ready-to-source env for the demo ---------------------------
cat > demo.env <<EOF
# Sourced by the demo: \`source demo.env\` then \`./demo-run.sh\`. Written by deploy-pis.sh.
export PI_OWNED=${PI_OWNED}
export PI_LOCKED=${PI_LOCKED}
export DEMO_USER=${DEMO_USER}
# Pi-1's password — the one Kali is allowed to know:
export DEVMON_DEMO_PASSWORD='${PI1_PASSWORD}'
EOF
chmod 600 demo.env

cat <<EOF

================================ READY ================================
Both Pis are set up and know each other by name (pi-owned / pi-locked).

Run the show:
  source demo.env
  ./demo-run.sh

Then watch the hub dashboard (https://sxmukelo.co.za) and the /demo page:
  - Pi-1 (${PI_OWNED}):  BREAK-IN  — Kali has the password, logs in mid-attack
  - Pi-2 (${PI_LOCKED}): BLOCKED   — Kali does not; brute force fails, attacker blocked

Note: demo.env holds Pi-1's password (chmod 600). Pi-2's password is NOT stored here.
======================================================================
EOF
