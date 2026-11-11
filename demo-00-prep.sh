#!/usr/bin/env bash
# WindPulse red-team demo — KALI prep. Run this ONCE on the Kali attacker box.
# Installs the small helpers the demo needs and creates redteam.ini from the example.
set -euo pipefail
cd "$(dirname "$0")"

echo "[*] Installing helpers (sshpass, ssh client) ..."
sudo apt-get update -y
sudo apt-get install -y sshpass openssh-client python3

if [ ! -f redteam.ini ]; then
  cp redteam.example.ini redteam.ini
  echo "[*] Wrote redteam.ini — EDIT IT: set [cluster] allow to your cluster's private range."
else
  echo "[*] redteam.ini already exists — leaving it as is."
fi

cat <<'EOF'

Next, set these for the demo (adjust IPs/password to your cluster), then run ./demo-run.sh:

  export PI_OWNED=192.168.1.21            # Pi-1: Kali KNOWS this one's password
  export PI_LOCKED=192.168.1.22           # Pi-2: Kali does NOT know this one
  export DEVMON_DEMO_PASSWORD='the-pi1-password'   # the password you set on Pi-1
  # optional: export DEMO_USER=pidemo

And make sure redteam.ini's [cluster] allow covers both Pi addresses.
EOF
