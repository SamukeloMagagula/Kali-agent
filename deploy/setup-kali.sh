#!/usr/bin/env bash
# Set up a Kali Linux box as the WindPulse red-team attacker, in one command. Run ON Kali.
#
# It installs the few helpers the kit needs (the heavy tools — nmap, hydra, sqlmap, nikto —
# already ship with Kali), fetches the red-team kit, and writes a starter redteam.ini.
#
#   FOR YOUR OWN CLUSTER ONLY. The scripted attacks are scoped by a safety guard
#   (private targets + an ownership flag); the raw Kali tools are not, so you are
#   responsible for only ever pointing them at your own private cluster.
#
# Usage (on Kali):
#   ./setup-kali.sh                       # clone the kit from GitHub (private repo -> token)
#   KIT_FROM=~/windpulse-redteam ./setup-kali.sh   # or use a folder rsync'd from the laptop
set -euo pipefail

DEST="${DEST:-$HOME/redteam}"
REPO="${REPO:-https://github.com/SamukeloMagagula/PI-Cluster-Monitoring-system.git}"

echo "[1/4] installing helpers (sshpass + ssh client; nmap/hydra are preinstalled on Kali) ..."
sudo apt-get update -y
sudo apt-get install -y sshpass openssh-client python3 git

echo "[2/4] fetching the red-team kit into $DEST ..."
mkdir -p "$DEST"
if [ -n "${KIT_FROM:-}" ] && [ -d "$KIT_FROM" ]; then
    cp -r "$KIT_FROM"/. "$DEST"/
    echo "    copied from $KIT_FROM"
elif [ ! -e "$DEST/attacks.py" ]; then
    # sparse clone of just tools/redteam (private repo: Git prompts for a GitHub token)
    tmp="$(mktemp -d)"
    git clone --filter=blob:none --no-checkout "$REPO" "$tmp/wp"
    ( cd "$tmp/wp" && git sparse-checkout set tools/redteam && git checkout )
    cp -r "$tmp/wp/tools/redteam"/. "$DEST"/
    rm -rf "$tmp"
    echo "    cloned tools/redteam from $REPO"
else
    echo "    kit already present, leaving it as is"
fi
chmod +x "$DEST"/*.sh 2>/dev/null || true

echo "[3/4] starter redteam.ini ..."
if [ ! -f "$DEST/redteam.ini" ] && [ -f "$DEST/redteam.example.ini" ]; then
    cp "$DEST/redteam.example.ini" "$DEST/redteam.ini"
    echo "    wrote $DEST/redteam.ini — EDIT [cluster] allow to your cluster's private range"
fi

echo "[4/4] attack tools available on this Kali:"
for t in nmap hydra ncrack medusa sqlmap nikto sshpass python3; do
    printf "    %-9s %s\n" "$t" "$(command -v "$t" >/dev/null && echo present || echo MISSING)"
done

cat <<EOF

Done. The attacker is set up in $DEST.

  cd $DEST
  # edit redteam.ini -> [cluster] allow = <your cluster's private range>

  ./kali-attacks.sh recon   <pi-ip>            # nmap            -> port-scan incident
  ./kali-attacks.sh brute   <pi-ip> <user>     # hydra           -> brute-force (blocked)
  PASSWORD='pw' ./kali-attacks.sh breakin <pi-ip> <user>   # hydra+pw -> BREAK-IN
  python3 attacks.py scenario --target <pi-ip> --i-own-this-cluster   # guarded kit

For the two-Pi show and the defences on the Pis, see tools/redteam/README.md.
EOF
