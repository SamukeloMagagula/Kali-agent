#!/usr/bin/env bash
# Automate a CHANGING MIX of attacks, so the hub shows different incident types over time
# instead of one attack on repeat. Run it from where attacks.py and redteam.ini live.
#
# Best spot: ON a monitored Pi, targeting its own loopback (127.0.0.1). The safety guard
# allows loopback, and that Pi's agent reports the resulting events to the hub, so the
# dashboard lights up with real, varied incidents. (Or set TARGET to a PRIVATE cluster IP.)
#
#   ./auto-attacks.sh                      # rotate attacks on 127.0.0.1 every 30s, forever
#   TARGET=192.168.1.22 INTERVAL=20 ./auto-attacks.sh
#   RANDOMIZE=1 ./auto-attacks.sh          # pick a random attack each round
#   ROUNDS=6 ./auto-attacks.sh             # stop after 6 attacks
#
# Extra attack types switch on when you provide what they need:
#   WEB_URL=http://127.0.0.1/dvwa/sqli/                  -> adds web-sqli and web-xss
#   DEVMON_DEMO_PASSWORD=... DEMO_USER=pidemo            -> adds ssh-login (needs sshpass;
#                                                           shows a break-in)
set -euo pipefail
cd "$(dirname "$0")"

TARGET="${TARGET:-127.0.0.1}"
INTERVAL="${INTERVAL:-30}"      # seconds between attacks
ROUNDS="${ROUNDS:-0}"          # 0 = forever
CONF="${CONF:-redteam.ini}"
CSV="${CSV:-auto-timeline.csv}"
OWN="--i-own-this-cluster"
PY="$(command -v python3 || command -v python)"

# Build the rotation from what is available on this box.
ATTACKS=(port-scan ssh-bruteforce backdoor)
[ -n "${WEB_URL:-}" ] && ATTACKS+=(web-sqli web-xss)
[ -n "${DEVMON_DEMO_PASSWORD:-}" ] && ATTACKS+=(ssh-login)

fire() {
  case "$1" in
    port-scan)      "$PY" attacks.py port-scan      --target "$TARGET" --ports 1-300 --csv "$CSV" --config "$CONF" $OWN ;;
    ssh-bruteforce) "$PY" attacks.py ssh-bruteforce --target "$TARGET" --attempts 12  --csv "$CSV" --config "$CONF" $OWN ;;
    ssh-login)      "$PY" attacks.py ssh-login      --target "$TARGET" --user "${DEMO_USER:-pidemo}" --spray 6 --csv "$CSV" --config "$CONF" $OWN ;;
    backdoor)       "$PY" attacks.py backdoor --port "${BD_PORT:-42000}" --config "$CONF" $OWN; sleep 6
                    "$PY" attacks.py backdoor --clean --config "$CONF" $OWN ;;
    web-sqli)       "$PY" attacks.py web-sqli --web-url "$WEB_URL" --csv "$CSV" --config "$CONF" $OWN ;;
    web-xss)        "$PY" attacks.py web-xss  --web-url "$WEB_URL" --csv "$CSV" --config "$CONF" $OWN ;;
  esac
}

echo "auto-attacks: target=$TARGET  every ${INTERVAL}s  rotation: ${ATTACKS[*]}"
echo "(Ctrl-C to stop)"
i=0; count=0
while :; do
  if [ "${RANDOMIZE:-0}" = "1" ]; then
    a="${ATTACKS[$((RANDOM % ${#ATTACKS[@]}))]}"
  else
    a="${ATTACKS[$((i % ${#ATTACKS[@]}))]}"
  fi
  echo "=== $(date +%H:%M:%S)  [$a]  ->  $TARGET ==="
  fire "$a" || echo "  ($a failed or skipped)"
  i=$((i + 1)); count=$((count + 1))
  if [ "$ROUNDS" -gt 0 ] && [ "$count" -ge "$ROUNDS" ]; then
    echo "done ($count attacks). Timeline: $CSV"
    break
  fi
  sleep "$INTERVAL"
done
