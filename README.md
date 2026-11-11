# Kali-agent — WindPulse Red-Team Attack Kit

Scoped attack tooling for validating WindPulse detectors against your own cluster, run from a
Kali Linux box. Every network attack is gated by `safety.py`: the target must be a private
address on an allowlist, and `--i-own-this-cluster` must be passed. The scripts are
non-destructive, and each maps to a detector in the hub.

This repo is one of three that make up WindPulse:

| Repo | Role |
|---|---|
| [sxmukelo](https://github.com/SamukeloMagagula/sxmukelo) | The hub: detection, correlation, dashboard |
| [Pi-Agents](https://github.com/SamukeloMagagula/Pi-Agents) | The agent that runs on each monitored node, plus defences |
| **Kali-agent** (this repo) | The attacker tooling |

## Setup on Kali

```sh
./deploy/setup-kali.sh          # installs sshpass, fetches dependencies, writes redteam.ini
# edit redteam.ini -> [cluster] allow = <your cluster's private range>
```

## Attacks

```sh
python3 attacks.py ssh-bruteforce --target 192.168.1.21 --i-own-this-cluster
python3 attacks.py ssh-login --target 192.168.1.21 --user pidemo --spray 6 --i-own-this-cluster
python3 attacks.py port-scan --target 192.168.1.21 --i-own-this-cluster
python3 attacks.py web-sqli --web-url http://192.168.1.21/dvwa/sqli/ --i-own-this-cluster
python3 attacks.py scenario --target 192.168.1.21 --i-own-this-cluster

# real industry tools (nmap/hydra/sqlmap/nikto), same scope discipline:
./kali-attacks.sh recon   <pi-ip>
./kali-attacks.sh brute   <pi-ip> <user>
PASSWORD='pw' ./kali-attacks.sh breakin <pi-ip> <user>
```

## The two-Pi demo

`demo-run.sh` runs the full show: Pi-1 (the attacker *has* the password → a BREAK-IN), then
Pi-2 (the attacker does not → brute-force, blocked). See the comments in each `demo-*.sh`
script, and `deploy-pis.sh` to set up both target Pis from Kali in one command.

## Files

- `safety.py` — the scope guard (allowlist, private-only, confirmation flag)
- `payloads.py` — non-destructive SQLi/XSS probes and throwaway credentials
- `attacks.py` — the attack subcommands and the `scenario` runner
- `kali-attacks.sh` — drives real Kali tools (nmap, hydra, sqlmap, nikto), mapped to detectors
- `auto-attacks.sh` — rotates through a varied mix of attacks for a self-running demo
- `redteam.example.ini` — copy to `redteam.ini` and edit
