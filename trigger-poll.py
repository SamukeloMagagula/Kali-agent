#!/usr/bin/env python3
"""Run on Kali. Polls the hub's /api/demo/pending for an attack someone queued from the
dashboard's /demo page, then runs the matching kali-attacks.sh scenario and reports back.

The hub only ever says "run X against device Y"; it cannot make this box attack anything
Y resolves to outside [cluster] allow in redteam.ini — safety.check_target() still enforces
that here, exactly as it would for a manual run. Standard library only, Python 3.9+.

  python3 trigger-poll.py [--config redteam.ini]
"""
from __future__ import annotations

import argparse
import configparser
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

import safety

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "kali-attacks.sh")


def _cfg(path: str) -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if not cfg.read(path):
        sys.exit("no config at %s — copy redteam.example.ini to redteam.ini first" % path)
    if not cfg.has_section("demo"):
        sys.exit("add a [demo] section to %s (see redteam.example.ini)" % path)
    return cfg


def _request(url: str, api_key: str, method: str = "GET", body: dict = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"X-Api-Key": api_key, "X-Kali-Id": socket_id(),
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def socket_id() -> str:
    import socket
    return socket.gethostname()[:60]


def run_scenario(scenario: str, target: str, user: str) -> str:
    cmd = {"recon": ["recon", target],
           "brute": ["brute", target, user],
           "breakin": ["breakin", target, user],
           "web": ["web", target],
           "all": ["all", target, user]}.get(scenario)
    if cmd is None:
        return "unknown scenario: %s" % scenario
    env = dict(os.environ, CONFIRM="1")
    proc = subprocess.run(["bash", SCRIPT] + cmd, env=env, capture_output=True, text=True,
                          timeout=300)
    tail = (proc.stdout or "") + (proc.stderr or "")
    return tail[-1800:]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(HERE, "redteam.ini"))
    args = ap.parse_args()
    cfg = _cfg(args.config)
    hub_url = cfg.get("demo", "hub_url").rstrip("/")
    api_key = cfg.get("demo", "api_key")
    poll_s = cfg.getfloat("demo", "poll_s", fallback=4.0)
    default_user = cfg.get("demo", "default_user", fallback="pidemo")
    if "paste-the-key" in api_key:
        sys.exit("set api_key in [demo] from the hub's /demo page before polling")

    print("trigger-poll: watching %s every %gs (Ctrl+C to stop)" % (hub_url, poll_s))
    while True:
        try:
            resp = _request("%s/api/demo/pending" % hub_url, api_key)
            pending = resp.get("pending")
            if pending is None:
                time.sleep(poll_s)
                continue
            target = pending.get("target_ip")
            print("[%s] got %s -> %s" % (time.strftime("%H:%M:%S"), pending["scenario"], target))
            if not target:
                result = "no target IP on that device; skipped"
            else:
                try:
                    ip = safety.check_target(target, args.config, confirmed=True)
                except safety.NotAllowed as exc:
                    result = "refused: %s" % exc
                else:
                    result = run_scenario(pending["scenario"], ip, default_user)
            print(result[-400:])
            _request("%s/api/demo/done" % hub_url, api_key, method="POST",
                     body={"id": pending["id"], "result": result})
        except urllib.error.URLError as exc:
            print("poll failed: %s" % exc, file=sys.stderr)
        except KeyboardInterrupt:
            print("\nstopped.")
            return 0
        except Exception as exc:  # a bad/odd response must not kill the loop mid-demo
            print("unexpected error: %s" % exc, file=sys.stderr)
        time.sleep(poll_s)


if __name__ == "__main__":
    sys.exit(main())
