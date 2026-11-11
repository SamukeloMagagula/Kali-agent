#!/usr/bin/env python3
"""Red-team demo attacks against the owner's OWN cluster (authorized use only).

Every network attack is scoped by safety.check_target: the target must be a private
address inside the allowlist in redteam.ini, and --i-own-this-cluster must be passed.
The attacks are non-destructive and map to the monitor's detectors:

    ssh-bruteforce   failed SSH logins        -> brute-force incident
    ssh-login        known-password login     -> remote-login / BREAK-IN (login in an attack)
    db-bruteforce    failed MariaDB logins    -> brute-force incident
    port-scan        many ports in a burst    -> port-scan incident
    web-sqli         SQL-injection probes     -> web-attack incident (Phase 9 detector)
    web-xss          reflected-XSS probes     -> web-attack incident (Phase 9 detector)
    backdoor         benign simulated backdoor-> unexpected-port / remote-access finding
    scenario         a timed sequence of the above for the live demo

Standard library only, Python 3.9+. Run on the spare attacker Pi:

    python3 attacks.py ssh-bruteforce --target 192.168.1.21 --i-own-this-cluster
    python3 attacks.py scenario --target 192.168.1.21 --web-url http://192.168.1.21/dvwa/ \\
            --i-own-this-cluster
"""
from __future__ import annotations

import argparse
import csv
import os
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional

import payloads
import safety

TIMELINE_FIELDS = ("ts", "step", "target", "detail")
BACKDOOR_DIR = "/tmp"
BACKDOOR_FILE = ".devmon-demo-backdoor.py"
BACKDOOR_CODE = """# Benign demo backdoor: listens on a port so the monitor flags an unexpected
# open port / remote-access process. It does nothing else: no shell, no payload.
import socket, sys, time
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(1)
while True:
    try:
        conn, _ = s.accept()
        conn.sendall(b"devmon demo backdoor: benign, no shell here\\n")
        conn.close()
    except OSError:
        time.sleep(1)
"""


def now_iso(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts))


def timeline(args: argparse.Namespace, step: str, target: str, detail: str = "") -> None:
    print("[%s] %-14s %-16s %s" % (now_iso(time.time()), step, target, detail), flush=True)
    if not getattr(args, "csv", None):
        return
    new = not os.path.exists(args.csv) or os.path.getsize(args.csv) == 0
    with open(args.csv, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=TIMELINE_FIELDS)
        if new:
            w.writeheader()
        w.writerow({"ts": now_iso(time.time()), "step": step, "target": target, "detail": detail})


def guard(args: argparse.Namespace, target: str) -> str:
    """Scope check; exits with a clear message if the target is not allowed."""
    try:
        return safety.check_target(target, args.config, args.confirmed)
    except safety.NotAllowed as exc:
        sys.exit("refused: %s" % exc)


# ---- SSH brute force -------------------------------------------------------------------


def ssh_bruteforce(args: argparse.Namespace) -> None:
    guard(args, args.target)
    null = "NUL" if os.name == "nt" else "/dev/null"
    timeline(args, "ssh-brute", args.target, "%d attempts on port %d" % (args.attempts, args.port))
    for i in range(args.attempts):
        user = args.user or payloads.SPRAY_USERS[i % len(payloads.SPRAY_USERS)]
        # BatchMode + a bogus user and no key: every attempt is a failed login on the target.
        subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=" + null, "-o", "ConnectTimeout=5",
                        "-o", "PreferredAuthentications=password,keyboard-interactive",
                        "-p", str(args.port), "%s@%s" % (user, args.target), "true"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        time.sleep(args.delay)
    timeline(args, "ssh-brute", args.target, "done")


# ---- SSH login with a known password: the attacker who "has" this Pi -------------------

DEMO_PW_ENV = "DEVMON_DEMO_PASSWORD"


def _demo_password(args: argparse.Namespace) -> str:
    """The known password for an owned target: from --password, else the named env var."""
    if getattr(args, "password", None):
        return args.password
    var = getattr(args, "password_env", None) or DEMO_PW_ENV
    pw = os.environ.get(var, "")
    if not pw:
        sys.exit("ssh-login needs the target's password: pass --password or set $%s." % var)
    return pw


def _failed_sprays(args: argparse.Namespace, n: int) -> None:
    """A short burst of wrong logins so a following success lands inside an attack window."""
    ssh_bruteforce(argparse.Namespace(
        target=args.target, port=args.port, attempts=n, user=None, delay=args.delay,
        confirmed=args.confirmed, config=args.config, csv=getattr(args, "csv", "")))


def ssh_login(args: argparse.Namespace) -> None:
    """Log in with a password the operator already knows (the attacker 'has' this Pi).

    With --spray N it first fires N wrong guesses, so the successful login falls inside a
    brute-force window and the hub records a BREAK-IN, not just a remote login. Needs the
    'sshpass' helper (on Kali: sudo apt install sshpass).
    """
    guard(args, args.target)
    password = _demo_password(args)
    if not _have_cmd("sshpass"):
        sys.exit("ssh-login needs 'sshpass' (on Kali: sudo apt install -y sshpass).")
    if args.spray > 0:
        timeline(args, "ssh-login", args.target,
                 "%d wrong guesses first, then the real password" % args.spray)
        _failed_sprays(args, args.spray)
        time.sleep(args.delay)
    null = "NUL" if os.name == "nt" else "/dev/null"
    env = dict(os.environ, SSHPASS=password)  # sshpass -e reads it from the environment, not argv
    timeline(args, "ssh-login", args.target, "authenticating as %s (we know the password)" % args.user)
    proc = subprocess.run(
        ["sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=" + null, "-o", "ConnectTimeout=8",
         "-o", "PreferredAuthentications=password", "-p", str(args.port),
         "%s@%s" % (args.user, args.target), args.run],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    if proc.returncode == 0:
        lines = (proc.stdout or "").strip().splitlines()
        timeline(args, "ssh-login", args.target,
                 "SUCCESS — shell as %s: %s" % (args.user, lines[0] if lines else "(no output)"))
    else:
        timeline(args, "ssh-login", args.target,
                 "login failed (rc=%d) — wrong password or password auth is off on the Pi"
                 % proc.returncode)


# ---- MariaDB brute force ---------------------------------------------------------------


def db_bruteforce(args: argparse.Namespace) -> None:
    guard(args, args.target)
    timeline(args, "db-brute", args.target, "%d attempts on port %d" % (args.attempts, args.port))
    try:
        import pymysql  # type: ignore
    except ImportError:
        pymysql = None
    if pymysql is None and not _have_cmd("mysql"):
        sys.exit("db-bruteforce needs either the pymysql package or the mysql client on this Pi.")
    for i in range(args.attempts):
        user = args.user or payloads.SPRAY_USERS[i % len(payloads.SPRAY_USERS)]
        pw = payloads.BAD_PASSWORDS[i % len(payloads.BAD_PASSWORDS)]
        if pymysql is not None:
            try:
                pymysql.connect(host=args.target, port=args.port, user=user, password=pw,
                                connect_timeout=5).close()
            except Exception:
                pass  # a failed login is the point
        else:
            subprocess.run(["mysql", "-h", args.target, "-P", str(args.port), "-u", user,
                            "-p" + pw, "-e", "SELECT 1"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        time.sleep(args.delay)
    timeline(args, "db-brute", args.target, "done")


def _have_cmd(name: str) -> bool:
    from shutil import which
    return which(name) is not None


# ---- port scan -------------------------------------------------------------------------


def parse_ports(text: str) -> List[int]:
    out: List[int] = []
    for part in text.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            out.extend(range(lo, hi + 1))
        elif part:
            out.append(int(part))
    if not out or not all(1 <= p <= 65535 for p in out):
        raise argparse.ArgumentTypeError("ports must be 1-65535, e.g. 1-1024 or 20,21,22,80")
    return out


def port_scan(args: argparse.Namespace) -> None:
    guard(args, args.target)
    timeline(args, "port-scan", args.target, "%d ports" % len(args.ports))
    for port in args.ports:
        try:
            with socket.create_connection((args.target, port), timeout=0.3):
                pass
        except OSError:
            pass
    timeline(args, "port-scan", args.target, "done")


# ---- web attacks -----------------------------------------------------------------------


def _url_host(url: str) -> str:
    host = urllib.parse.urlparse(url).hostname
    if not host:
        sys.exit("could not read a host from --web-url %r" % url)
    return host


def _send_web(url: str, param: str, value: str, timeout: float) -> int:
    sep = "&" if urllib.parse.urlparse(url).query else "?"
    full = "%s%s%s=%s" % (url, sep, param, urllib.parse.quote(value))
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # demo test app may be self-signed
    req = urllib.request.Request(full, headers={"User-Agent": "devmon-redteam-demo"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.getcode()
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, OSError):
        return 0


def _web_attack(args: argparse.Namespace, kind: str, values: List[str]) -> None:
    guard(args, _url_host(args.web_url))
    timeline(args, kind, args.web_url, "%d payloads on param %r" % (len(values), args.param))
    for value in values:
        code = _send_web(args.web_url, args.param, value, args.timeout)
        timeline(args, kind, args.web_url, "HTTP %s  %s" % (code or "no-response", value[:40]))
        time.sleep(args.delay)


def web_sqli(args: argparse.Namespace) -> None:
    _web_attack(args, "web-sqli", payloads.SQLI)


def web_xss(args: argparse.Namespace) -> None:
    _web_attack(args, "web-xss", payloads.XSS)


# ---- benign simulated backdoor (run ON a target Pi) ------------------------------------


def _backdoor_path() -> str:
    return os.path.join(BACKDOOR_DIR, BACKDOOR_FILE)


def backdoor(args: argparse.Namespace) -> None:
    """Simulate a compromise locally: a process from /tmp listening on an unexpected port.

    Benign — no shell, no payload. Run it ON a target Pi to show the monitor flag an
    unexpected open port / remote-access process. Remove it with --clean.
    """
    pidfile = _backdoor_path() + ".pid"
    if args.clean:
        _backdoor_clean(pidfile)
        print("backdoor sim removed.", flush=True)
        return
    if sys.platform.startswith("win"):
        sys.exit("The backdoor sim is for a Linux target Pi.")
    path = _backdoor_path()
    with open(path, "w", encoding="utf-8") as f:
        f.write(BACKDOOR_CODE)
    proc = subprocess.Popen([sys.executable, path, str(args.port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(pidfile, "w", encoding="utf-8") as f:
        f.write(str(proc.pid))
    timeline(args, "backdoor", socket.gethostname(),
             "listening on %d from %s (pid %d) — benign; remove with --clean"
             % (args.port, path, proc.pid))


def _backdoor_clean(pidfile: str) -> None:
    try:
        with open(pidfile, encoding="utf-8") as f:
            pid = int(f.read().strip())
        os.kill(pid, 15)
    except (OSError, ValueError):
        pass
    for p in (pidfile, _backdoor_path()):
        try:
            os.unlink(p)
        except OSError:
            pass


# ---- scenario --------------------------------------------------------------------------


def scenario(args: argparse.Namespace) -> None:
    """A timed demo: recon -> SSH brute force -> port scan -> web attacks. (The backdoor is
    run separately, on the target Pi.)"""
    guard(args, args.target)
    timeline(args, "scenario", args.target, "start")
    ssh_bruteforce(argparse.Namespace(**dict(vars(args), attempts=args.attempts, user=None)))
    time.sleep(args.gap)
    port_scan(argparse.Namespace(**dict(vars(args), ports=parse_ports("1-200"))))
    if args.web_url:
        time.sleep(args.gap)
        web_sqli(argparse.Namespace(**dict(vars(args), param=args.param)))
        time.sleep(args.gap)
        web_xss(argparse.Namespace(**dict(vars(args), param=args.param)))
    timeline(args, "scenario", args.target, "done — watch the /demo page on the hub")


# ---- command line ----------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument(safety.CONFIRM_FLAG, dest="confirmed", action="store_true",
                       help="required: confirms this is your own cluster")
        p.add_argument("--config", default=safety.default_config(),
                       help="redteam.ini with the cluster allowlist")
        p.add_argument("--csv", default="", help="append a timeline row per step to this file")
        p.add_argument("--delay", type=float, default=0.2, help="seconds between attempts")

    p = sub.add_parser("ssh-bruteforce", help="failed SSH logins")
    common(p)
    p.add_argument("--target", required=True)
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--attempts", type=int, default=12)
    p.add_argument("--user", default=None, help="one username to spray (default: rotate)")
    p.set_defaults(func=ssh_bruteforce)

    p = sub.add_parser("ssh-login", help="log in with a known password (owned Pi; can show a break-in)")
    common(p)
    p.add_argument("--target", required=True)
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--user", default="pidemo", help="account to log in as (default: pidemo)")
    p.add_argument("--password", default=None,
                   help="the known password (prefer --password-env to keep it out of the argv)")
    p.add_argument("--password-env", default=DEMO_PW_ENV,
                   help="env var holding the password (default: %s)" % DEMO_PW_ENV)
    p.add_argument("--spray", type=int, default=6,
                   help="wrong guesses before the real login (0 = straight in, no break-in)")
    p.add_argument("--run", default="id; hostname; echo devmon-demo-login-ok",
                   help="command to run once logged in")
    p.set_defaults(func=ssh_login)

    p = sub.add_parser("db-bruteforce", help="failed MariaDB logins")
    common(p)
    p.add_argument("--target", required=True)
    p.add_argument("--port", type=int, default=3306)
    p.add_argument("--attempts", type=int, default=12)
    p.add_argument("--user", default=None)
    p.set_defaults(func=db_bruteforce)

    p = sub.add_parser("port-scan", help="connect to many ports in a burst")
    common(p)
    p.add_argument("--target", required=True)
    p.add_argument("--ports", type=parse_ports, default=parse_ports("1-200"))
    p.set_defaults(func=port_scan)

    for name, func in (("web-sqli", web_sqli), ("web-xss", web_xss)):
        p = sub.add_parser(name, help="send %s detection probes" % name.split("-")[1].upper())
        common(p)
        p.add_argument("--web-url", required=True, help="test app URL, e.g. http://PI/dvwa/sqli/")
        p.add_argument("--param", default="id", help="query parameter to inject (default id)")
        p.add_argument("--timeout", type=float, default=5.0)
        p.set_defaults(func=func)

    p = sub.add_parser("backdoor", help="benign simulated backdoor (run ON a target Pi)")
    common(p)
    p.add_argument("--port", type=int, default=42000, help="unexpected port to listen on")
    p.add_argument("--clean", action="store_true", help="remove the backdoor sim and exit")
    p.set_defaults(func=backdoor, target="(local)")

    p = sub.add_parser("scenario", help="timed sequence for the live demo")
    common(p)
    p.add_argument("--target", required=True)
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--attempts", type=int, default=12)
    p.add_argument("--web-url", default="", help="optional test app URL for the web steps")
    p.add_argument("--param", default="id")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--gap", type=float, default=5.0, help="seconds between steps")
    p.set_defaults(func=scenario)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
