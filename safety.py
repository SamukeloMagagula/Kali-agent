"""Scope guard for the red-team demo kit.

Every attack script must pass its target through `check_target` before doing anything.
A target is allowed only when it is (1) a private address, and (2) inside the owner's
declared cluster allowlist in redteam.ini. This keeps the demo pointed at the owner's
own cluster and nothing else. Standard library only, Python 3.9+.
"""
from __future__ import annotations

import configparser
import ipaddress
import os
import socket
from typing import List, Optional

CONFIRM_FLAG = "--i-own-this-cluster"


class NotAllowed(Exception):
    """Raised when a target is outside the allowlist or is not a private address."""


def _networks(text: str) -> List[ipaddress._BaseNetwork]:
    nets: List[ipaddress._BaseNetwork] = []
    for part in text.replace("\n", ",").split(","):
        part = part.strip()
        if not part:
            continue
        nets.append(ipaddress.ip_network(part, strict=False))
    return nets


def load_allow(path: str) -> List[ipaddress._BaseNetwork]:
    """The cluster allowlist from redteam.ini's [cluster] allow, or raise if missing/empty."""
    if not os.path.exists(path):
        raise NotAllowed(
            "No config at %s. Copy redteam.example.ini to redteam.ini and set [cluster] allow "
            "to your own cluster's private range before running any attack." % path)
    cfg = configparser.ConfigParser()
    cfg.read(path)
    allow = cfg.get("cluster", "allow", fallback="").strip()
    if not allow:
        raise NotAllowed("[cluster] allow is empty in %s; set it to your cluster's range." % path)
    nets = _networks(allow)
    if not nets:
        raise NotAllowed("[cluster] allow in %s has no valid networks." % path)
    for n in nets:
        if not n.is_private:
            raise NotAllowed(
                "%s in the allowlist is not a private range. The demo may only target your own "
                "private cluster." % n)
    return nets


def resolve(target: str) -> List[str]:
    """Every IP a target name resolves to (so a hostname cannot smuggle in a public address)."""
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, None)
    except socket.gaierror as exc:
        raise NotAllowed("cannot resolve %s: %s" % (target, exc))
    return sorted({info[4][0] for info in infos})


def check_target(target: str, config_path: str, confirmed: bool) -> str:
    """Return the first allowed IP for `target`, or raise NotAllowed.

    `confirmed` must be True (the caller passed CONFIRM_FLAG). Every address the target
    resolves to must be private and inside the allowlist.
    """
    if not confirmed:
        raise NotAllowed(
            "Refusing to attack %s without %s. This kit is only for your own cluster." % (
                target, CONFIRM_FLAG))
    nets = load_allow(config_path)
    ips = resolve(target)
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if not addr.is_private:
            raise NotAllowed("%s resolves to %s, which is not a private address." % (target, ip))
        if not any(addr in n for n in nets):
            raise NotAllowed(
                "%s (%s) is not in the cluster allowlist. Add its range to [cluster] allow in "
                "redteam.ini if it is really yours." % (target, ip))
    return ips[0]


def default_config() -> str:
    """redteam.ini next to the kit, overridable with DEVMON_REDTEAM_INI."""
    env = os.environ.get("DEVMON_REDTEAM_INI")
    if env:
        return env
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "redteam.ini")
