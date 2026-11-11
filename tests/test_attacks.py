import os
import sys

import pytest

KIT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.abspath(KIT))

import attacks  # noqa: E402
import payloads  # noqa: E402


def test_parse_ports_range_and_list():
    assert attacks.parse_ports("1-3,22") == [1, 2, 3, 22]


@pytest.mark.parametrize("bad", ["", "0-1", "70000", "abc"])
def test_parse_ports_rejects(bad):
    with pytest.raises(Exception):
        attacks.parse_ports(bad)


def test_sqli_payloads_are_non_destructive():
    for p in payloads.SQLI:
        low = p.lower()
        assert "drop " not in low and "delete " not in low and "truncate" not in low
    assert payloads.SQLI and payloads.XSS


def test_guard_refuses_without_confirmation(tmp_path, capsys):
    ini = tmp_path / "redteam.ini"
    ini.write_text("[cluster]\nallow = 192.168.1.0/24\n", encoding="utf-8")
    ns = __import__("argparse").Namespace(config=str(ini), confirmed=False)
    with pytest.raises(SystemExit):
        attacks.guard(ns, "192.168.1.21")


def test_guard_refuses_target_outside_allow(tmp_path):
    ini = tmp_path / "redteam.ini"
    ini.write_text("[cluster]\nallow = 192.168.1.0/24\n", encoding="utf-8")
    ns = __import__("argparse").Namespace(config=str(ini), confirmed=True)
    with pytest.raises(SystemExit):
        attacks.guard(ns, "10.9.9.9")


def test_url_host():
    assert attacks._url_host("http://192.168.1.21/dvwa/sqli/?id=1") == "192.168.1.21"


def test_backdoor_path_in_tmp():
    assert attacks._backdoor_path().endswith(attacks.BACKDOOR_FILE)


def test_parser_builds_all_subcommands():
    parser = attacks.build_parser()
    for cmd in ("ssh-bruteforce", "ssh-login", "db-bruteforce", "port-scan", "web-sqli",
                "web-xss", "backdoor", "scenario"):
        args = parser.parse_args([cmd] + (["--target", "192.168.1.21"]
                                          if cmd not in ("backdoor", "web-sqli", "web-xss")
                                          else ["--web-url", "http://192.168.1.21/"]
                                          if cmd.startswith("web") else []))
        assert args.cmd == cmd


def test_ssh_login_defaults():
    args = attacks.build_parser().parse_args(["ssh-login", "--target", "192.168.1.21"])
    assert args.user == "pidemo" and args.spray == 6
    assert args.password_env == attacks.DEMO_PW_ENV


def test_demo_password_from_arg_then_env(monkeypatch):
    import argparse
    monkeypatch.delenv(attacks.DEMO_PW_ENV, raising=False)
    assert attacks._demo_password(argparse.Namespace(password="s3cret")) == "s3cret"
    monkeypatch.setenv("MY_PW", "fromenv")
    ns = argparse.Namespace(password=None, password_env="MY_PW")
    assert attacks._demo_password(ns) == "fromenv"


def test_demo_password_missing_exits(monkeypatch):
    import argparse
    monkeypatch.delenv(attacks.DEMO_PW_ENV, raising=False)
    with pytest.raises(SystemExit):
        attacks._demo_password(argparse.Namespace(password=None, password_env=attacks.DEMO_PW_ENV))


def test_ssh_login_refuses_target_outside_allow(tmp_path, monkeypatch):
    import argparse
    monkeypatch.setenv(attacks.DEMO_PW_ENV, "x")
    ini = tmp_path / "redteam.ini"
    ini.write_text("[cluster]\nallow = 192.168.1.0/24\n", encoding="utf-8")
    ns = argparse.Namespace(target="10.9.9.9", config=str(ini), confirmed=True,
                            password=None, password_env=attacks.DEMO_PW_ENV, spray=0,
                            port=22, user="pidemo", run="true", delay=0.0, csv="")
    with pytest.raises(SystemExit):
        attacks.ssh_login(ns)
