import os
import sys

import pytest

KIT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.abspath(KIT))

import safety  # noqa: E402


def write_ini(tmp_path, allow):
    p = tmp_path / "redteam.ini"
    p.write_text("[cluster]\nallow = %s\n" % allow, encoding="utf-8")
    return str(p)


def test_missing_config_refuses(tmp_path):
    with pytest.raises(safety.NotAllowed):
        safety.load_allow(str(tmp_path / "nope.ini"))


def test_empty_allow_refuses(tmp_path):
    with pytest.raises(safety.NotAllowed):
        safety.load_allow(write_ini(tmp_path, ""))


def test_public_range_refuses(tmp_path):
    with pytest.raises(safety.NotAllowed):
        safety.load_allow(write_ini(tmp_path, "8.8.8.0/24"))


def test_private_range_loads(tmp_path):
    nets = safety.load_allow(write_ini(tmp_path, "192.168.1.0/24, 10.0.0.0/24"))
    assert len(nets) == 2


def test_resolve_passthrough_ip():
    assert safety.resolve("192.168.1.5") == ["192.168.1.5"]


def test_check_target_requires_confirmation(tmp_path):
    ini = write_ini(tmp_path, "192.168.1.0/24")
    with pytest.raises(safety.NotAllowed):
        safety.check_target("192.168.1.21", ini, confirmed=False)


def test_check_target_allows_private_in_list(tmp_path):
    ini = write_ini(tmp_path, "192.168.1.0/24")
    assert safety.check_target("192.168.1.21", ini, confirmed=True) == "192.168.1.21"


def test_check_target_rejects_outside_list(tmp_path):
    ini = write_ini(tmp_path, "192.168.1.0/24")
    with pytest.raises(safety.NotAllowed):
        safety.check_target("192.168.2.21", ini, confirmed=True)


def test_check_target_rejects_public(tmp_path):
    ini = write_ini(tmp_path, "192.168.1.0/24")
    with pytest.raises(safety.NotAllowed):
        safety.check_target("8.8.8.8", ini, confirmed=True)
