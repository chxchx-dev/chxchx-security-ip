import pytest

from chxchx_security.config import Settings
from chxchx_security.services import audit
from chxchx_security.utils.process import CmdResult


def settings():
    return Settings(
        app_name="test",
        tor_socks_host="127.0.0.1",
        tor_socks_port=9050,
        tor_check_url="https://check.torproject.org/api/ip",
        http_timeout_seconds=10,
        allow_direct_network_tests=False,
        enable_runtime_logs=False,
        log_level="WARNING",
    )


def test_doctor_reports_required_dependencies(monkeypatch):
    monkeypatch.setattr(audit, "exists", lambda command: command != "firewall-cmd")
    monkeypatch.setattr(audit, "service_state", lambda: "active")
    monkeypatch.setattr(audit, "socks_reachable", lambda _settings: True)
    monkeypatch.setattr(audit, "run", lambda *_args, **_kwargs: CmdResult(True, 0, "yes", ""))
    monkeypatch.setattr(audit.glob, "glob", lambda _pattern: [])

    checks = audit.doctor(settings())

    assert checks
    assert all(check.ok for check in checks)
    assert {check.name for check in checks} == {
        "OS",
        "Tor binary",
        "torsocks",
        "curl",
        "NetworkManager CLI",
        "Tor service",
        "Tor SOCKS",
        "System clock",
        "Session Tor drop-ins",
    }


def test_doctor_flags_stale_session_dropins(monkeypatch):
    monkeypatch.setattr(
        audit.glob, "glob", lambda _pattern: ["/etc/tor/torrc.d/chxsec-demo.conf"]
    )

    check = audit._session_dropin_check()

    assert check.ok is False
    assert "session destroy" in check.detail


@pytest.mark.parametrize(
    ("release", "manager"),
    [
        ({"ID": "fedora", "NAME": "Fedora Linux", "VERSION_ID": "43"}, "dnf"),
        ({"ID": "ubuntu", "NAME": "Ubuntu", "VERSION_ID": "24.04"}, "apt-get"),
        ({"ID": "kali", "NAME": "Kali GNU/Linux", "VERSION_ID": "2026.1"}, "apt-get"),
    ],
)
def test_doctor_accepts_supported_install_targets(monkeypatch, release, manager):
    monkeypatch.setattr(audit, "_os_release_data", lambda: release)
    monkeypatch.setattr(audit.platform, "system", lambda: "Linux")
    monkeypatch.setattr(audit, "exists", lambda command: command == manager)

    check = audit._os_check()

    assert check.ok
    assert "unsupported" not in check.detail


def test_doctor_rejects_unsupported_distro(monkeypatch):
    monkeypatch.setattr(audit, "_os_release_data", lambda: {"ID": "debian", "NAME": "Debian"})
    monkeypatch.setattr(audit.platform, "system", lambda: "Linux")
    monkeypatch.setattr(audit, "exists", lambda _command: True)

    check = audit._os_check()

    assert not check.ok
    assert "unsupported" in check.detail
