from chxchx_security.config import Settings
from chxchx_security.services import tor
from chxchx_security.services.tor import protected_argv
from chxchx_security.utils.process import CmdResult


def settings():
    return Settings(
        app_name="x",
        tor_socks_host="127.0.0.1",
        tor_socks_port=9050,
        tor_check_url="https://check.torproject.org/api/ip",
        http_timeout_seconds=10,
        allow_direct_network_tests=False,
        enable_runtime_logs=False,
        log_level="WARNING",
    )


def test_protected_argv_isolates():
    argv = protected_argv(settings(), ["curl", "https://example.com"])
    assert argv[:2] == ["torsocks", "--isolate"]
    assert "curl" in argv


def test_verify_retries_transient_request(monkeypatch):
    responses = iter(
        [
            CmdResult(False, 35, "", "TLS connection failed"),
            CmdResult(True, 0, '{"IsTor": true, "IP": "203.0.113.42"}', ""),
        ]
    )
    calls = []

    monkeypatch.setattr(tor, "exists", lambda command: command == "curl")
    monkeypatch.setattr(tor, "socks_reachable", lambda _settings: True)
    monkeypatch.setattr(tor, "run", lambda argv, **kwargs: calls.append(argv) or next(responses))
    monkeypatch.setattr(tor.time, "sleep", lambda _seconds: None)

    result = tor.verify(settings())

    assert result.ok is True
    assert result.error_code is None
    assert len(calls) == 2


def test_verify_classifies_timeout(monkeypatch):
    monkeypatch.setattr(tor, "exists", lambda command: command == "curl")
    monkeypatch.setattr(tor, "socks_reachable", lambda _settings: True)
    monkeypatch.setattr(
        tor,
        "run",
        lambda _argv, **_kwargs: CmdResult(False, 124, "", "timed out"),
    )
    monkeypatch.setattr(tor.time, "sleep", lambda _seconds: None)

    result = tor.verify(settings())

    assert result.ok is False
    assert result.error_code == "timeout"


def test_protected_run_requires_verified_route(monkeypatch):
    monkeypatch.setattr(tor, "exists", lambda command: command == "torsocks")
    monkeypatch.setattr(
        tor,
        "verify",
        lambda _settings: tor.TorVerification(
            False, False, None, "Endpoint did not confirm Tor", "not_tor"
        ),
    )

    try:
        tor.run_protected(settings(), ["true"])
    except RuntimeError as exc:
        assert "not_tor" in str(exc)
    else:
        raise AssertionError("protected execution must refuse an unverified route")

def test_stop_service_uses_systemctl(monkeypatch):
    commands = []
    expected = object()
    monkeypatch.setattr(tor, "exists", lambda command: command == "systemctl")
    monkeypatch.setattr(
        tor,
        "run",
        lambda argv, timeout: commands.append((argv, timeout)) or expected,
    )

    assert tor.stop_service() is expected
    assert commands == [(["sudo", "systemctl", "stop", "tor.service"], 30)]
