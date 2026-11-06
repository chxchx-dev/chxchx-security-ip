from chxchx_security.config import Settings
from chxchx_security.services import tor
from chxchx_security.services.tor import protected_argv
from chxchx_security.utils.process import CmdResult


def settings(**overrides):
    values = dict(
        app_name="x",
        tor_socks_host="127.0.0.1",
        tor_socks_port=9050,
        tor_check_url="https://check.torproject.org/api/ip",
        http_timeout_seconds=10,
        allow_direct_network_tests=False,
        enable_runtime_logs=False,
        log_level="WARNING",
    )
    values.update(overrides)
    return Settings(**values)


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
        tor, "ensure_service", lambda _settings: CmdResult(True, 0, "", "")
    )
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


def test_ensure_service_starts_tor_when_needed(monkeypatch):
    actions = []
    monkeypatch.setattr(tor, "service_state", lambda: "inactive")
    monkeypatch.setattr(tor, "start_service", lambda: actions.append("start") or CmdResult(True, 0, "", ""))
    monkeypatch.setattr(tor, "_wait_for_socks", lambda _settings: True)

    result = tor.ensure_service(settings())

    assert result.ok is True
    assert actions == ["start"]


def test_ensure_service_respects_opt_out(monkeypatch):
    monkeypatch.setattr(tor, "service_state", lambda: "inactive")

    result = tor.ensure_service(settings(auto_start_tor=False))

    assert result.ok is False
    assert "CHXSEC_AUTO_START_TOR" in result.stderr


def test_rotate_identity_reports_a_changed_exit_ip(monkeypatch):
    calls = []
    monkeypatch.setattr(tor, "request_newnym", lambda _settings: calls.append(True))
    monkeypatch.setattr(tor.time, "sleep", lambda _seconds: None)
    responses = iter(
        [
            tor.TorVerification(True, True, "203.0.113.10", "ok"),
            tor.TorVerification(True, True, "203.0.113.10", "ok"),
            tor.TorVerification(True, True, "198.51.100.20", "ok"),
        ]
    )
    monkeypatch.setattr(tor, "verify", lambda _settings, reveal_ip=False: next(responses))

    result = tor.rotate_identity(settings())

    assert result.ok is True
    assert result.changed is True
    assert result.previous_ip == "203.0.113.10"
    assert result.current_ip == "198.51.100.20"
    assert calls == [True, True]


def test_rotate_identity_explains_control_failure(monkeypatch):
    monkeypatch.setattr(
        tor,
        "verify",
        lambda _settings, reveal_ip=False: tor.TorVerification(
            True, True, "203.0.113.10", "ok"
        ),
    )
    monkeypatch.setattr(
        tor,
        "request_newnym",
        lambda _settings: (_ for _ in ()).throw(
            tor.TorControlError("control unavailable")
        ),
    )

    result = tor.rotate_identity(settings())

    assert result.ok is False
    assert result.error_code == "control_unavailable"
    assert "--restart" in result.detail


def test_rotate_identity_restart_fallback(monkeypatch):
    commands = []
    monkeypatch.setattr(
        tor,
        "verify",
        lambda _settings, reveal_ip=False: tor.TorVerification(
            True, True, "203.0.113.10", "ok"
        ),
    )
    monkeypatch.setattr(tor.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(tor, "_wait_for_socks", lambda _settings: True)
    monkeypatch.setattr(
        tor,
        "run",
        lambda argv, **kwargs: commands.append(argv) or CmdResult(True, 0, "", ""),
    )

    result = tor.rotate_identity(settings(), restart=True)

    assert result.ok is True
    assert commands[0] == ["sudo", "systemctl", "restart", "tor.service"]
