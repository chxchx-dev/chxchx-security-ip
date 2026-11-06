import pytest
import json

from chxchx_security import cli
from chxchx_security.services.audit import Check
from chxchx_security.services.global_plan import build_global_plan
from chxchx_security.services.global_runtime import GlobalResult, GlobalStatus
from chxchx_security.services.network import ConnectionInfo
from chxchx_security.services.tor import RotationResult, TorVerification
from chxchx_security.utils.process import CmdResult


def test_doctor_json_output(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "doctor",
        lambda _settings: [Check("Tor", True, "active"), Check("SOCKS", False, "down")],
    )

    exit_code = cli.main(["doctor", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert payload["ok"] is False
    assert payload["checks"][0] == {"name": "Tor", "ok": True, "detail": "active"}


def test_audit_alias_supports_json(monkeypatch, capsys):
    monkeypatch.setattr(cli, "doctor", lambda _settings: [Check("Tor", True, "active")])

    exit_code = cli.main(["audit", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["ok"] is True


def test_interactive_doctor_returns_failure_status(monkeypatch):
    answers = iter(["1", "", "0"])
    monkeypatch.setattr(cli.Prompt, "ask", lambda *_args, **_kwargs: next(answers))

    class TTYInput:
        def isatty(self):
            return True

    monkeypatch.setattr(cli.sys, "stdin", TTYInput())
    monkeypatch.setattr(cli, "doctor", lambda _settings: [Check("Tor", False, "down")])

    assert cli.main([]) == 1


def test_verify_json_masks_ip_by_default(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "verify",
        lambda _settings, reveal_ip=False: TorVerification(
            True, True, "203.0.x.x" if not reveal_ip else "203.0.113.42", "Tor path verified"
        ),
    )

    exit_code = cli.main(["tor", "verify", "--json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload == {
        "detail": "Tor path verified",
        "error": None,
        "ip": "203.0.x.x",
        "is_tor": True,
        "ok": True,
    }


def test_mac_list_hides_connection_name_by_default(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "active_connections",
        lambda: [ConnectionInfo("Private WiFi", "802-11-wireless")],
    )

    assert cli.main(["mac", "list"]) == 0
    output = capsys.readouterr().out

    assert "Private WiFi" not in output
    assert "Wi-Fi connection" in output


def test_session_plan_is_explicitly_non_executing(capsys):
    assert cli.main(["session", "plan", "demo", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["namespace"] == "chxsec-demo"
    assert payload["executable"] is False


def test_session_network_plan_is_explicitly_non_executing(capsys):
    assert cli.main(["session", "network-plan", "demo", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["subnet"] == "10.203.0.0/30"
    assert payload["executable"] is False


def test_session_tor_port_plan_is_explicitly_non_executing(capsys):
    assert cli.main(["session", "tor-port-plan", "10.203.0.1", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["directives"] == [
        "TransPort 10.203.0.1:9040",
        "DNSPort 10.203.0.1:5300",
    ]
    assert payload["executable"] is False


def test_session_firewall_plan_is_explicitly_non_executing(capsys):
    assert cli.main(["session", "firewall-plan", "demo", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["filter_table"] == "chxsec_2a97516c"
    assert payload["nat_table"] == "chxsec_nat_2a97516c"
    assert payload["executable"] is False
    assert "policy drop" not in payload["ruleset"]
    assert 'iifname "chxh-2a97516c" drop' in payload["ruleset"]


def test_session_network_apply_without_yes_is_dry_run(capsys):
    assert cli.main(["session", "network-apply", "demo", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["applied"] is False
    assert payload["commands"][0][-3:] == ["netns", "add", "chxsec-demo"]


def test_session_network_apply_rejects_bad_session_id(capsys):
    assert cli.main(["session", "network-apply", "Bad_ID"]) == 2


def test_session_firewall_apply_without_yes_is_dry_run(capsys):
    assert cli.main(["session", "firewall-apply", "demo", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["applied"] is False
    assert "policy drop" not in payload["ruleset"]
    assert payload["commands"][0][-3:] == ["table", "inet", "chxsec_2a97516c"]


def test_session_tor_port_apply_without_yes_is_dry_run(capsys):
    assert cli.main(["session", "tor-port-apply", "demo", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["applied"] is False
    assert "DNSPort 10.203.0.1:5300" in payload["config"]


def test_session_start_without_yes_is_dry_run(capsys, monkeypatch):
    monkeypatch.setattr(
        "chxchx_security.services.session_runtime.os.getuid", lambda: 1000
    )
    monkeypatch.setattr(
        "chxchx_security.services.session_runtime.os.getgid", lambda: 1000
    )
    assert cli.main(["session", "start", "--json", "demo", "--", "true"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["exit_code"] is None
    assert any("setpriv" in " ".join(c) for c in payload["commands"])


def test_session_start_requires_a_command(capsys):
    with pytest.raises(SystemExit):
        cli.main(["session", "start", "demo"])


def test_interactive_command_guide_returns_to_menu(monkeypatch, capsys):
    answers = iter(["9", "", "0"])
    monkeypatch.setattr(cli.Prompt, "ask", lambda *_args, **_kwargs: next(answers))

    class TTYInput:
        def isatty(self):
            return True

    monkeypatch.setattr(cli.sys, "stdin", TTYInput())

    assert cli.main([]) == 0

    output = capsys.readouterr().out
    assert "Guía rápida de comandos" in output
    assert "chxsec run -- curl https://example.com" in output
    assert "chxsec session start --yes demo -- curl https://example.com" in output
    assert output.count("¿Qué quieres hacer?") == 2

def test_interactive_run_splits_command_into_arguments(monkeypatch):
    answers = iter(["8", "curl 'https://example.com/path with space'", "", "0"])
    monkeypatch.setattr(cli.Prompt, "ask", lambda *_args, **_kwargs: next(answers))

    class TTYInput:
        def isatty(self):
            return True

    monkeypatch.setattr(cli.sys, "stdin", TTYInput())
    executed = []
    monkeypatch.setattr(
        cli,
        "run_protected",
        lambda _settings, command: executed.append(command) or 0,
    )

    assert cli.main([]) == 0
    assert executed == [["curl", "https://example.com/path with space"]]


def test_non_interactive_start_prints_help(monkeypatch, capsys):
    class PipedInput:
        def isatty(self):
            return False

    monkeypatch.setattr(cli.sys, "stdin", PipedInput())

    assert cli.main([]) == 0
    assert "usage: chxsec" in capsys.readouterr().out

def test_tor_stop_command_stops_the_service(monkeypatch):
    class Result:
        ok = True
        stdout = ""
        stderr = ""

    stopped = []
    monkeypatch.setattr(cli, "stop_service", lambda: stopped.append(True) or Result())

    assert cli.main(["tor", "stop"]) == 0
    assert stopped == [True]


def test_menu_stop_requires_confirmation(monkeypatch):
    answers = iter(["3", "", "0"])
    monkeypatch.setattr(cli.Prompt, "ask", lambda *_args, **_kwargs: next(answers))

    class TTYInput:
        def isatty(self):
            return True

    class Result:
        ok = True
        stdout = ""
        stderr = ""

    monkeypatch.setattr(cli.sys, "stdin", TTYInput())
    monkeypatch.setattr(cli.Confirm, "ask", lambda *_args, **_kwargs: True)
    stopped = []
    monkeypatch.setattr(cli, "stop_service", lambda: stopped.append(True) or Result())

    assert cli.main([]) == 0
    assert stopped == [True]


def _fake_global_runtime(monkeypatch, *, plan=None, start=None, stop=None, status=None):
    calls = {}

    class FakeRuntime:
        def plan(self, **kwargs):
            calls["plan"] = kwargs
            return plan

        def start(self, **kwargs):
            calls["start"] = kwargs
            return start

        def stop(self):
            calls["stop"] = True
            return stop

        def status(self):
            calls["status"] = True
            return status

    monkeypatch.setattr(cli, "GlobalRuntime", FakeRuntime)
    return calls


def test_global_plan_json_is_non_executing(monkeypatch, capsys):
    plan = build_global_plan(tor_uid=967)
    _fake_global_runtime(monkeypatch, plan=plan)

    assert cli.main(["global", "plan", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["tor_uid"] == 967
    assert payload["executable"] is False
    assert "meta l4proto tcp redirect to :9040" in payload["ruleset"]


def test_global_start_without_yes_is_a_dry_run(monkeypatch, capsys):
    plan = build_global_plan(tor_uid=967)
    result = GlobalResult(
        True, False, "dry-run; nothing was changed", (("nft", "-c", "-f"),), plan
    )
    calls = _fake_global_runtime(monkeypatch, plan=plan, start=result)

    assert cli.main(["global", "start"]) == 0
    output = capsys.readouterr().out

    assert calls["start"]["dry_run"] is True
    assert "Re-run with --yes" in output


def test_global_start_with_yes_ensures_tor_and_applies(monkeypatch, capsys):
    plan = build_global_plan(tor_uid=967)
    result = GlobalResult(True, True, "whole-host Tor mode is active", (), plan)
    calls = _fake_global_runtime(monkeypatch, plan=plan, start=result)
    ensured = []
    monkeypatch.setattr(
        cli,
        "ensure_service",
        lambda _settings: ensured.append(True) or CmdResult(True, 0, "active", ""),
    )

    assert cli.main(["global", "start", "--yes", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert ensured == [True]
    assert calls["start"]["dry_run"] is False
    assert payload["applied"] is True


def test_global_stop_reports_failure(monkeypatch, capsys):
    _fake_global_runtime(
        monkeypatch,
        stop=GlobalResult(False, False, "could not remove the global nftables tables"),
    )

    assert cli.main(["global", "stop", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)

    assert payload["ok"] is False
    assert "could not remove" in payload["detail"]


def test_global_status_uses_the_active_flag_for_the_exit_code(monkeypatch, capsys):
    _fake_global_runtime(
        monkeypatch,
        status=GlobalStatus(False, "inactive", "whole-host Tor mode is inactive"),
    )

    assert cli.main(["global", "status", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)

    assert payload["state"] == "inactive"


def test_tor_new_identity_masks_ip_addresses(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "rotate_identity",
        lambda _settings, restart=False: RotationResult(
            True,
            True,
            "203.0.113.42",
            "198.51.100.20",
            "Tor circuit rotated; the exit IP changed",
        ),
    )

    assert cli.main(["tor", "new-identity", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload["previous_ip"] == "203.0.x.x"
    assert payload["current_ip"] == "198.51.x.x"
    assert payload["changed"] is True
