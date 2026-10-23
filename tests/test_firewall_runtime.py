import os

import pytest

from chxchx_security.services.firewall_plan import build_firewall_plan
from chxchx_security.services.firewall_runtime import FirewallRuntime
from chxchx_security.services.network_plan import NetworkPlanError
from chxchx_security.utils.process import CmdResult

SUBNET = "10.203.0.0/30"


@pytest.fixture(autouse=True)
def nft_present(monkeypatch):
    monkeypatch.setattr("chxchx_security.services.firewall_runtime.exists", lambda _: True)


def _runtime(calls, results=None, seen_files=None):
    results = results or {}

    def runner(command):
        calls.append(tuple(command))
        if seen_files is not None and "-f" in command:
            path = command[command.index("-f") + 1]
            with open(path, encoding="utf-8") as handle:
                seen_files.append((path, handle.read(), oct(os.stat(path).st_mode & 0o777)))
        return results.get(len(calls), CmdResult(True, 0, "", ""))

    return FirewallRuntime(runner=runner, privileged_prefix=("sudo",))


def _absent_first():
    return {1: CmdResult(False, 1, "", "Error: No such file or directory")}


def test_dry_run_never_calls_runner_and_returns_ruleset():
    calls = []
    result = _runtime(calls).apply("demo", subnet=SUBNET, dry_run=True)

    assert result.ok is True and result.applied is False
    assert calls == []
    assert result.ruleset == build_firewall_plan("demo", subnet=SUBNET).ruleset


def test_apply_checks_then_applies_private_ruleset_file():
    calls, files = [], []
    result = _runtime(calls, _absent_first(), files).apply("demo", subnet=SUBNET)

    assert result.ok is True and result.applied is True
    assert [c[1:3] for c in calls] == [("nft", "list"), ("nft", "-c"), ("nft", "-f")]
    assert all(content == result.ruleset for _, content, _ in files)
    assert all(mode == "0o600" for _, _, mode in files)
    assert not os.path.exists(files[0][0])


def test_apply_refuses_when_tables_already_exist():
    calls = []
    result = _runtime(calls).apply("demo", subnet=SUBNET)

    assert result.ok is False
    assert "already exist" in result.detail
    assert len(calls) == 1


def test_validation_failure_applies_nothing():
    calls = []
    results = {**_absent_first(), 2: CmdResult(False, 1, "", "syntax error")}
    result = _runtime(calls, results).apply("demo", subnet=SUBNET)

    assert result.ok is False
    assert "nothing was applied" in result.detail
    assert not any(c[1:3] == ("nft", "-f") for c in calls)


def test_apply_failure_removes_both_tables():
    calls = []
    results = {**_absent_first(), 3: CmdResult(False, 1, "", "boom")}
    result = _runtime(calls, results).apply("demo", subnet=SUBNET)

    assert result.ok is False
    assert "cleanup completed" in result.detail
    assert calls[-2][1:5] == ("nft", "delete", "table", "inet")
    assert calls[-1][1:5] == ("nft", "delete", "table", "ip")


def test_remove_tolerates_missing_tables():
    calls = []
    missing = CmdResult(False, 1, "", "Error: No such file or directory")
    result = _runtime(calls, {1: missing, 2: missing}).remove("demo")

    assert result.ok is True
    assert len(calls) == 2


def test_remove_reports_real_failures():
    calls = []
    result = _runtime(calls, {1: CmdResult(False, 1, "", "permission denied")}).remove("demo")

    assert result.ok is False


def test_invalid_subnet_runs_nothing():
    calls = []
    with pytest.raises(NetworkPlanError):
        _runtime(calls).apply("demo", subnet="192.168.1.0/24")
    assert calls == []
