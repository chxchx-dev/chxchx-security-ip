import pytest

from chxchx_security.services.network_plan import NetworkPlanError
from chxchx_security.services.network_runtime import NetworkRuntime
from chxchx_security.utils.process import CmdResult


def _runtime(calls, fail_at=None):
    def runner(command):
        calls.append(tuple(command))
        if fail_at is not None and len(calls) == fail_at:
            stderr = "File exists" if fail_at == 3 else "boom"
            return CmdResult(False, 1, "", stderr)
        return CmdResult(True, 0, "", "")

    return NetworkRuntime(runner=runner, privileged_prefix=("sudo",))


def test_dry_run_never_calls_runner_and_lists_all_commands():
    calls = []
    result = _runtime(calls).apply("demo", subnet="10.203.0.0/30", dry_run=True)

    assert result.ok is True
    assert result.applied is False
    assert calls == []
    assert result.commands[0] == ("sudo", "ip", "netns", "add", "chxsec-demo")
    assert any("veth" in command for command in result.commands)


def test_apply_wires_veth_and_installs_no_route():
    calls = []
    result = _runtime(calls).apply("demo", subnet="10.203.0.0/30")

    assert result.ok is True
    assert result.applied is True
    assert all(command[0] == "sudo" for command in calls)
    assert not any("route" in command for command in calls)
    assert calls[-1][-1] == "up"


@pytest.mark.parametrize("fail_at", [3, 5, 8])
def test_failure_rolls_back_only_resources_created_by_this_attempt(fail_at):
    calls = []
    result = _runtime(calls, fail_at=fail_at).apply("demo", subnet="10.203.0.0/30")

    assert result.ok is False
    assert result.applied is False
    assert "rollback completed" in result.detail
    if fail_at == 3:
        assert not any(command[:4] == ("sudo", "ip", "link", "delete") for command in calls)
        assert calls[-1] == ("sudo", "ip", "netns", "delete", "chxsec-demo")
    else:
        assert calls[-2][:4] == ("sudo", "ip", "link", "delete")
        assert calls[-1] == ("sudo", "ip", "netns", "delete", "chxsec-demo")


def test_namespace_creation_failure_skips_wiring():
    calls = []
    result = _runtime(calls, fail_at=1).apply("demo", subnet="10.203.0.0/30")

    assert result.ok is False
    assert len(calls) == 1


def test_invalid_subnet_runs_nothing():
    calls = []
    with pytest.raises(NetworkPlanError):
        _runtime(calls).apply("demo", subnet="192.168.1.0/24")
    assert calls == []
