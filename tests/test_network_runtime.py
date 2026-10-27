import pytest

import chxchx_security.services.namespace_runtime as namespace_runtime
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
    assert any(
        command[-1] == "/etc/netns/chxsec-demo/resolv.conf"
        for command in result.commands
    )


def test_apply_wires_veth_and_installs_no_route(tmp_path, monkeypatch):
    config_root = tmp_path / "netns"
    monkeypatch.setattr(namespace_runtime, "NETNS_CONFIG_ROOT", str(config_root))
    calls = []
    result = _runtime(calls).apply("demo", subnet="10.203.0.0/30")

    assert result.ok is True
    assert result.applied is True
    assert all(command[0] == "sudo" for command in calls)
    assert not any("route" in command for command in calls)
    assert calls[-1][1] == "install"
    assert calls[-1][-1] == str(config_root / "chxsec-demo" / "resolv.conf")
    assert "namespace DNS points to the Tor gateway" in result.detail


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

def test_apply_installs_namespace_resolver_pointing_to_tor_gateway(tmp_path, monkeypatch):
    config_root = tmp_path / "netns"
    monkeypatch.setattr(namespace_runtime, "NETNS_CONFIG_ROOT", str(config_root))
    calls = []
    resolver_configs = []

    def runner(command):
        command = tuple(command)
        calls.append(command)
        if len(command) >= 2 and command[1] == "install" and command[-1].endswith("/resolv.conf"):
            with open(command[-2], encoding="utf-8") as handle:
                resolver_configs.append(handle.read())
        return CmdResult(True, 0, "", "")

    result = NetworkRuntime(
        runner=runner, privileged_prefix=("sudo",)
    ).apply("demo", subnet="10.203.0.0/30")

    assert result.ok is True
    assert len(resolver_configs) == 1
    assert resolver_configs[0].splitlines() == [
        "# Managed by chxsec for chxsec-demo",
        "nameserver 10.203.0.1",
        "options timeout:2 attempts:2",
    ]
    assert calls[-1][-1] == str(config_root / "chxsec-demo" / "resolv.conf")

def test_apply_refuses_to_overwrite_existing_namespace_resolver(tmp_path, monkeypatch):
    config_root = tmp_path / "netns"
    config_directory = config_root / "chxsec-demo"
    config_directory.mkdir(parents=True)
    resolver = config_directory / "resolv.conf"
    resolver.write_text("nameserver 192.0.2.53\n", encoding="utf-8")
    monkeypatch.setattr(namespace_runtime, "NETNS_CONFIG_ROOT", str(config_root))
    calls = []

    result = _runtime(calls).apply("demo", subnet="10.203.0.0/30")

    assert result.ok is False
    assert "refusing to overwrite it" in result.detail
    assert resolver.read_text(encoding="utf-8") == "nameserver 192.0.2.53\n"
    assert not any(
        command[1] == "install" and command[-1] == str(resolver)
        for command in calls
    )
