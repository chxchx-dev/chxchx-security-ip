import os

import pytest

import chxchx_security.services.namespace_runtime as namespace_runtime
from chxchx_security.services.namespace_runtime import NamespaceRuntime
from chxchx_security.services.session import SessionState
from chxchx_security.utils.process import CmdResult


def test_runtime_dry_run_never_calls_runner():
    calls = []
    runtime = NamespaceRuntime(
        runner=lambda command: calls.append(command) or CmdResult(True, 0, "", "")
    )

    result = runtime.create("demo", dry_run=True)

    assert result.ok is True
    assert result.network_ready is False
    assert result.state is SessionState.STARTING
    assert calls == []

def test_runtime_preserves_explicit_empty_privileged_prefix():
    runtime = NamespaceRuntime(runner=lambda command: CmdResult(True, 0, "", ""), privileged_prefix=())

    result = runtime.create("demo", dry_run=True)

    assert result.commands[0] == ("ip", "netns", "add", "chxsec-demo")


def test_runtime_creates_namespace_and_loopback():
    calls = []

    def runner(command):
        calls.append(tuple(command))
        return CmdResult(True, 0, "", "")

    runtime = NamespaceRuntime(runner=runner, privileged_prefix=("sudo",))
    result = runtime.create("demo")

    assert result.ok is True
    assert result.state is SessionState.ACTIVE
    assert result.network_ready is False
    assert calls == [
        ("sudo", "ip", "netns", "add", "chxsec-demo"),
        ("sudo", "ip", "netns", "exec", "chxsec-demo", "ip", "link", "set", "lo", "up"),
    ]


def test_runtime_rolls_back_when_loopback_setup_fails():
    calls = []

    def runner(command):
        calls.append(tuple(command))
        if len(calls) == 2:
            return CmdResult(False, 1, "", "loopback failed")
        return CmdResult(True, 0, "", "")

    runtime = NamespaceRuntime(runner=runner)
    result = runtime.create("demo")

    assert result.ok is False
    assert "rollback completed" in result.detail
    assert calls[-1] == ("sudo", "ip", "netns", "delete", "chxsec-demo")


def test_runtime_destroy_is_deterministic(tmp_path, monkeypatch):
    monkeypatch.setattr(namespace_runtime, "NETNS_CONFIG_ROOT", str(tmp_path / "netns"))
    calls = []
    runtime = NamespaceRuntime(
        runner=lambda command: calls.append(tuple(command))
        or CmdResult(True, 0, "", "")
    )

    result = runtime.destroy("demo")

    assert result.ok is True
    assert result.state is SessionState.DESTROYED
    assert calls == [("sudo", "ip", "netns", "delete", "chxsec-demo")]

def test_runtime_destroy_removes_only_managed_resolver_config(tmp_path, monkeypatch):
    config_root = tmp_path / "netns"
    config_directory = config_root / "chxsec-demo"
    config_directory.mkdir(parents=True)
    resolver = config_directory / "resolv.conf"
    resolver.write_text(
        "# Managed by chxsec for chxsec-demo\nnameserver 10.203.0.1\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(namespace_runtime, "NETNS_CONFIG_ROOT", str(config_root))
    calls = []

    def runner(command):
        command = tuple(command)
        calls.append(command)
        if command[0] == "rm":
            os.remove(command[-1])
        elif command[0] == "rmdir":
            os.rmdir(command[-1])
        return CmdResult(True, 0, "", "")

    result = NamespaceRuntime(runner=runner, privileged_prefix=()).destroy("demo")

    assert result.ok is True
    assert not config_directory.exists()
    assert calls == [
        ("ip", "netns", "delete", "chxsec-demo"),
        ("rm", "-f", "--", str(resolver)),
        ("rmdir", "--", str(config_directory)),
    ]


def test_runtime_destroy_preserves_unmanaged_resolver_config(tmp_path, monkeypatch):
    config_root = tmp_path / "netns"
    config_directory = config_root / "chxsec-demo"
    config_directory.mkdir(parents=True)
    resolver = config_directory / "resolv.conf"
    resolver.write_text("nameserver 192.0.2.53\n", encoding="utf-8")
    monkeypatch.setattr(namespace_runtime, "NETNS_CONFIG_ROOT", str(config_root))
    calls = []

    def runner(command):
        calls.append(tuple(command))
        return CmdResult(True, 0, "", "")

    result = NamespaceRuntime(runner=runner, privileged_prefix=()).destroy("demo")

    assert result.ok is False
    assert "unmanaged resolver config was left in place" in result.detail
    assert resolver.read_text(encoding="utf-8") == "nameserver 192.0.2.53\n"
    assert calls == [("ip", "netns", "delete", "chxsec-demo")]
