import pytest

from chxchx_security.services import session_runtime as module
from chxchx_security.services.session_runtime import SessionRuntime
from chxchx_security.utils.process import CmdResult

SUBNET = "10.203.0.0/30"


def _ok(*_a, **_k):
    return CmdResult(True, 0, "", "")


class FakeApplyRemove:
    """Stand-in for NetworkRuntime/FirewallRuntime/TorPortRuntime/NamespaceRuntime."""

    def __init__(self, name, log, fail_on_apply=False):
        self.name = name
        self.log = log
        self.fail_on_apply = fail_on_apply

    def apply(self, session_id, **kwargs):
        self.log.append(("apply", self.name))
        ok = not self.fail_on_apply
        return _Result(ok, f"{self.name} apply", ((f"{self.name}-cmd",),))

    def remove(self, session_id):
        self.log.append(("remove", self.name))
        return _Result(True, f"{self.name} removed")

    destroy = remove


class _Result:
    def __init__(self, ok, detail, commands=()):
        self.ok = ok
        self.detail = detail
        self.commands = commands


@pytest.fixture
def wiring(monkeypatch):
    log = []

    def make(name, fail=False):
        return FakeApplyRemove(name, log, fail_on_apply=fail)

    return log, make


def _patch_stages(monkeypatch, make, *, fail_network=False, fail_firewall=False, fail_tor=False):
    monkeypatch.setattr(module, "NetworkRuntime", lambda **_k: make("network", fail_network))
    monkeypatch.setattr(module, "FirewallRuntime", lambda **_k: make("firewall", fail_firewall))
    monkeypatch.setattr(module, "TorPortRuntime", lambda **_k: make("tor", fail_tor))
    monkeypatch.setattr(module, "NamespaceRuntime", lambda **_k: make("namespace"))


def test_dry_run_never_touches_the_system_and_lists_every_stage():
    runtime = SessionRuntime(runner=lambda c: pytest.fail("runner should not be called"))

    result = runtime.start("demo", ["curl", "https://example.com"], subnet=SUBNET, dry_run=True)

    assert result.ok is True
    assert any("netns" in c and "add" in c for c in result.commands)
    assert any("veth" in c for c in result.commands)
    assert any("setpriv" in c for c in result.commands)
    assert any("route" in c and "default" in c for c in result.commands)
    assert any("disable_ipv6" in " ".join(c) for c in result.commands)


def test_happy_path_applies_in_order_execs_and_always_cleans_up(monkeypatch, wiring):
    log, make = wiring
    _patch_stages(monkeypatch, make)
    calls = []
    runtime = SessionRuntime(
        runner=_ok, executor=lambda argv: calls.append(tuple(argv)) or 0
    )

    result = runtime.start("demo", ["true"], subnet=SUBNET, dry_run=False)

    assert result.ok is True and result.exit_code == 0
    assert [name for action, name in log if action == "apply"] == ["network", "firewall", "tor"]
    assert [name for action, name in log if action == "remove"] == ["tor", "firewall", "namespace"]
    assert len(calls) == 1 and "setpriv" in calls[0]


def test_network_failure_stops_immediately_without_a_second_rollback(monkeypatch, wiring):
    # NetworkRuntime.apply() already rolls itself back on failure; session_runtime
    # must not call cleanup again, or it would report a spurious "destroy failed"
    # for a namespace that no longer exists.
    log, make = wiring
    _patch_stages(monkeypatch, make, fail_network=True)
    executed = []
    runtime = SessionRuntime(runner=_ok, executor=lambda argv: executed.append(argv) or 0)

    result = runtime.start("demo", ["true"], subnet=SUBNET, dry_run=False)

    assert result.ok is False
    assert executed == []
    assert log == [("apply", "network")]


@pytest.mark.parametrize("stage", ["firewall", "tor"])
def test_later_stage_failure_stops_early_and_rolls_back_whatever_ran(monkeypatch, wiring, stage):
    log, make = wiring
    _patch_stages(monkeypatch, make, **{f"fail_{stage}": True})
    executed = []
    runtime = SessionRuntime(runner=_ok, executor=lambda argv: executed.append(argv) or 0)

    result = runtime.start("demo", ["true"], subnet=SUBNET, dry_run=False)

    assert result.ok is False
    assert executed == []
    applied = [name for action, name in log if action == "apply"]
    assert stage in applied
    assert applied[-1] == stage
    expected_cleanup = ["namespace"] if stage == "firewall" else ["firewall", "namespace"]
    assert [name for action, name in log if action == "remove"] == expected_cleanup


def test_ipv6_disable_failure_rolls_back_before_route_or_exec(monkeypatch, wiring):
    log, make = wiring
    _patch_stages(monkeypatch, make)
    executed = []

    def runner(argv):
        if "sysctl" in argv:
            return CmdResult(False, 1, "", "boom")
        return CmdResult(True, 0, "", "")

    runtime = SessionRuntime(runner=runner, executor=lambda argv: executed.append(argv) or 0)
    result = runtime.start("demo", ["true"], subnet=SUBNET, dry_run=False)

    assert result.ok is False
    assert "IPv6" in result.detail
    assert executed == []
    assert [name for action, name in log if action == "remove"] == ["tor", "firewall", "namespace"]


def test_route_failure_rolls_back_without_exec(monkeypatch, wiring):
    log, make = wiring
    _patch_stages(monkeypatch, make)
    executed = []

    def runner(argv):
        if "route" in argv:
            return CmdResult(False, 1, "", "boom")
        return CmdResult(True, 0, "", "")

    runtime = SessionRuntime(runner=runner, executor=lambda argv: executed.append(argv) or 0)
    result = runtime.start("demo", ["true"], subnet=SUBNET, dry_run=False)

    assert result.ok is False
    assert "route" in result.detail
    assert executed == []


def test_cleanup_runs_even_when_the_command_raises(monkeypatch, wiring):
    log, make = wiring
    _patch_stages(monkeypatch, make)

    def boom(_argv):
        raise KeyboardInterrupt

    runtime = SessionRuntime(runner=_ok, executor=boom)

    with pytest.raises(KeyboardInterrupt):
        runtime.start("demo", ["true"], subnet=SUBNET, dry_run=False)

    assert [name for action, name in log if action == "remove"] == ["tor", "firewall", "namespace"]


def test_non_root_execution_drops_privileges_with_setpriv(monkeypatch, wiring):
    log, make = wiring
    _patch_stages(monkeypatch, make)
    calls = []
    runtime = SessionRuntime(
        runner=_ok,
        privileged_prefix=("sudo",),
        executor=lambda argv: calls.append(tuple(argv)) or 0,
    )
    monkeypatch.setattr(module.os, "getuid", lambda: 1000)
    monkeypatch.setattr(module.os, "getgid", lambda: 1000)

    runtime.start("demo", ["id"], subnet=SUBNET)

    assert calls[0][:2] == ("sudo", "ip")
    assert "setpriv" in calls[0]
    assert "--reuid" in calls[0] and "1000" in calls[0]


def test_empty_command_is_rejected_before_touching_anything(monkeypatch, wiring):
    log, make = wiring
    _patch_stages(monkeypatch, make)
    runtime = SessionRuntime(runner=lambda c: pytest.fail("must not run"))

    with pytest.raises(ValueError):
        runtime.start("demo", [], subnet=SUBNET, dry_run=True)

    assert log == []
