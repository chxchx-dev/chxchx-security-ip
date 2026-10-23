import os

import pytest

from chxchx_security.services import tor_runtime
from chxchx_security.services.network_plan import NetworkPlanError
from chxchx_security.services.tor_runtime import TorPortRuntime, dropin_path
from chxchx_security.utils.process import CmdResult

SUBNET = "10.203.0.0/30"
TCP_OK = "LISTEN 0 4096 10.203.0.1:9040 0.0.0.0:*"
UDP_OK = "UNCONN 0 0 10.203.0.1:5300 0.0.0.0:*"


class Fake:
    def __init__(self, **overrides):
        self.calls = []
        self.files = []
        self.overrides = overrides
        self.listening = False

    def __call__(self, command):
        command = tuple(command)
        self.calls.append(command)
        rest = command[1:] if command[0] == "sudo" else command
        if rest[0] == "install":
            with open(rest[7], encoding="utf-8") as handle:
                self.files.append((handle.read(), oct(os.stat(rest[7]).st_mode & 0o777)))
        if rest[:2] == ("systemctl", "reload"):
            self.listening = self.overrides.get("listens", True)
        if rest[0] in self.overrides:
            return self.overrides[rest[0]]
        if rest[:2] == ("systemctl", "is-active"):
            return CmdResult(True, 0, "active", "")
        if rest[0] == "ip":
            return CmdResult(True, 0, "2: chxh-2a97516c    inet 10.203.0.1/30", "")
        if rest[0] == "test":
            return CmdResult(False, 1, "", "")
        if rest[0] == "cat":
            return CmdResult(False, 1, "", "No such file or directory")
        if rest[0] == "getenforce":
            return CmdResult(True, 0, "Disabled", "")
        if rest[0] == "semanage":
            return CmdResult(True, 0, "", "")
        if rest[0] == "ss":
            if not self.listening:
                return CmdResult(True, 0, "", "")
            return CmdResult(True, 0, TCP_OK if rest[1] == "-Hltn" else UDP_OK, "")
        return CmdResult(True, 0, "", "")


def _runtime(fake):
    return TorPortRuntime(runner=fake, privileged_prefix=("sudo",), sleep=lambda _s: None)


@pytest.fixture(autouse=True)
def no_real_files(monkeypatch):
    monkeypatch.setattr(tor_runtime.os.path, "lexists", lambda _p: False)


def test_dry_run_never_calls_runner():
    fake = Fake()
    result = _runtime(fake).apply("demo", subnet=SUBNET, dry_run=True)

    assert result.ok is True and result.applied is False
    assert fake.calls == []
    assert "TransPort 10.203.0.1:9040" in result.config
    assert "DNSPort 10.203.0.1:5300" in result.config


def test_apply_installs_verifies_reloads_and_confirms_listeners():
    fake = Fake()
    result = _runtime(fake).apply("demo", subnet=SUBNET)

    assert result.ok is True and result.applied is True
    content, mode = fake.files[0]
    assert mode == "0o600"
    assert "TransPort 10.203.0.1:9040" in content
    steps = [
        "reload" if "reload" in c else (c[1] if c[0] == "sudo" else c[0])
        for c in fake.calls
    ]
    assert steps.index("install") < steps.index("tor") < steps.index("reload")
    assert result.commands[0][-1] == dropin_path("demo")
    assert not any(c[:2] == ("sudo", "systemctl") and "restart" in c for c in fake.calls)
    assert not any("semanage" in c for c in fake.calls)


def test_apply_requires_active_tor_and_wired_interface():
    inactive = Fake(systemctl=CmdResult(True, 0, "inactive", ""))
    assert "not active" in _runtime(inactive).apply("demo", subnet=SUBNET).detail

    unwired = Fake(ip=CmdResult(False, 1, "", "Device does not exist"))
    result = _runtime(unwired).apply("demo", subnet=SUBNET)
    assert "network-apply" in result.detail
    assert not any("install" in c for c in unwired.calls)


def test_apply_refuses_when_ports_are_taken_by_other_processes():
    taken = Fake(ss=CmdResult(True, 0, "UNCONN 0 0 0.0.0.0:5300 0.0.0.0:*", ""))
    result = _runtime(taken).apply("demo", subnet=SUBNET)

    assert result.ok is False
    assert "already in use" in result.detail
    assert not any("install" in c for c in taken.calls)


def test_multicast_listener_on_same_port_is_not_a_conflict():
    fake = Fake(ss=CmdResult(True, 0, "UNCONN 0 0 224.0.0.251:5300 0.0.0.0:*", ""))
    fake.listening = False
    assert tor_runtime._conflicting("UNCONN 0 0 224.0.0.251:5300 0.0.0.0:*", "10.203.0.1", 5300) is False
    assert tor_runtime._conflicting("UNCONN 0 0 [::]:5300 [::]:*", "10.203.0.1", 5300) is True


def test_config_rejected_by_tor_rolls_back_without_reload():
    fake = Fake(tor=CmdResult(False, 1, "", "bad config"))
    result = _runtime(fake).apply("demo", subnet=SUBNET)

    assert result.ok is False
    assert "rejected" in result.detail and "rollback completed" in result.detail
    assert any(c[-2:] == ("-f", dropin_path("demo")) for c in fake.calls)
    reloads = [c for c in fake.calls if "reload" in c]
    assert len(reloads) == 1


def test_not_listening_after_reload_rolls_back():
    fake = Fake(listens=False)
    result = _runtime(fake).apply("demo", subnet=SUBNET)

    assert result.ok is False
    assert "not listening" in result.detail
    assert "rollback completed" in result.detail


def test_remove_without_dropin_is_noop():
    fake = Fake()
    result = _runtime(fake).remove("demo")

    assert result.ok is True
    assert not any("rm" in c for c in fake.calls)


def test_remove_deletes_dropin_and_reloads_only_if_tor_active(monkeypatch):
    monkeypatch.setattr(tor_runtime.os.path, "lexists", lambda _p: True)
    fake = Fake()
    result = _runtime(fake).remove("demo")

    assert result.ok is True
    assert ("sudo", "rm", "-f", dropin_path("demo")) in fake.calls
    assert any("reload" in c for c in fake.calls)


def test_remove_unlabels_the_ports_found_in_the_existing_dropin(monkeypatch):
    monkeypatch.setattr(tor_runtime.os.path, "lexists", lambda _p: True)
    dropin = "# Managed by chxsec\nTransPort 10.203.0.1:19040\nDNSPort 10.203.0.1:15300\n"
    fake = Fake(cat=CmdResult(True, 0, dropin, ""))
    result = _runtime(fake).remove("demo")

    assert result.ok is True
    assert ("sudo", "semanage", "port", "-d", "-t", "tor_port_t", "-p", "tcp", "19040") in fake.calls
    assert ("sudo", "semanage", "port", "-d", "-t", "tor_port_t", "-p", "udp", "15300") in fake.calls


def test_apply_labels_both_ports_for_selinux_before_installing_the_dropin():
    fake = Fake(getenforce=CmdResult(True, 0, "Enforcing", ""))
    result = _runtime(fake).apply("demo", subnet=SUBNET)

    assert result.ok is True
    label_tcp = ("sudo", "semanage", "port", "-a", "-t", "tor_port_t", "-p", "tcp", "9040")
    label_udp = ("sudo", "semanage", "port", "-a", "-t", "tor_port_t", "-p", "udp", "5300")
    assert fake.calls.index(label_tcp) < fake.calls.index(label_udp)
    install_index = next(i for i, c in enumerate(fake.calls) if "install" in c)
    assert fake.calls.index(label_udp) < install_index


def test_apply_skips_labeling_a_port_already_registered_as_tor_port_t():
    fake = Fake(
        getenforce=CmdResult(True, 0, "Enforcing", ""),
        semanage=CmdResult(True, 0, "tor_port_t  tcp  9040\ntor_port_t  udp  5300", ""),
    )
    result = _runtime(fake).apply("demo", subnet=SUBNET)

    assert result.ok is True
    assert not any(c[1:5] == ("semanage", "port", "-a", "-t") for c in fake.calls)


def test_apply_refuses_when_port_is_labeled_for_a_different_selinux_type():
    fake = Fake(
        getenforce=CmdResult(True, 0, "Enforcing", ""),
        semanage=CmdResult(True, 0, "http_port_t  tcp  9040", ""),
    )
    result = _runtime(fake).apply("demo", subnet=SUBNET)

    assert result.ok is False
    assert "http_port_t" in result.detail
    assert not any("install" in c for c in fake.calls)


def test_apply_unlabels_the_first_port_if_labeling_the_second_fails():
    calls_seen = []

    def runner(command):
        command = tuple(command)
        calls_seen.append(command)
        rest = command[1:] if command[0] == "sudo" else command
        if rest[:2] == ("systemctl", "is-active"):
            return CmdResult(True, 0, "active", "")
        if rest[0] == "ip":
            return CmdResult(True, 0, "2: chxh-2a97516c    inet 10.203.0.1/30", "")
        if rest[0] == "test":
            return CmdResult(False, 1, "", "")
        if rest[0] == "cat":
            return CmdResult(False, 1, "", "")
        if rest[0] == "getenforce":
            return CmdResult(True, 0, "Enforcing", "")
        if rest[0] == "ss":
            return CmdResult(True, 0, "", "")
        if rest[:3] == ("semanage", "port", "-l"):
            return CmdResult(True, 0, "", "")
        if rest[:4] == ("semanage", "port", "-a", "-t") and rest[-2:] == ("udp", "5300"):
            return CmdResult(False, 1, "", "semanage: boom")
        return CmdResult(True, 0, "", "")

    result = TorPortRuntime(runner=runner, privileged_prefix=("sudo",)).apply("demo", subnet=SUBNET)

    assert result.ok is False
    assert "udp port 5300" in result.detail
    assert ("sudo", "semanage", "port", "-d", "-t", "tor_port_t", "-p", "tcp", "9040") in calls_seen
    assert not any("install" in c for c in calls_seen)


def test_dropin_path_rejects_traversal():
    with pytest.raises(ValueError):
        dropin_path("../../etc/passwd")


def test_invalid_subnet_runs_nothing():
    fake = Fake()
    with pytest.raises(NetworkPlanError):
        _runtime(fake).apply("demo", subnet="192.168.1.0/24")
    assert fake.calls == []
