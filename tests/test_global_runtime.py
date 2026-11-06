import json

import pytest

from chxchx_security.services import global_runtime
from chxchx_security.services.global_plan import (
    DROPIN_PATH,
    FILTER_TABLE,
    NAT_TABLE,
    GlobalPlanError,
)
from chxchx_security.services.global_runtime import (
    STATE_FILE,
    GlobalRuntime,
)
from chxchx_security.utils.process import CmdResult

OK = CmdResult(True, 0, "", "")


class FakeSystem:
    """Small command-level simulation of the host tools GlobalRuntime drives."""

    def __init__(self):
        self.commands = []
        self.dropin = None
        self.state = None
        self.tables = set()
        self.listening = True
        self.reloaded = False
        self.busy = set()
        self.selinux = "Disabled"
        self.semanage_list = ""
        self.semanage_local = ""
        self.ps_uid = "967\n"
        self.ps_ok = True
        self.id_ok = True
        self.tor_active = True
        self.fail_on = None

    def fail(self, *needles):
        self.fail_on = needles

    def _matches_failure(self, argv):
        return bool(self.fail_on) and all(needle in argv for needle in self.fail_on)

    def _read_file(self, path):
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def __call__(self, argv):
        argv = tuple(argv)
        self.commands.append(argv)
        if self._matches_failure(argv):
            return CmdResult(False, 1, "", "simulated failure")
        if argv[:2] == ("sudo", "-n"):
            argv = argv[2:]

        head = argv[0]
        if head == "ps":
            if not self.ps_ok:
                return CmdResult(False, 1, "", "no tor process")
            return CmdResult(True, 0, self.ps_uid, "")
        if head == "systemctl":
            if argv[1] == "is-active":
                return CmdResult(True, 0, "active" if self.tor_active else "inactive", "")
            if argv[1] == "show":
                return CmdResult(True, 0, "", "")
            if argv[1] == "reload":
                self.reloaded = True
            return OK
        if head == "id":
            if self.id_ok and argv[-1] == "toranon":
                return CmdResult(True, 0, "967\n", "")
            return CmdResult(False, 1, "", "no such user")
        if head == "cat":
            if argv[1] == DROPIN_PATH:
                return (
                    CmdResult(True, 0, self.dropin, "")
                    if self.dropin is not None
                    else CmdResult(False, 1, "", "missing")
                )
            if argv[1] == STATE_FILE:
                return (
                    CmdResult(True, 0, self.state, "")
                    if self.state is not None
                    else CmdResult(False, 1, "", "missing")
                )
            return CmdResult(False, 1, "", "missing")
        if head == "ss":
            protocol = "tcp" if argv[1] == "-Hltn" else "udp"
            port = int(argv[2].rpartition(":")[2])
            if (protocol, port) in self.busy:
                return CmdResult(True, 0, self._listener(protocol, port), "")
            if (
                self.listening
                and self.reloaded
                and (protocol, port) in {("tcp", 9040), ("udp", 5300)}
            ):
                return CmdResult(True, 0, self._listener(protocol, port), "")
            return OK
        if head == "nft":
            if argv[1] == "list":
                table = argv[-1]
                if table in self.tables:
                    return CmdResult(True, 0, f"table {table}", "")
                return CmdResult(False, 1, "", "No such file or directory")
            if argv[1] == "delete":
                self.tables.discard(argv[-1])
                return OK
            if argv[1] in {"-f", "-c"}:
                if argv[1] == "-f":
                    self.tables.update({NAT_TABLE, FILTER_TABLE})
                return OK
            return OK
        if head == "install":
            if "-d" in argv:
                return OK
            target = argv[-1]
            content = self._read_file(argv[-2])
            if target == DROPIN_PATH:
                self.dropin = content
            elif target == STATE_FILE:
                self.state = content
            return OK
        if head == "rm":
            if argv[-1] == DROPIN_PATH:
                self.dropin = None
            elif argv[-1] == STATE_FILE:
                self.state = None
            return OK
        if head == "semanage":
            if argv[2] == "-l":
                if "-C" in argv:
                    return CmdResult(True, 0, self.semanage_local, "")
                return CmdResult(True, 0, self.semanage_list, "")
            return OK
        if head == "getenforce":
            return CmdResult(True, 0, self.selinux, "")
        return OK

    @staticmethod
    def _listener(protocol, port):
        kind = "LISTEN" if protocol == "tcp" else "UNCONN"
        return f"{kind} 0 4096 127.0.0.1:{port} 0.0.0.0:*"

    def actions(self):
        return [
            command
            for command in self.commands
            if not (command[0] == "nft" and command[1] == "list")
            and command[0] != "cat"
            and command != ("systemctl", "is-active", "tor.service")
        ]


def runtime(system):
    return GlobalRuntime(
        runner=system, privileged_prefix=(), sleep=lambda _seconds: None
    )


def use_nft(monkeypatch):
    monkeypatch.setattr(global_runtime, "exists", lambda command: command == "nft")


def test_plan_detects_the_tor_runtime_user():
    system = FakeSystem()

    plan = runtime(system).plan()

    assert plan.tor_uid == 967
    assert ("ps", "-o", "uid=", "-C", "tor") in system.commands


def test_plan_refuses_multiple_tor_users():
    system = FakeSystem()
    system.ps_uid = "967\n968\n"

    with pytest.raises(GlobalPlanError):
        runtime(system).plan()


def test_plan_refuses_when_no_tor_user_can_be_found():
    system = FakeSystem()
    system.ps_ok = False
    system.id_ok = False

    with pytest.raises(GlobalPlanError):
        runtime(system).plan()


def test_dry_run_changes_nothing(monkeypatch):
    system = FakeSystem()
    use_nft(monkeypatch)

    result = runtime(system).start(dry_run=True)

    assert result.ok is True
    assert result.applied is False
    assert "dry-run" in result.detail
    assert system.tables == set()
    assert system.dropin is None
    assert any("<ruleset-file>" in command for command in result.commands)
    assert any("<dropin-file>" in command for command in result.commands)
    assert any("<state-file>" in command for command in result.commands)


def test_start_installs_the_dropin_and_fail_closed_ruleset(monkeypatch):
    system = FakeSystem()
    use_nft(monkeypatch)

    result = runtime(system).start()

    assert result.ok is True
    assert result.applied is True
    assert result.plan is not None
    assert result.plan.tor_uid == 967
    assert system.tables == {NAT_TABLE, FILTER_TABLE}
    assert system.dropin is not None
    assert "TransPort 127.0.0.1:9040" in system.dropin
    assert "DNSPort 127.0.0.1:5300" in system.dropin
    assert system.state is not None
    actions = system.actions()
    assert any(command[1:3] == ("-c", "-f") for command in actions)
    assert ("systemctl", "reload", "tor.service") in actions


def test_start_refuses_when_tor_is_not_active(monkeypatch):
    system = FakeSystem()
    system.tor_active = False
    use_nft(monkeypatch)

    result = runtime(system).start()

    assert result.ok is False
    assert "tor.service is not active" in result.detail


def test_start_refuses_when_a_global_port_is_busy(monkeypatch):
    system = FakeSystem()
    system.busy = {("tcp", 9040)}
    use_nft(monkeypatch)

    result = runtime(system).start()

    assert result.ok is False
    assert "TCP port 9040 is already in use" in result.detail


def test_start_reuses_a_matching_dropin(monkeypatch):
    system = FakeSystem()
    system.dropin = (
        "# Managed by chxsec global mode\n"
        "TransPort 127.0.0.1:9040\n"
        "DNSPort 127.0.0.1:5300\n"
    )
    use_nft(monkeypatch)

    result = runtime(system).start()

    assert result.ok is True
    installs = [
        command
        for command in system.commands
        if command[0] == "install" and command[-1] == DROPIN_PATH
    ]
    assert installs == []


def test_start_refuses_a_different_dropin(monkeypatch):
    system = FakeSystem()
    system.dropin = "TransPort 127.0.0.1:9999\n"
    use_nft(monkeypatch)

    result = runtime(system).start()

    assert result.ok is False
    assert "different global Tor drop-in" in result.detail


def test_start_rolls_back_when_nft_validation_fails(monkeypatch):
    system = FakeSystem()
    system.fail("nft", "-c", "-f")
    use_nft(monkeypatch)

    result = runtime(system).start()

    assert result.ok is False
    assert result.applied is False
    assert "rollback attempted" in result.detail
    assert system.dropin is None
    assert system.state is None
    actions = system.actions()
    assert ("nft", "delete", "table", "ip", NAT_TABLE) in actions
    assert ("nft", "delete", "table", "inet", FILTER_TABLE) in actions


def test_start_labels_selinux_ports_and_records_markers(monkeypatch):
    system = FakeSystem()
    system.selinux = "Enforcing"
    use_nft(monkeypatch)

    result = runtime(system).start()

    assert result.ok is True
    assert system.dropin is not None
    assert "# chxsec-selinux-port: tcp 9040" in system.dropin
    assert "# chxsec-selinux-port: udp 5300" in system.dropin
    assert (
        "semanage",
        "port",
        "-a",
        "-t",
        "tor_port_t",
        "-p",
        "tcp",
        "9040",
    ) in system.commands


def test_start_records_selinux_labels_in_state(monkeypatch):
    system = FakeSystem()
    system.selinux = "Enforcing"
    use_nft(monkeypatch)

    result = runtime(system).start()

    assert result.ok is True
    payload = json.loads(system.state)
    assert {"port": 9040, "proto": "tcp"} in payload["labeled"]
    assert {"port": 5300, "proto": "udp"} in payload["labeled"]


def test_stop_unlabels_ports_recorded_only_in_state():
    system = FakeSystem()
    system.dropin = (
        "# Managed by chxsec global mode\n"
        "TransPort 127.0.0.1:9040\n"
        "DNSPort 127.0.0.1:5300\n"
    )
    system.state = json.dumps(
        {
            "version": 1,
            "labeled": [
                {"port": 9040, "proto": "tcp"},
                {"port": 5300, "proto": "udp"},
            ],
        }
    )

    result = runtime(system).stop()

    assert result.ok is True
    actions = system.actions()
    assert ("semanage", "port", "-d", "-t", "tor_port_t", "-p", "tcp", "9040") in actions
    assert ("semanage", "port", "-d", "-t", "tor_port_t", "-p", "udp", "5300") in actions


def test_stop_removes_tables_dropin_labels_and_state():
    system = FakeSystem()
    system.tables = {NAT_TABLE, FILTER_TABLE}
    system.dropin = (
        "# Managed by chxsec global mode\n"
        "# chxsec-selinux-port: tcp 9040\n"
        "# chxsec-selinux-port: udp 5300\n"
        "TransPort 127.0.0.1:9040\n"
    )
    system.state = "{}"

    result = runtime(system).stop()

    assert result.ok is True
    assert system.tables == set()
    assert system.dropin is None
    assert system.state is None
    assert system.actions() == [
        ("nft", "delete", "table", "ip", NAT_TABLE),
        ("nft", "delete", "table", "inet", FILTER_TABLE),
        ("rm", "-f", DROPIN_PATH),
        ("semanage", "port", "-d", "-t", "tor_port_t", "-p", "tcp", "9040"),
        ("semanage", "port", "-d", "-t", "tor_port_t", "-p", "udp", "5300"),
        ("systemctl", "reload", "tor.service"),
        ("rm", "-f", STATE_FILE),
    ]


def test_stop_keeps_the_dropin_when_tables_cannot_be_removed():
    system = FakeSystem()
    system.tables = {NAT_TABLE, FILTER_TABLE}
    system.dropin = "# Managed by chxsec global mode\n"
    system.fail("nft", "delete", "table", "ip", NAT_TABLE)

    result = runtime(system).stop()

    assert result.ok is False
    assert system.dropin is not None
    assert "traffic stays protected" in result.detail


def test_status_reports_active(monkeypatch):
    system = FakeSystem()
    system.tables = {NAT_TABLE, FILTER_TABLE}
    system.reloaded = True
    system.state = json.dumps(
        {"trans_port": 9040, "dns_port": 5300, "tor_uid": 967, "allow_lan": False}
    )
    monkeypatch.setattr(global_runtime.os.path, "lexists", lambda _path: True)

    status = runtime(system).status()

    assert status.active is True
    assert status.state == "active"
    assert status.trans_port == 9040
    assert status.dns_port == 5300


def test_status_reports_inactive(monkeypatch):
    system = FakeSystem()
    monkeypatch.setattr(global_runtime.os.path, "lexists", lambda _path: False)

    status = runtime(system).status()

    assert status.active is False
    assert status.state == "inactive"


def test_status_reports_partial_when_state_exists_without_dropin(monkeypatch):
    system = FakeSystem()
    system.state = json.dumps({"trans_port": 9040, "dns_port": 5300})
    monkeypatch.setattr(global_runtime.os.path, "lexists", lambda _path: False)

    status = runtime(system).status()

    assert status.active is False
    assert status.state == "partial"


def test_status_reports_partial_state(monkeypatch):
    system = FakeSystem()
    system.tables = {NAT_TABLE}
    system.state = json.dumps({"trans_port": 9040, "dns_port": 5300})
    monkeypatch.setattr(global_runtime.os.path, "lexists", lambda _path: True)

    status = runtime(system).status()

    assert status.active is False
    assert status.state == "partial"
    assert "partially applied" in status.detail
