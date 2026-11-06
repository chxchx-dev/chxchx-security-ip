from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass
from typing import Callable, Sequence

from chxchx_security.services.global_plan import (
    DROPIN_PATH,
    FILTER_TABLE,
    NAT_TABLE,
    GlobalPlan,
    GlobalPlanError,
    build_global_plan,
)
from chxchx_security.services.tor_selinux import (
    ensure_ports,
    managed_ports,
    unlabel_ports,
    with_managed_ports,
)
from chxchx_security.utils.process import CmdResult, exists, run

CommandRunner = Callable[[Sequence[str]], CmdResult]

TORRC = "/etc/tor/torrc"
DEFAULTS_TORRC = "/usr/share/tor/defaults-torrc"
STATE_DIR = "/run/chxsec"
STATE_FILE = "/run/chxsec/global.json"
TOR_USERS = ("toranon", "debian-tor", "tor", "_tor")
_PLACEHOLDER = "<ruleset-file>"
_DROPIN_PLACEHOLDER = "<dropin-file>"
_STATE_PLACEHOLDER = "<state-file>"


@dataclass(frozen=True)
class GlobalResult:
    ok: bool
    applied: bool
    detail: str
    commands: tuple[tuple[str, ...], ...] = ()
    plan: GlobalPlan | None = None

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "ok": self.ok,
            "applied": self.applied,
            "detail": self.detail,
            "commands": [list(command) for command in self.commands],
        }
        if self.plan is not None:
            payload["plan"] = self.plan.as_dict()
        return payload


@dataclass(frozen=True)
class GlobalStatus:
    active: bool
    state: str
    detail: str
    dropin: bool = False
    nat_table: bool | None = None
    filter_table: bool | None = None
    trans_port: int | None = None
    dns_port: int | None = None
    tor_uid: int | None = None
    allow_lan: bool | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "active": self.active,
            "state": self.state,
            "detail": self.detail,
            "dropin": self.dropin,
            "nat_table": self.nat_table,
            "filter_table": self.filter_table,
            "trans_port": self.trans_port,
            "dns_port": self.dns_port,
            "tor_uid": self.tor_uid,
            "allow_lan": self.allow_lan,
        }


def _local(row: str) -> tuple[str, int] | None:
    columns = row.split()
    if len(columns) < 4:
        return None
    host, _, port = columns[3].rpartition(":")
    return (host, int(port)) if port.isdigit() else None


def _listening(output: str, address: str, port: int) -> bool:
    return any(_local(row) == (address, port) for row in output.splitlines())


class GlobalRuntime:
    """Wires the whole host through Tor with a fail-closed nftables kill switch."""

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        privileged_prefix: tuple[str, ...] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._runner = runner or (lambda argv: run(argv, timeout=30))
        if privileged_prefix is None:
            privileged_prefix = () if os.geteuid() == 0 else ("sudo",)
        self._prefix = privileged_prefix
        self._sleep = sleep

    # ---- discovery -----------------------------------------------------
    def _detect_uid(self) -> int:
        processes = self._runner(("ps", "-o", "uid=", "-C", "tor"))
        if processes.ok:
            uids = sorted(
                {int(value) for value in processes.stdout.split() if value.isdigit()}
            )
            if len(uids) == 1:
                return uids[0]
            if len(uids) > 1:
                raise GlobalPlanError(
                    "multiple Tor processes use different users; refusing to guess"
                )

        service = self._runner(("systemctl", "show", "-p", "User", "--value", "tor.service"))
        candidates = []
        if service.ok and service.stdout.strip():
            candidates.append(service.stdout.strip())
        candidates.extend(TOR_USERS)
        for candidate in candidates:
            if not candidate or candidate == "root":
                continue
            result = self._runner(("id", "-u", candidate))
            if result.ok and result.stdout.strip().isdigit():
                return int(result.stdout.strip())
        raise GlobalPlanError(
            "could not determine Tor's runtime user; refusing to guess because "
            "redirecting Tor into itself would create a loop"
        )

    def _read(self, path: str) -> str | None:
        result = self._runner(("cat", path))
        return result.stdout if result.ok else None

    def _table_present(self, family: str, table: str, *, readonly: bool = False) -> bool | None:
        if readonly:
            if os.geteuid() == 0:
                command: tuple[str, ...] = ("nft", "list", "table", family, table)
            else:
                command = ("sudo", "-n", "nft", "list", "table", family, table)
        else:
            command = (*self._prefix, "nft", "list", "table", family, table)
        result = self._runner(command)
        if result.ok:
            return True
        if "No such file or directory" in result.stderr:
            return False
        return None

    def _port_in_use(self, protocol: str, port: int) -> bool:
        flag = "-Hltn" if protocol == "tcp" else "-Hlun"
        return bool(self._runner(("ss", flag, f"sport = :{port}")).stdout.strip())

    def _wait_listening(self, trans_port: int, dns_port: int) -> bool:
        for _ in range(20):
            tcp = self._runner(("ss", "-Hltn", f"sport = :{trans_port}"))
            udp = self._runner(("ss", "-Hlun", f"sport = :{dns_port}"))
            if _listening(tcp.stdout, "127.0.0.1", trans_port) and _listening(
                udp.stdout, "127.0.0.1", dns_port
            ):
                return True
            self._sleep(0.5)
        return False

    # ---- command builders ----------------------------------------------
    def _delete_table_commands(self) -> tuple[tuple[str, ...], ...]:
        return (
            (*self._prefix, "nft", "delete", "table", "ip", NAT_TABLE),
            (*self._prefix, "nft", "delete", "table", "inet", FILTER_TABLE),
        )

    def _install_command(self, source: str, target: str) -> tuple[str, ...]:
        return (*self._prefix, "install", "-m", "0644", "-o", "root", "-g", "root", source, target)

    def _verify_command(self) -> tuple[str, ...]:
        return (
            *self._prefix,
            "tor",
            "--runasdaemon",
            "0",
            "--defaults-torrc",
            DEFAULTS_TORRC,
            "-f",
            TORRC,
            "--verify-config",
        )

    def _reload_command(self) -> tuple[str, ...]:
        return (*self._prefix, "systemctl", "reload", "tor.service")

    def _state_commands(self, plan: GlobalPlan) -> tuple[tuple[str, ...], ...]:
        return (
            (
                *self._prefix,
                "install",
                "-d",
                "-m",
                "0755",
                "-o",
                "root",
                "-g",
                "root",
                STATE_DIR,
            ),
            self._install_command(_STATE_PLACEHOLDER, STATE_FILE),
        )

    def _write_file(self, directory: str, name: str, content: str, mode: int) -> str:
        path = os.path.join(directory, name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        return path

    def _state_payload(
        self, plan: GlobalPlan, labeled: Sequence[tuple[int, str]] = ()
    ) -> str:
        return json.dumps(
            {
                "version": 1,
                "trans_port": plan.trans_port,
                "dns_port": plan.dns_port,
                "tor_uid": plan.tor_uid,
                "allow_lan": plan.allow_lan,
                "labeled": [
                    {"port": port, "proto": proto} for port, proto in labeled
                ],
                "created": int(time.time()),
            },
            sort_keys=True,
        )

    # ---- lifecycle -----------------------------------------------------
    def plan(
        self,
        *,
        trans_port: int = 9040,
        dns_port: int = 5300,
        allow_lan: bool = False,
    ) -> GlobalPlan:
        return build_global_plan(
            trans_port=trans_port,
            dns_port=dns_port,
            tor_uid=self._detect_uid(),
            allow_lan=allow_lan,
        )

    def start(
        self,
        *,
        trans_port: int = 9040,
        dns_port: int = 5300,
        allow_lan: bool = False,
        dry_run: bool = False,
    ) -> GlobalResult:
        try:
            plan = self.plan(
                trans_port=trans_port, dns_port=dns_port, allow_lan=allow_lan
            )
        except ValueError as exc:
            return GlobalResult(False, False, str(exc))

        if dry_run:
            labels = ensure_ports(
                self._runner,
                self._prefix,
                ((plan.trans_port, "tcp"), (plan.dns_port, "udp")),
                dry_run=True,
            )
            commands = (
                *labels.commands,
                self._install_command(_DROPIN_PLACEHOLDER, plan.dropin_path),
                self._verify_command(),
                self._reload_command(),
                (*self._prefix, "nft", "-c", "-f", _PLACEHOLDER),
                (*self._prefix, "nft", "-f", _PLACEHOLDER),
                *self._state_commands(plan),
            )
            return GlobalResult(
                True, False, "dry-run; nothing was changed", commands, plan
            )

        if not exists("nft"):
            return GlobalResult(False, False, "nft command is not installed", (), plan)
        service = self._runner(("systemctl", "is-active", "tor.service"))
        if service.stdout.strip() != "active":
            return GlobalResult(
                False,
                False,
                "tor.service is not active; run `chxsec tor start` first",
                (),
                plan,
            )

        nat = self._table_present("ip", NAT_TABLE)
        filt = self._table_present("inet", FILTER_TABLE)
        if nat or filt:
            return GlobalResult(
                False,
                False,
                "global mode tables already exist; run `chxsec global stop` first",
                self._delete_table_commands(),
                plan,
            )

        existing_dropin = self._read(plan.dropin_path)
        installed_dropin = False
        if existing_dropin is None:
            if self._port_in_use("tcp", plan.trans_port):
                return GlobalResult(
                    False,
                    False,
                    f"TCP port {plan.trans_port} is already in use; "
                    "choose a different --trans-port",
                    (),
                    plan,
                )
            if self._port_in_use("udp", plan.dns_port):
                return GlobalResult(
                    False,
                    False,
                    f"UDP port {plan.dns_port} is already in use; "
                    "choose a different --dns-port",
                    (),
                    plan,
                )
        elif not self._dropin_matches(existing_dropin, plan):
            return GlobalResult(
                False,
                False,
                "a different global Tor drop-in exists; run `chxsec global stop` first",
                (),
                plan,
            )

        commands: list[tuple[str, ...]] = []
        labeled: tuple[tuple[int, str], ...] = ()

        def rollback(detail: str) -> GlobalResult:
            for command in self._delete_table_commands():
                commands.append(command)
                self._runner(command)
            if installed_dropin:
                remove = (*self._prefix, "rm", "-f", plan.dropin_path)
                commands.append(remove)
                self._runner(remove)
            commands.extend(unlabel_ports(self._runner, self._prefix, labeled))
            if service.stdout.strip() == "active":
                commands.append(self._reload_command())
                self._runner(commands[-1])
            cleanup = (*self._prefix, "rm", "-f", STATE_FILE)
            commands.append(cleanup)
            self._runner(cleanup)
            return GlobalResult(False, False, f"{detail}; rollback attempted", tuple(commands), plan)

        labels = ensure_ports(
            self._runner,
            self._prefix,
            ((plan.trans_port, "tcp"), (plan.dns_port, "udp")),
        )
        commands.extend(labels.commands)
        labeled = labels.labeled
        if not labels.ok:
            return rollback(labels.detail)

        with tempfile.TemporaryDirectory(prefix="chxsec-") as directory:
            if not installed_dropin and existing_dropin is None:
                config = with_managed_ports(plan.torrc, labeled)
                source = self._write_file(directory, "global.conf", config, 0o600)
                install = self._install_command(source, plan.dropin_path)
                commands.append(install)
                if not self._runner(install).ok:
                    return rollback("could not install the global Tor drop-in")
                installed_dropin = True

            verify = self._verify_command()
            commands.append(verify)
            if not self._runner(verify).ok:
                return rollback("Tor rejected the global configuration")
            reload = self._reload_command()
            commands.append(reload)
            if not self._runner(reload).ok:
                return rollback("Tor reload failed")
            if not self._wait_listening(plan.trans_port, plan.dns_port):
                return rollback("Tor is not listening on the global ports")

            ruleset = self._write_file(directory, "global.nft", plan.ruleset, 0o600)
            check = (*self._prefix, "nft", "-c", "-f", ruleset)
            apply = (*self._prefix, "nft", "-f", ruleset)
            commands.extend((check, apply))
            if not self._runner(check).ok:
                return rollback("the global ruleset failed nft validation")
            if not self._runner(apply).ok:
                return rollback("applying the global nftables ruleset failed")

            state = self._write_file(
                directory, "global.json", self._state_payload(plan, labeled), 0o600
            )
            mkdir, install_state = (
                self._state_commands(plan)[0],
                self._install_command(state, STATE_FILE),
            )
            commands.extend((mkdir, install_state))
            if not self._runner(mkdir).ok or not self._runner(install_state).ok:
                return rollback("could not record the global mode state")

        return GlobalResult(
            True,
            True,
            "whole-host Tor mode is active (fail-closed nftables)",
            tuple(commands),
            plan,
        )

    def stop(self) -> GlobalResult:
        commands: list[tuple[str, ...]] = []
        results = [
            (family, table, self._table_present(family, table))
            for family, table in (("ip", NAT_TABLE), ("inet", FILTER_TABLE))
        ]
        for family, table, present in results:
            if present is False:
                continue
            command = (*self._prefix, "nft", "delete", "table", family, table)
            commands.append(command)
            result = self._runner(command)
            if not result.ok and "No such file or directory" not in result.stderr:
                return GlobalResult(
                    False,
                    False,
                    "could not remove the global nftables tables; "
                    "keeping the Tor drop-in so traffic stays protected",
                    tuple(commands),
                )

        contents = self._read(DROPIN_PATH)
        state_contents = self._read(STATE_FILE)
        ports = list(
            dict.fromkeys(
                [
                    *(managed_ports(contents) if contents is not None else []),
                    *self._state_labeled(state_contents),
                ]
            )
        )
        if contents is not None:
            remove = (*self._prefix, "rm", "-f", DROPIN_PATH)
            commands.append(remove)
            if not self._runner(remove).ok:
                return GlobalResult(
                    False,
                    False,
                    "tables removed but the Tor drop-in could not be removed",
                    tuple(commands),
                )
        if ports:
            commands.extend(unlabel_ports(self._runner, self._prefix, ports))
            if self._runner(("systemctl", "is-active", "tor.service")).stdout.strip() == "active":
                commands.append(self._reload_command())
                if not self._runner(commands[-1]).ok:
                    return GlobalResult(
                        False,
                        False,
                        "drop-in removed but Tor reload failed",
                        tuple(commands),
                    )

        commands.append((*self._prefix, "rm", "-f", STATE_FILE))
        self._runner(commands[-1])
        return GlobalResult(
            True, False, "whole-host Tor mode is disabled", tuple(commands)
        )

    def status(self) -> GlobalStatus:
        state = self._read(STATE_FILE)
        payload: dict[str, object] = {}
        if state:
            try:
                loaded = json.loads(state)
                if isinstance(loaded, dict):
                    payload = loaded
            except json.JSONDecodeError:
                payload = {}
        trans_port = payload.get("trans_port") if isinstance(payload.get("trans_port"), int) else None
        dns_port = payload.get("dns_port") if isinstance(payload.get("dns_port"), int) else None
        tor_uid = payload.get("tor_uid") if isinstance(payload.get("tor_uid"), int) else None
        allow_lan = payload.get("allow_lan") if isinstance(payload.get("allow_lan"), bool) else None
        dropin = os.path.lexists(DROPIN_PATH)
        nat = self._table_present("ip", NAT_TABLE, readonly=True)
        filt = self._table_present("inet", FILTER_TABLE, readonly=True)
        listening = (
            trans_port is not None
            and dns_port is not None
            and _listening(
                self._runner(("ss", "-Hltn", f"sport = :{trans_port}")).stdout,
                "127.0.0.1",
                trans_port,
            )
            and _listening(
                self._runner(("ss", "-Hlun", f"sport = :{dns_port}")).stdout,
                "127.0.0.1",
                dns_port,
            )
        )
        if dropin and listening and nat is not False and filt is not False:
            detail = "whole-host Tor mode is active"
            if nat is None or filt is None:
                detail += " (nftables tables could not be verified without privileges)"
            return GlobalStatus(
                True, "active", detail, dropin, nat, filt,
                trans_port, dns_port, tor_uid, allow_lan,
            )
        if not dropin and not state and nat is not True and filt is not True:
            return GlobalStatus(False, "inactive", "whole-host Tor mode is inactive")
        return GlobalStatus(
            False,
            "partial",
            "global mode looks partially applied; run `chxsec global stop` "
            "and start it again",
            dropin,
            nat,
            filt,
            trans_port,
            dns_port,
            tor_uid,
            allow_lan,
        )

    @staticmethod
    def _state_labeled(content: str | None) -> list[tuple[int, str]]:
        if not content:
            return []
        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, dict):
            return []
        entries = payload.get("labeled")
        if not isinstance(entries, list):
            return []
        ports: list[tuple[int, str]] = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            port = entry.get("port")
            proto = entry.get("proto")
            if isinstance(port, int) and 1 <= port <= 65535 and proto in {"tcp", "udp"}:
                ports.append((port, proto))
        return ports

    @staticmethod
    def _dropin_matches(content: str, plan: GlobalPlan) -> bool:
        return (
            "chxsec global mode" in content
            and f"TransPort 127.0.0.1:{plan.trans_port}" in content
            and f"DNSPort 127.0.0.1:{plan.dns_port}" in content
        )
