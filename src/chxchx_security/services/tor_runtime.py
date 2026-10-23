from __future__ import annotations

import os
import re
import tempfile
import time
from dataclasses import dataclass
from typing import Callable, Sequence

from chxchx_security.services.network_plan import build_network_plan
from chxchx_security.services.session import validate_session_id
from chxchx_security.services.tor_ports import build_tor_port_plan
from chxchx_security.utils.process import CmdResult, run

CommandRunner = Callable[[Sequence[str]], CmdResult]

DROPIN_DIR = "/etc/tor/torrc.d"
TORRC = "/etc/tor/torrc"
DEFAULTS_TORRC = "/usr/share/tor/defaults-torrc"
SELINUX_PORT_TYPE = "tor_port_t"
_PLACEHOLDER = "<dropin-file>"
_WILDCARDS = {"0.0.0.0", "*", "[::]", "::"}
_TRANS_PORT_RE = re.compile(r"^TransPort\s+\S+:(\d+)", re.MULTILINE)
_DNS_PORT_RE = re.compile(r"^DNSPort\s+\S+:(\d+)", re.MULTILINE)


def dropin_path(session_id: str) -> str:
    return os.path.join(DROPIN_DIR, f"chxsec-{validate_session_id(session_id)}.conf")


@dataclass(frozen=True)
class TorPortResult:
    ok: bool
    session_id: str
    applied: bool
    detail: str
    commands: tuple[tuple[str, ...], ...] = ()
    config: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "session_id": self.session_id,
            "applied": self.applied,
            "detail": self.detail,
            "commands": [list(command) for command in self.commands],
            "config": self.config,
        }


def _listening(output: str, address: str, port: int) -> bool:
    return any(_local(row) == (address, port) for row in output.splitlines())


def _conflicting(output: str, address: str, port: int) -> bool:
    for row in output.splitlines():
        local = _local(row)
        if local and local[1] == port and (local[0] in _WILDCARDS or local[0] == address):
            return True
    return False


def _local(row: str) -> tuple[str, int] | None:
    columns = row.split()
    if len(columns) < 4:
        return None
    host, _, port = columns[3].rpartition(":")
    return (host, int(port)) if port.isdigit() else None


def _selinux_port_type(semanage_port_list: str, proto: str, port: int) -> str | None:
    """Find which SELinux type (if any) a port is registered under, e.g. from `semanage port -l`."""
    for line in semanage_port_list.splitlines():
        columns = line.split()
        if len(columns) < 3 or columns[1] != proto:
            continue
        port_type = columns[0]
        for port_range in " ".join(columns[2:]).split(","):
            port_range = port_range.strip()
            if "-" in port_range:
                low, _, high = port_range.partition("-")
                if low.isdigit() and high.isdigit() and int(low) <= port <= int(high):
                    return port_type
            elif port_range == str(port):
                return port_type
    return None


def _configured_ports(dropin_content: str) -> list[tuple[int, str]]:
    ports = []
    if match := _TRANS_PORT_RE.search(dropin_content):
        ports.append((int(match.group(1)), "tcp"))
    if match := _DNS_PORT_RE.search(dropin_content):
        ports.append((int(match.group(1)), "udp"))
    return ports


class TorPortRuntime:
    """Adds a per-session Tor drop-in and reloads Tor; never restarts the service."""

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

    def _reload(self) -> CmdResult:
        return self._runner((*self._prefix, "systemctl", "reload", "tor.service"))

    def _wait_listening(self, address: str, trans_port: int, dns_port: int) -> bool:
        for _ in range(10):
            tcp = self._runner(("ss", "-Hltn", f"sport = :{trans_port}"))
            udp = self._runner(("ss", "-Hlun", f"sport = :{dns_port}"))
            if _listening(tcp.stdout, address, trans_port) and _listening(
                udp.stdout, address, dns_port
            ):
                return True
            self._sleep(0.5)
        return False

    def _unlabel_ports(self, ports: list[tuple[int, str]]) -> list[tuple[str, ...]]:
        commands = []
        for port, proto in ports:
            command = (*self._prefix, "semanage", "port", "-d", "-t", SELINUX_PORT_TYPE, "-p", proto, str(port))
            commands.append(command)
            self._runner(command)  # best-effort: a missing entry is not an error
        return commands

    def remove(self, session_id: str, *, force: bool = False) -> TorPortResult:
        path = dropin_path(session_id)
        existing = self._runner(("cat", path))
        if (
            not force
            and not os.path.lexists(path)
            and not existing.ok
        ):
            return TorPortResult(True, session_id, False, "no Tor drop-in to remove")
        commands = [(*self._prefix, "rm", "-f", path)]
        if not self._runner(commands[0]).ok:
            return TorPortResult(False, session_id, False, "could not remove Tor drop-in", tuple(commands))
        commands.extend(self._unlabel_ports(_configured_ports(existing.stdout)))
        state = self._runner(("systemctl", "is-active", "tor.service"))
        if state.stdout.strip() == "active":
            commands.append((*self._prefix, "systemctl", "reload", "tor.service"))
            if not self._reload().ok:
                return TorPortResult(
                    False, session_id, False, "drop-in removed but Tor reload failed", tuple(commands)
                )
        return TorPortResult(True, session_id, False, "Tor drop-in removed", tuple(commands))

    def apply(
        self,
        session_id: str,
        *,
        subnet: str,
        trans_port: int = 9040,
        dns_port: int = 5300,
        dry_run: bool = False,
    ) -> TorPortResult:
        network = build_network_plan(
            session_id, subnet=subnet, trans_port=trans_port, dns_port=dns_port
        )
        address = network.host_address.split("/", 1)[0]
        plan = build_tor_port_plan(address, trans_port=trans_port, dns_port=dns_port)
        path = dropin_path(session_id)
        config = (
            f"# Managed by chxsec for session {session_id}; remove with "
            f"`chxsec session destroy {session_id}`\n" + plan.render()
        )
        verify = (
            *self._prefix, "tor", "--runasdaemon", "0", "--defaults-torrc",
            DEFAULTS_TORRC, "-f", TORRC, "--verify-config",
        )
        install = lambda source: (  # noqa: E731
            *self._prefix, "install", "-m", "0644", "-o", "root", "-g", "root", source, path,
        )
        reload = (*self._prefix, "systemctl", "reload", "tor.service")
        label = lambda port, proto: (  # noqa: E731
            *self._prefix, "semanage", "port", "-a", "-t", SELINUX_PORT_TYPE, "-p", proto, str(port),
        )
        if dry_run:
            return TorPortResult(
                True, session_id, False, "dry-run; nothing was changed",
                (label(trans_port, "tcp"), label(dns_port, "udp"), install(_PLACEHOLDER), verify, reload),
                config,
            )

        def fail(detail: str, commands: list[tuple[str, ...]]) -> TorPortResult:
            return TorPortResult(False, session_id, False, detail, tuple(commands), config)

        if self._runner(("systemctl", "is-active", "tor.service")).stdout.strip() != "active":
            return fail("tor.service is not active; run `chxsec tor start` first", [])
        wired = self._runner(("ip", "-o", "-4", "addr", "show", "dev", network.host_interface))
        if not wired.ok or address not in wired.stdout:
            return fail("session interface is not wired; run `session network-apply` first", [])
        if os.path.lexists(path) or self._runner(("test", "-e", path)).ok:
            return fail("Tor drop-in already exists; run `session destroy` first", [])
        tcp = self._runner(("ss", "-Hltn", f"sport = :{trans_port}"))
        udp = self._runner(("ss", "-Hlun", f"sport = :{dns_port}"))
        if _conflicting(tcp.stdout, address, trans_port):
            return fail(f"TCP port {trans_port} is already in use; choose --trans-port", [])
        if _conflicting(udp.stdout, address, dns_port):
            return fail(f"UDP port {dns_port} is already in use; choose --dns-port", [])

        commands: list[tuple[str, ...]] = []
        labeled: list[tuple[int, str]] = []
        selinux_enabled = self._runner(("getenforce",))
        if selinux_enabled.ok and selinux_enabled.stdout.strip() in {"Enforcing", "Permissive"}:
            listing = self._runner(("semanage", "port", "-l"))
            for port, proto in ((trans_port, "tcp"), (dns_port, "udp")):
                existing_type = _selinux_port_type(listing.stdout, proto, port) if listing.ok else None
                if existing_type == SELINUX_PORT_TYPE:
                    continue
                if existing_type is not None:
                    commands.extend(self._unlabel_ports(labeled))
                    return fail(
                        f"{proto} port {port} is already an SELinux '{existing_type}' port; "
                        "choose a different --trans-port/--dns-port",
                        commands,
                    )
                command = label(port, proto)
                commands.append(command)
                if not self._runner(command).ok:
                    commands.extend(self._unlabel_ports(labeled))
                    return fail(f"could not label {proto} port {port} for SELinux (tor_t needs to bind it)", commands)
                labeled.append((port, proto))
        with tempfile.TemporaryDirectory(prefix="chxsec-") as directory:
            source = os.path.join(directory, "dropin.conf")
            fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(config)
            commands.append(install(source))
            if not self._runner(commands[-1]).ok:
                commands.extend(self._unlabel_ports(labeled))
                state = "SELinux label cleanup attempted"
                return fail(f"could not install Tor drop-in; {state}", commands)

        def rollback(detail: str) -> TorPortResult:
            removed = self.remove(session_id, force=True)
            state = "rollback completed" if removed.ok else "rollback FAILED; remove the drop-in manually"
            return fail(f"{detail}; {state}", commands + list(removed.commands))

        commands.append(verify)
        if not self._runner(verify).ok:
            return rollback("Tor rejected the configuration")
        commands.append(reload)
        if not self._runner(reload).ok:
            return rollback("Tor reload failed")
        if not self._wait_listening(address, trans_port, dns_port):
            return rollback("Tor is not listening on the session address")

        return TorPortResult(
            True, session_id, True,
            "Tor is listening on the session gateway address", tuple(commands), config,
        )
