from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Callable, Sequence

from chxchx_security.services.firewall_runtime import FirewallRuntime
from chxchx_security.services.namespace_runtime import NamespaceRuntime
from chxchx_security.services.network_plan import build_network_plan
from chxchx_security.services.network_runtime import NetworkRuntime
from chxchx_security.services.tor_runtime import TorPortRuntime
from chxchx_security.utils.process import CmdResult, run

CommandRunner = Callable[[Sequence[str]], CmdResult]


@dataclass(frozen=True)
class SessionStartResult:
    ok: bool
    session_id: str
    exit_code: int | None
    detail: str
    commands: tuple[tuple[str, ...], ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "session_id": self.session_id,
            "exit_code": self.exit_code,
            "detail": self.detail,
            "commands": [list(command) for command in self.commands],
        }


class SessionRuntime:
    """Orchestrates network, firewall and Tor wiring around one protected command.

    Every step is fail-closed: if any stage fails, everything wired so far is
    rolled back before returning, and cleanup always runs after the command
    exits, even on a signal or an unhandled exception.
    """

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        privileged_prefix: tuple[str, ...] | None = None,
        executor: Callable[[Sequence[str]], int] | None = None,
    ) -> None:
        self._runner = runner or (lambda argv: run(argv, timeout=30))
        if privileged_prefix is None:
            privileged_prefix = () if os.geteuid() == 0 else ("sudo",)
        self._prefix = privileged_prefix
        self._executor = executor or (lambda argv: subprocess.call(argv))
        self._network = NetworkRuntime(runner=self._runner, privileged_prefix=privileged_prefix)
        self._firewall = FirewallRuntime(runner=self._runner, privileged_prefix=privileged_prefix)
        self._tor = TorPortRuntime(runner=self._runner, privileged_prefix=privileged_prefix)
        self._namespaces = NamespaceRuntime(runner=self._runner, privileged_prefix=privileged_prefix)

    def _disable_ipv6_command(self, namespace: str) -> tuple[str, ...]:
        return (
            *self._prefix, "ip", "netns", "exec", namespace, "sysctl", "-w",
            "net.ipv6.conf.all.disable_ipv6=1", "net.ipv6.conf.default.disable_ipv6=1",
        )

    def _route_command(self, namespace: str, host_ip: str, interface: str) -> tuple[str, ...]:
        return (
            *self._prefix, "ip", "netns", "exec", namespace, "ip", "route",
            "add", "default", "via", host_ip, "dev", interface,
        )

    def _exec_command(self, namespace: str, command: Sequence[str]) -> tuple[str, ...]:
        uid, gid = os.getuid(), os.getgid()
        if uid == 0:
            return (*self._prefix, "ip", "netns", "exec", namespace, *command)
        return (
            *self._prefix, "ip", "netns", "exec", namespace, "setpriv",
            "--reuid", str(uid), "--regid", str(gid), "--clear-groups", "--", *command,
        )

    def _cleanup(
        self,
        session_id: str,
        *,
        remove_tor: bool = True,
        remove_firewall: bool = True,
        remove_namespace: bool = True,
    ) -> str:
        tor = self._tor.remove(session_id) if remove_tor else None
        firewall = self._firewall.remove(session_id) if remove_firewall else None
        namespace = self._namespaces.destroy(session_id) if remove_namespace else None
        results = [result for result in (tor, firewall, namespace) if result is not None]
        if all(result.ok for result in results):
            return "session cleaned up"
        details = "; ".join(
            f"{name}={result.detail}"
            for name, result in (("tor", tor), ("firewall", firewall), ("namespace", namespace))
            if result is not None and not result.ok
        )
        return f"cleanup incomplete: {details}"

    def start(
        self,
        session_id: str,
        command: Sequence[str],
        *,
        subnet: str,
        trans_port: int = 9040,
        dns_port: int = 5300,
        dry_run: bool = False,
    ) -> SessionStartResult:
        if not command:
            raise ValueError("No command supplied")

        plan = build_network_plan(session_id, subnet=subnet, trans_port=trans_port, dns_port=dns_port)
        host_ip = plan.host_address.split("/", 1)[0]

        if dry_run:
            network_commands = self._network.apply(
                session_id, subnet=subnet, trans_port=trans_port, dns_port=dns_port, dry_run=True
            ).commands
            firewall_commands = self._firewall.apply(
                session_id, subnet=subnet, trans_port=trans_port, dns_port=dns_port, dry_run=True
            ).commands
            tor_commands = self._tor.apply(
                session_id, subnet=subnet, trans_port=trans_port, dns_port=dns_port, dry_run=True
            ).commands
            flat = (
                *network_commands,
                *firewall_commands,
                *tor_commands,
                self._disable_ipv6_command(plan.namespace),
                self._route_command(plan.namespace, host_ip, plan.namespace_interface),
                self._exec_command(plan.namespace, command),
            )
            return SessionStartResult(
                True, session_id, None, "dry-run; nothing was changed", flat
            )

        executed: list[tuple[str, ...]] = []

        def fail(
            detail: str,
            *,
            remove_tor: bool = False,
            remove_firewall: bool = False,
        ) -> SessionStartResult:
            cleanup_detail = self._cleanup(
                session_id,
                remove_tor=remove_tor,
                remove_firewall=remove_firewall,
            )
            if cleanup_detail != "session cleaned up":
                detail = f"{detail}; {cleanup_detail}"
            return SessionStartResult(False, session_id, None, detail, tuple(executed))

        network = self._network.apply(session_id, subnet=subnet, trans_port=trans_port, dns_port=dns_port)
        executed.extend(network.commands)
        if not network.ok:
            return SessionStartResult(False, session_id, None, network.detail, tuple(executed))

        firewall = self._firewall.apply(session_id, subnet=subnet, trans_port=trans_port, dns_port=dns_port)
        executed.extend(firewall.commands)
        if not firewall.ok:
            return fail(f"firewall setup failed: {firewall.detail}")

        tor = self._tor.apply(session_id, subnet=subnet, trans_port=trans_port, dns_port=dns_port)
        executed.extend(tor.commands)
        if not tor.ok:
            return fail(f"Tor setup failed: {tor.detail}", remove_firewall=True)

        ipv6_cmd = self._disable_ipv6_command(plan.namespace)
        executed.append(ipv6_cmd)
        if not self._runner(ipv6_cmd).ok:
            return fail("could not disable IPv6 inside the namespace", remove_tor=True, remove_firewall=True)

        route_cmd = self._route_command(plan.namespace, host_ip, plan.namespace_interface)
        executed.append(route_cmd)
        if not self._runner(route_cmd).ok:
            return fail("could not add the namespace default route", remove_tor=True, remove_firewall=True)

        exec_cmd = self._exec_command(plan.namespace, command)
        executed.append(exec_cmd)
        try:
            exit_code = self._executor(exec_cmd)
        finally:
            cleanup_detail = self._cleanup(session_id)

        detail = f"command exited {exit_code}; {cleanup_detail}"
        return SessionStartResult(
            exit_code == 0 and cleanup_detail == "session cleaned up",
            session_id,
            exit_code,
            detail,
            tuple(executed),
        )
