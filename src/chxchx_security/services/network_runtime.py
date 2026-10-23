from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from chxchx_security.services.namespace_runtime import NamespaceRuntime
from chxchx_security.services.network_plan import NetworkPlan, build_network_plan
from chxchx_security.utils.process import CmdResult, run

CommandRunner = Callable[[Sequence[str]], CmdResult]


@dataclass(frozen=True)
class NetworkApplyResult:
    ok: bool
    session_id: str
    namespace: str
    applied: bool
    detail: str
    commands: tuple[tuple[str, ...], ...] = ()

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "session_id": self.session_id,
            "namespace": self.namespace,
            "applied": self.applied,
            "detail": self.detail,
            "commands": [list(command) for command in self.commands],
        }


class NetworkRuntime:
    """Creates a namespace and wires a veth pair; installs no route to the outside."""

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        privileged_prefix: tuple[str, ...] | None = None,
    ) -> None:
        self._runner = runner or (lambda argv: run(argv, timeout=30))
        self._namespaces = NamespaceRuntime(
            runner=self._runner, privileged_prefix=privileged_prefix
        )
        self._prefix = self._namespaces._privileged_prefix

    def _commands(self, plan: NetworkPlan) -> tuple[tuple[str, ...], ...]:
        steps = [
            step.command
            for step in plan.steps
            if step.status == "planned" and step.command
        ]
        return tuple((*self._prefix, *command[1:]) for command in steps)

    def _rollback(self, plan: NetworkPlan, *, remove_veth: bool) -> bool:
        if remove_veth:
            veth = self._runner((*self._prefix, "ip", "link", "delete", plan.host_interface))
            veth_ok = veth.ok or "Cannot find device" in veth.stderr
        else:
            veth_ok = True
        namespace = self._namespaces.destroy(plan.session_id)
        return namespace.ok and veth_ok

    def apply(
        self,
        session_id: str,
        *,
        subnet: str,
        trans_port: int = 9040,
        dns_port: int = 5300,
        dry_run: bool = False,
    ) -> NetworkApplyResult:
        plan = build_network_plan(
            session_id, subnet=subnet, trans_port=trans_port, dns_port=dns_port
        )
        commands = self._commands(plan)
        if dry_run:
            return NetworkApplyResult(
                True,
                session_id,
                plan.namespace,
                False,
                "dry-run; nothing was changed",
                self._namespaces.create(session_id, dry_run=True).commands + commands,
            )

        created = self._namespaces.create(session_id)
        if not created.ok:
            return NetworkApplyResult(
                False, session_id, plan.namespace, False, created.detail, created.commands
            )

        executed = list(created.commands)
        veth_created = False
        for index, command in enumerate(commands):
            executed.append(command)
            if not self._runner(command).ok:
                rolled_back = self._rollback(plan, remove_veth=veth_created)
                state = "rollback completed" if rolled_back else "rollback FAILED; clean up manually"
                return NetworkApplyResult(
                    False,
                    session_id,
                    plan.namespace,
                    False,
                    f"network wiring failed; {state}",
                    tuple(executed),
                )
            if index == 0:
                veth_created = True

        return NetworkApplyResult(
            True,
            session_id,
            plan.namespace,
            True,
            "veth wired; no route to the outside is installed",
            tuple(executed),
        )
