from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from typing import Callable, Sequence

from chxchx_security.services.firewall_plan import (
    FirewallPlan,
    build_firewall_plan,
    table_names,
)
from chxchx_security.utils.process import CmdResult, exists, run

CommandRunner = Callable[[Sequence[str]], CmdResult]

_PLACEHOLDER = "<ruleset-file>"


@dataclass(frozen=True)
class FirewallResult:
    ok: bool
    session_id: str
    applied: bool
    detail: str
    commands: tuple[tuple[str, ...], ...] = ()
    ruleset: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "session_id": self.session_id,
            "applied": self.applied,
            "detail": self.detail,
            "commands": [list(command) for command in self.commands],
            "ruleset": self.ruleset,
        }


class FirewallRuntime:
    """Installs the session's nftables tables atomically; never touches other tables."""

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        privileged_prefix: tuple[str, ...] | None = None,
    ) -> None:
        self._runner = runner or (lambda argv: run(argv, timeout=30))
        if privileged_prefix is None:
            privileged_prefix = () if os.geteuid() == 0 else ("sudo",)
        self._prefix = privileged_prefix

    def _delete_commands(self, session_id: str) -> tuple[tuple[str, ...], ...]:
        filter_table, nat_table = table_names(session_id)
        return (
            (*self._prefix, "nft", "delete", "table", "inet", filter_table),
            (*self._prefix, "nft", "delete", "table", "ip", nat_table),
        )

    def _commands(self, plan: FirewallPlan, path: str) -> tuple[tuple[str, ...], ...]:
        return (
            (*self._prefix, "nft", "list", "table", "inet", plan.filter_table),
            (*self._prefix, "nft", "-c", "-f", path),
            (*self._prefix, "nft", "-f", path),
        )

    def remove(self, session_id: str) -> FirewallResult:
        commands = self._delete_commands(session_id)
        ok = True
        for command in commands:
            result = self._runner(command)
            if not result.ok and "No such file or directory" not in result.stderr:
                ok = False
        return FirewallResult(
            ok,
            session_id,
            False,
            "firewall tables removed" if ok else "firewall removal failed",
            commands,
        )

    def apply(
        self,
        session_id: str,
        *,
        subnet: str,
        trans_port: int = 9040,
        dns_port: int = 5300,
        dry_run: bool = False,
    ) -> FirewallResult:
        plan = build_firewall_plan(
            session_id, subnet=subnet, trans_port=trans_port, dns_port=dns_port
        )
        if dry_run:
            return FirewallResult(
                True,
                session_id,
                False,
                "dry-run; nothing was changed",
                self._commands(plan, _PLACEHOLDER),
                plan.ruleset,
            )
        if not exists("nft"):
            return FirewallResult(
                False, session_id, False, "nft command is not installed",
                self._commands(plan, _PLACEHOLDER), plan.ruleset,
            )

        with tempfile.TemporaryDirectory(prefix="chxsec-") as directory:
            path = os.path.join(directory, "ruleset.nft")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(plan.ruleset)
            list_cmd, check_cmd, apply_cmd = self._commands(plan, path)

            if self._runner(list_cmd).ok:
                return FirewallResult(
                    False, session_id, False,
                    "firewall tables already exist; run `session destroy` first",
                    (list_cmd,), plan.ruleset,
                )
            if not self._runner(check_cmd).ok:
                return FirewallResult(
                    False, session_id, False,
                    "ruleset failed nft validation; nothing was applied",
                    (list_cmd, check_cmd), plan.ruleset,
                )
            if not self._runner(apply_cmd).ok:
                cleaned = self.remove(session_id).ok
                state = "cleanup completed" if cleaned else "cleanup FAILED; remove tables manually"
                return FirewallResult(
                    False, session_id, False,
                    f"applying ruleset failed; {state}",
                    (list_cmd, check_cmd, apply_cmd), plan.ruleset,
                )

        return FirewallResult(
            True, session_id, True,
            "fail-closed nftables tables installed for the session interface only",
            (list_cmd, check_cmd, apply_cmd), plan.ruleset,
        )
