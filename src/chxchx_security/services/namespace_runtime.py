from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Sequence

from chxchx_security.services.namespace import detect_namespace_tools
from chxchx_security.services.session import (
    SessionLifecycle,
    SessionState,
    namespace_name,
)
from chxchx_security.services.namespace_config import (
    NETNS_CONFIG_ROOT,
    configure_namespace_resolver,
    remove_namespace_resolver,
)
from chxchx_security.utils.process import CmdResult, run


CommandRunner = Callable[[Sequence[str]], CmdResult]


@dataclass(frozen=True)
class NamespaceResult:
    ok: bool
    action: str
    session_id: str
    namespace: str
    state: SessionState
    network_ready: bool
    detail: str
    commands: tuple[tuple[str, ...], ...] = ()


class NamespaceRuntime:
    """Lifecycle-only namespace adapter; it does not configure network access."""

    def __init__(
        self,
        *,
        runner: CommandRunner | None = None,
        privileged_prefix: tuple[str, ...] | None = None,
    ) -> None:
        self._runner = runner or (lambda argv: run(argv, timeout=30))
        if privileged_prefix is None:
            privileged_prefix = () if os.geteuid() == 0 else ("sudo",)
        self._privileged_prefix = privileged_prefix

    def _create_commands(self, namespace: str) -> tuple[tuple[str, ...], ...]:
        prefix = self._privileged_prefix
        return (
            (*prefix, "ip", "netns", "add", namespace),
            (*prefix, "ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"),
        )

    def _destroy_command(self, namespace: str) -> tuple[str, ...]:
        return (*self._privileged_prefix, "ip", "netns", "delete", namespace)

    def create(self, session_id: str, *, dry_run: bool = False) -> NamespaceResult:
        lifecycle = SessionLifecycle(session_id)
        namespace = lifecycle.namespace
        commands = self._create_commands(namespace)
        if dry_run:
            return NamespaceResult(
                True,
                "create",
                session_id,
                namespace,
                SessionState.STARTING,
                False,
                "dry-run; no namespace was created",
                commands,
            )

        tools = detect_namespace_tools()
        if not tools.ip:
            return NamespaceResult(
                False,
                "create",
                session_id,
                namespace,
                SessionState.FAILED,
                False,
                "ip command is not installed",
                commands,
            )
        if self._privileged_prefix == ("sudo",) and not tools.sudo:
            return NamespaceResult(
                False,
                "create",
                session_id,
                namespace,
                SessionState.FAILED,
                False,
                "sudo is not installed",
                commands,
            )

        created = self._runner(commands[0])
        if not created.ok:
            return NamespaceResult(
                False,
                "create",
                session_id,
                namespace,
                SessionState.FAILED,
                False,
                "namespace creation failed",
                commands,
            )

        loopback = self._runner(commands[1])
        if not loopback.ok:
            rollback = self._runner(self._destroy_command(namespace))
            rollback_detail = "rollback completed" if rollback.ok else "rollback failed"
            return NamespaceResult(
                False,
                "create",
                session_id,
                namespace,
                SessionState.FAILED,
                False,
                f"loopback setup failed; {rollback_detail}",
                commands + (self._destroy_command(namespace),),
            )

        return NamespaceResult(
            True,
            "create",
            session_id,
            namespace,
            SessionState.ACTIVE,
            False,
            "namespace created; network wiring is not configured",
            commands,
        )

    def configure_resolver(
        self,
        session_id: str,
        gateway_address: str,
        *,
        dry_run: bool = False,
    ) -> NamespaceResult:
        namespace = namespace_name(session_id)
        configured = configure_namespace_resolver(
            namespace,
            gateway_address,
            runner=self._runner,
            prefix=self._privileged_prefix,
            config_root=NETNS_CONFIG_ROOT,
            dry_run=dry_run,
        )
        state = (
            SessionState.STARTING
            if dry_run
            else SessionState.ACTIVE
            if configured.ok
            else SessionState.FAILED
        )
        return NamespaceResult(
            configured.ok,
            "configure-resolver",
            session_id,
            namespace,
            state,
            configured.ok and not dry_run,
            configured.detail,
            configured.commands,
        )

    def _remove_resolver_config(
        self, namespace: str
    ) -> tuple[bool, str, tuple[tuple[str, ...], ...]]:
        result = remove_namespace_resolver(
            namespace,
            runner=self._runner,
            prefix=self._privileged_prefix,
            config_root=NETNS_CONFIG_ROOT,
        )
        return result.ok, result.detail, result.commands

    def destroy(self, session_id: str, *, dry_run: bool = False) -> NamespaceResult:
        namespace = namespace_name(session_id)
        command = self._destroy_command(namespace)
        resolver_path = os.path.join(NETNS_CONFIG_ROOT, namespace, "resolv.conf")
        resolver_dir = os.path.dirname(resolver_path)
        cleanup_plan = (
            (*self._privileged_prefix, "rm", "-f", "--", resolver_path),
            (*self._privileged_prefix, "rmdir", "--", resolver_dir),
        )
        if dry_run:
            return NamespaceResult(
                True,
                "destroy",
                session_id,
                namespace,
                SessionState.DESTROYED,
                False,
                "dry-run; namespace and managed DNS config would be removed",
                (command, *cleanup_plan),
            )

        result = self._runner(command)
        if not result.ok:
            return NamespaceResult(
                False,
                "destroy",
                session_id,
                namespace,
                SessionState.FAILED,
                False,
                "namespace destruction failed",
                (command,),
            )

        resolver_ok, detail, resolver_commands = self._remove_resolver_config(namespace)
        return NamespaceResult(
            resolver_ok,
            "destroy",
            session_id,
            namespace,
            SessionState.DESTROYED if resolver_ok else SessionState.FAILED,
            False,
            f"namespace destroyed; {detail}",
            (command, *resolver_commands),
        )
