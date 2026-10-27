from __future__ import annotations

import ipaddress
import os
import tempfile
from dataclasses import dataclass
from typing import Callable, Sequence

from chxchx_security.utils.process import CmdResult

CommandRunner = Callable[[Sequence[str]], CmdResult]
NETNS_CONFIG_ROOT = "/etc/netns"


@dataclass(frozen=True)
class NamespaceConfigResult:
    ok: bool
    detail: str
    commands: tuple[tuple[str, ...], ...] = ()


def configure_namespace_resolver(
    namespace: str,
    gateway_address: str,
    *,
    runner: CommandRunner,
    prefix: tuple[str, ...],
    config_root: str = NETNS_CONFIG_ROOT,
    dry_run: bool = False,
) -> NamespaceConfigResult:
    gateway = ipaddress.IPv4Address(gateway_address)
    directory = os.path.join(config_root, namespace)
    resolver_path = os.path.join(directory, "resolv.conf")
    create_parent = (*prefix, "mkdir", "-p", "--", config_root)
    create_directory = (*prefix, "mkdir", "--mode=0755", "--", directory)
    install_placeholder = (
        *prefix,
        "install",
        "--mode=0644",
        "--",
        "<temporary-resolv.conf>",
        resolver_path,
    )
    planned = (create_parent, create_directory, install_placeholder)

    if dry_run:
        return NamespaceConfigResult(
            True, "dry-run; namespace DNS will use the session gateway", planned
        )
    if os.path.lexists(directory):
        return NamespaceConfigResult(
            False, "namespace DNS config already exists; refusing to overwrite it"
        )

    commands: list[tuple[str, ...]] = []
    for command in (create_parent, create_directory):
        commands.append(command)
        if not runner(command).ok:
            return NamespaceConfigResult(
                False,
                "could not create namespace DNS config directory",
                tuple(commands),
            )

    marker = f"# Managed by chxsec for {namespace}"
    content = f"{marker}\nnameserver {gateway}\noptions timeout:2 attempts:2\n"
    with tempfile.TemporaryDirectory(prefix="chxsec-resolver-") as temp_dir:
        source = os.path.join(temp_dir, "resolv.conf")
        fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        install = (*prefix, "install", "--mode=0644", "--", source, resolver_path)
        commands.append(install)
        if not runner(install).ok:
            return NamespaceConfigResult(
                False, "could not install namespace DNS config", tuple(commands)
            )

    return NamespaceConfigResult(
        True,
        "namespace DNS points to the session gateway for Tor resolution",
        tuple(commands),
    )


def remove_namespace_resolver(
    namespace: str,
    *,
    runner: CommandRunner,
    prefix: tuple[str, ...],
    config_root: str = NETNS_CONFIG_ROOT,
) -> NamespaceConfigResult:
    directory = os.path.join(config_root, namespace)
    resolver_path = os.path.join(directory, "resolv.conf")
    commands: list[tuple[str, ...]] = []

    if os.path.lexists(resolver_path):
        if os.path.islink(resolver_path) or not os.path.isfile(resolver_path):
            return NamespaceConfigResult(False, "resolver path is not a managed regular file")
        try:
            with open(resolver_path, encoding="utf-8") as handle:
                marker = handle.readline().rstrip("\n")
        except OSError:
            return NamespaceConfigResult(False, "could not inspect namespace resolver config")
        if marker != f"# Managed by chxsec for {namespace}":
            return NamespaceConfigResult(False, "unmanaged resolver config was left in place")

        remove = (*prefix, "rm", "-f", "--", resolver_path)
        commands.append(remove)
        if not runner(remove).ok:
            return NamespaceConfigResult(
                False, "could not remove namespace resolver config", tuple(commands)
            )

    if os.path.isdir(directory) and not os.path.islink(directory):
        try:
            empty = not os.listdir(directory)
        except OSError:
            return NamespaceConfigResult(
                False, "could not inspect namespace config directory", tuple(commands)
            )
        if empty:
            remove_dir = (*prefix, "rmdir", "--", directory)
            commands.append(remove_dir)
            if not runner(remove_dir).ok:
                return NamespaceConfigResult(
                    False,
                    "could not remove empty namespace config directory",
                    tuple(commands),
                )

    return NamespaceConfigResult(True, "namespace DNS config removed", tuple(commands))
