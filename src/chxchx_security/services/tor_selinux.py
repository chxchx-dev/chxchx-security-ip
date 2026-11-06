from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from chxchx_security.utils.process import CmdResult

CommandRunner = Callable[[Sequence[str]], CmdResult]

SELINUX_PORT_TYPE = "tor_port_t"
_MARKER = "# chxsec-selinux-port:"


@dataclass(frozen=True)
class LabelResult:
    ok: bool
    detail: str
    commands: tuple[tuple[str, ...], ...] = ()
    labeled: tuple[tuple[int, str], ...] = ()


def port_type(semanage_port_list: str, proto: str, port: int) -> str | None:
    """Find the most specific SELinux type assigned to a port."""
    matches: list[tuple[int, str]] = []
    for line in semanage_port_list.splitlines():
        columns = line.split()
        if len(columns) < 3 or columns[1] != proto:
            continue
        label = columns[0]
        for port_range in " ".join(columns[2:]).split(","):
            port_range = port_range.strip()
            if "-" in port_range:
                low, _, high = port_range.partition("-")
                if low.isdigit() and high.isdigit() and int(low) <= port <= int(high):
                    matches.append((int(high) - int(low), label))
            elif port_range == str(port):
                matches.append((0, label))
    if not matches:
        return None
    specificity = min(width for width, _ in matches)
    types = {label for width, label in matches if width == specificity}
    return next(iter(types)) if len(types) == 1 else "<conflicting SELinux mappings>"


def managed_ports(dropin_content: str) -> list[tuple[int, str]]:
    ports = []
    for line in dropin_content.splitlines():
        if not line.startswith(_MARKER):
            continue
        fields = line.removeprefix(_MARKER).split()
        if len(fields) != 2 or fields[0] not in {"tcp", "udp"} or not fields[1].isdigit():
            continue
        port = int(fields[1])
        if 1 <= port <= 65535:
            ports.append((port, fields[0]))
    return ports


def with_managed_ports(config: str, ports: Sequence[tuple[int, str]]) -> str:
    if not ports:
        return config
    header, body = config.split("\n", 1)
    markers = "".join(
        f"{_MARKER} {proto} {port}\n" for port, proto in ports
    )
    return f"{header}\n{markers}{body}"


def unlabel_ports(
    runner: CommandRunner,
    prefix: Sequence[str],
    ports: Sequence[tuple[int, str]],
) -> list[tuple[str, ...]]:
    commands: list[tuple[str, ...]] = []
    for port, proto in ports:
        command = (
            *prefix,
            "semanage",
            "port",
            "-d",
            "-t",
            SELINUX_PORT_TYPE,
            "-p",
            proto,
            str(port),
        )
        commands.append(command)
        runner(command)  # best effort: a missing entry is not an error
    return commands


def ensure_ports(
    runner: CommandRunner,
    prefix: Sequence[str],
    ports: Sequence[tuple[int, str]],
    *,
    dry_run: bool = False,
) -> LabelResult:
    """Make sure Tor can bind the requested ports under SELinux.

    Only entries created by this call are reported as labeled, so callers can
    roll them back without touching local administrator customizations.
    """
    label = lambda port, proto: (  # noqa: E731
        *prefix,
        "semanage",
        "port",
        "-a",
        "-t",
        SELINUX_PORT_TYPE,
        "-p",
        proto,
        str(port),
    )
    if dry_run:
        return LabelResult(
            True,
            "dry-run; SELinux labels are not changed",
            tuple(label(port, proto) for port, proto in ports),
        )

    enabled = runner(("getenforce",))
    if not enabled.ok or enabled.stdout.strip() not in {"Enforcing", "Permissive"}:
        return LabelResult(True, "SELinux is not enforcing")

    listing = runner((*prefix, "semanage", "port", "-l"))
    local_listing = runner((*prefix, "semanage", "port", "-l", "-C"))
    if not listing.ok or not local_listing.ok:
        return LabelResult(False, "could not inspect SELinux port mappings")

    commands: list[tuple[str, ...]] = []
    labeled: list[tuple[int, str]] = []

    def rollback(detail: str) -> LabelResult:
        commands.extend(unlabel_ports(runner, prefix, labeled))
        return LabelResult(False, detail, tuple(commands), ())

    for port, proto in ports:
        local_type = port_type(local_listing.stdout, proto, port)
        if local_type == SELINUX_PORT_TYPE:
            continue
        if local_type is not None:
            return rollback(
                f"{proto} port {port} has a local SELinux '{local_type}' mapping; "
                "remove or change it before applying Tor ports"
            )
        existing_type = port_type(listing.stdout, proto, port)
        if existing_type == SELINUX_PORT_TYPE:
            continue
        if existing_type not in {None, "unreserved_port_t"}:
            return rollback(
                f"{proto} port {port} is already an SELinux '{existing_type}' port; "
                "choose a different --trans-port/--dns-port"
            )
        command = label(port, proto)
        commands.append(command)
        if not runner(command).ok:
            return rollback(
                f"could not label {proto} port {port} for SELinux "
                "(tor_t needs to bind it)"
            )
        labeled.append((port, proto))

    return LabelResult(True, "SELinux ports ready", tuple(commands), tuple(labeled))
