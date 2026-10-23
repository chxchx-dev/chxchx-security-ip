from __future__ import annotations

import argparse
import json
import sys

from rich.prompt import Prompt

from chxchx_security import __version__
from chxchx_security.config import ConfigurationError, Settings
from chxchx_security.services.audit import doctor
from chxchx_security.services.network import (
    ALLOWED_MAC_MODES,
    active_connections,
    apply_mac_mode,
    connection_label,
)
from chxchx_security.services.namespace import (
    build_namespace_plan,
    detect_namespace_tools,
)
from chxchx_security.services.namespace_runtime import NamespaceRuntime
from chxchx_security.services.network_plan import build_network_plan
from chxchx_security.services.network_runtime import NetworkRuntime
from chxchx_security.services.session import SessionError
from chxchx_security.services.firewall_plan import build_firewall_plan
from chxchx_security.services.firewall_runtime import FirewallRuntime
from chxchx_security.services.session_runtime import SessionRuntime
from chxchx_security.services.tor_ports import build_tor_port_plan
from chxchx_security.services.tor_runtime import TorPortRuntime
from chxchx_security.services.tor import (
    protected_shell,
    run_protected,
    service_state,
    socks_reachable,
    start_service,
    verify,
)
from chxchx_security.ui import checks_table, console, header, print_signature


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chxsec", description="ChxChx Security privacy CLI")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")

    doctor_p = sub.add_parser("doctor", help="Check local privacy prerequisites")
    doctor_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    audit_p = sub.add_parser("audit", help="Alias of doctor")
    audit_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    tor = sub.add_parser("tor", help="Tor service and route checks")
    tor_sub = tor.add_subparsers(dest="tor_command", required=True)
    tor_sub.add_parser("status")
    tor_sub.add_parser("start")
    verify_p = tor_sub.add_parser("verify")
    verify_p.add_argument("--reveal-ip", action="store_true")
    verify_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    run_p = sub.add_parser("run", help="Run a compatible command through torsocks")
    run_p.add_argument("argv", nargs=argparse.REMAINDER)

    sub.add_parser("shell", help="Start an ephemeral torsocks shell")

    session = sub.add_parser("session", help="Inspect the upcoming isolated-session engine")
    session_sub = session.add_subparsers(dest="session_command", required=True)
    session_tools = session_sub.add_parser("tools", help="Check namespace prerequisites")
    session_tools.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    session_plan = session_sub.add_parser("plan", help="Show a non-executing namespace plan")
    session_plan.add_argument("session_id", nargs="?", default="demo")
    session_plan.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    network_plan = session_sub.add_parser("network-plan", help="Show a non-executing veth/Tor plan")
    network_plan.add_argument("session_id", nargs="?", default="demo")
    network_plan.add_argument("--subnet", default="10.203.0.0/30")
    network_plan.add_argument("--trans-port", type=int, default=9040)
    network_plan.add_argument("--dns-port", type=int, default=5300)
    network_plan.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    session_start = session_sub.add_parser(
        "start",
        help="Wire network+firewall+Tor for a session and run a command inside it "
        "(privileged; needs --yes)",
    )
    session_start.add_argument("session_id")
    session_start.add_argument("--subnet", default="10.203.0.0/30")
    session_start.add_argument("--trans-port", type=int, default=9040)
    session_start.add_argument("--dns-port", type=int, default=5300)
    session_start.add_argument(
        "--yes", action="store_true", help="Actually run the privileged commands"
    )
    session_start.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    session_start.add_argument("argv", nargs=argparse.REMAINDER)
    network_apply = session_sub.add_parser(
        "network-apply",
        help="Create a namespace and wire its veth pair (privileged; needs --yes)",
    )
    network_apply.add_argument("session_id")
    network_apply.add_argument("--subnet", default="10.203.0.0/30")
    network_apply.add_argument(
        "--yes", action="store_true", help="Actually run the privileged commands"
    )
    network_apply.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    firewall_apply = session_sub.add_parser(
        "firewall-apply",
        help="Install the session's fail-closed nftables tables (privileged; needs --yes)",
    )
    firewall_apply.add_argument("session_id")
    firewall_apply.add_argument("--subnet", default="10.203.0.0/30")
    firewall_apply.add_argument("--trans-port", type=int, default=9040)
    firewall_apply.add_argument("--dns-port", type=int, default=5300)
    firewall_apply.add_argument(
        "--yes", action="store_true", help="Actually run the privileged commands"
    )
    firewall_apply.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    tor_port_apply = session_sub.add_parser(
        "tor-port-apply",
        help="Add a Tor drop-in listening on the session gateway (privileged; needs --yes)",
    )
    tor_port_apply.add_argument("session_id")
    tor_port_apply.add_argument("--subnet", default="10.203.0.0/30")
    tor_port_apply.add_argument("--trans-port", type=int, default=9040)
    tor_port_apply.add_argument("--dns-port", type=int, default=5300)
    tor_port_apply.add_argument(
        "--yes", action="store_true", help="Actually run the privileged commands"
    )
    tor_port_apply.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    session_destroy = session_sub.add_parser(
        "destroy",
        help="Remove a session's firewall tables, namespace and veth pair (privileged)",
    )
    session_destroy.add_argument("session_id")
    tor_port_plan = session_sub.add_parser(
        "tor-port-plan", help="Show a non-executing Tor listener configuration"
    )
    tor_port_plan.add_argument("bind_address", nargs="?", default="10.203.0.1")
    tor_port_plan.add_argument("--trans-port", type=int, default=9040)
    tor_port_plan.add_argument("--dns-port", type=int, default=5300)
    tor_port_plan.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    firewall_plan = session_sub.add_parser(
        "firewall-plan", help="Show a non-executing fail-closed nftables plan"
    )
    firewall_plan.add_argument("session_id", nargs="?", default="demo")
    firewall_plan.add_argument("--subnet", default="10.203.0.0/30")
    firewall_plan.add_argument("--trans-port", type=int, default=9040)
    firewall_plan.add_argument("--dns-port", type=int, default=5300)
    firewall_plan.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    mac = sub.add_parser("mac", help="NetworkManager MAC privacy")
    mac_sub = mac.add_subparsers(dest="mac_command", required=True)
    mac_list = mac_sub.add_parser("list")
    mac_list.add_argument(
        "--reveal-identifiers",
        action="store_true",
        help="Show local connection names and types",
    )
    mac_apply = mac_sub.add_parser("apply")
    mac_apply.add_argument("connection")
    mac_apply.add_argument("mode", choices=sorted(ALLOWED_MAC_MODES))
    mac_apply.add_argument("--reconnect", action="store_true")

    sub.add_parser("about")
    return parser


def _checks_json(checks) -> str:
    return json.dumps(
        {
            "ok": all(check.ok for check in checks),
            "checks": [
                {"name": check.name, "ok": check.ok, "detail": check.detail}
                for check in checks
            ],
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _checks_ok(checks) -> bool:
    return all(check.ok for check in checks)


def _verification_json(result) -> str:
    return json.dumps(
        {
            "ok": result.ok,
            "is_tor": result.is_tor,
            "ip": result.ip,
            "detail": result.detail,
            "error": result.error_code,
        },
        ensure_ascii=False,
        sort_keys=True,
    )


def _interactive(settings: Settings) -> int:
    header(__version__)
    console.print()
    console.print("[bold]1[/] Doctor / audit")
    console.print("[bold]2[/] Start Tor")
    console.print("[bold]3[/] Verify Tor route")
    console.print("[bold]4[/] Open protected shell")
    console.print("[bold]5[/] List active NetworkManager profiles")
    console.print("[bold]0[/] Exit")
    choice = Prompt.ask("Select", choices=["0", "1", "2", "3", "4", "5"], default="1")
    if choice == "0":
        return 0
    if choice == "1":
        checks = doctor(settings)
        checks_table(checks)
        return 0 if _checks_ok(checks) else 1
    if choice == "2":
        result = start_service()
        console.print("[green]Tor started[/]" if result.ok else f"[red]{result.stderr or result.stdout}[/]")
        return 0 if result.ok else 1
    if choice == "3":
        result = verify(settings)
        if result.ok:
            console.print(f"[green]{result.detail}[/] exit={result.ip or 'hidden'}")
            return 0
        console.print(f"[red]{result.detail}[/]")
        return 1
    if choice == "4":
        console.print("[yellow]This shell protects compatible TCP apps; it is not a whole-host tunnel.[/]")
        return protected_shell(settings)
    if choice == "5":
        for item in active_connections():
            console.print(f"- {connection_label(item)}")
        return 0
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        settings = Settings.from_env()
    except ConfigurationError as exc:
        parser.error(str(exc))

    if args.command is None:
        return _interactive(settings)

    if args.command in {"doctor", "audit"}:
        checks = doctor(settings)
        if getattr(args, "json", False):
            print(_checks_json(checks))
        else:
            header(__version__)
            checks_table(checks)
        return 0 if _checks_ok(checks) else 1

    if args.command == "tor":
        if args.tor_command == "status":
            console.print(f"service={service_state()} socks={'reachable' if socks_reachable(settings) else 'down'}")
            return 0
        if args.tor_command == "start":
            result = start_service()
            console.print("Tor started" if result.ok else result.stderr or result.stdout)
            return 0 if result.ok else 1
        if args.tor_command == "verify":
            result = verify(settings, reveal_ip=args.reveal_ip)
            if args.json:
                print(_verification_json(result))
            else:
                console.print(f"{result.detail}; exit={result.ip or 'not shown'}")
            return 0 if result.ok else 1

    if args.command == "run":
        command = list(args.argv)
        if command and command[0] == "--":
            command = command[1:]
        if not command:
            parser.error("chxsec run requires a command after --")
        try:
            return run_protected(settings, command)
        except RuntimeError as exc:
            console.print(f"[red]{exc}[/]")
            return 1

    if args.command == "shell":
        try:
            return protected_shell(settings)
        except RuntimeError as exc:
            console.print(f"[red]{exc}[/]")
            return 1

    if args.command == "session":
        if args.session_command == "tools":
            tools = detect_namespace_tools()
            if args.json:
                print(json.dumps(tools.as_dict(), ensure_ascii=False, sort_keys=True))
            else:
                console.print("Namespace tooling")
                for name, available in tools.as_dict().items():
                    console.print(f"- {name}: {'available' if available else 'missing'}")
                console.print(
                    "No privileged namespace action is executed by this command."
                )
            return 0 if tools.ready else 1
        if args.session_command == "plan":
            try:
                plan = build_namespace_plan(args.session_id)
            except ValueError as exc:
                console.print(f"[red]{exc}[/]")
                return 2
            if args.json:
                print(plan.as_json())
            else:
                console.print(f"session={plan.session_id} namespace={plan.namespace}")
                console.print(f"executable={'yes' if plan.executable else 'no'}")
                console.print(f"status={plan.reason}")
                for step in plan.steps:
                    command = " ".join(step.command) if step.command else "pending"
                    console.print(f"- [{step.status}] {step.name}: {command}")
            return 0
        if args.session_command == "network-plan":
            try:
                plan = build_network_plan(
                    args.session_id,
                    subnet=args.subnet,
                    trans_port=args.trans_port,
                    dns_port=args.dns_port,
                )
            except ValueError as exc:
                console.print(f"[red]{exc}[/]")
                return 2
            if args.json:
                print(json.dumps(plan.as_dict(), ensure_ascii=False, sort_keys=True))
            else:
                console.print(
                    f"session={plan.session_id} namespace={plan.namespace} subnet={plan.subnet}"
                )
                console.print(f"executable={'yes' if plan.executable else 'no'}")
                console.print(f"status={plan.reason}")
                for step in plan.steps:
                    command = " ".join(step.command) if step.command else "pending"
                    console.print(f"- [{step.status}] {step.name}: {command}")
            return 0
        if args.session_command == "start":
            command = list(args.argv)
            if command and command[0] == "--":
                command = command[1:]
            if not command:
                parser.error("chxsec session start requires a command after --")
            try:
                result = SessionRuntime().start(
                    args.session_id,
                    command,
                    subnet=args.subnet,
                    trans_port=args.trans_port,
                    dns_port=args.dns_port,
                    dry_run=not args.yes,
                )
            except ValueError as exc:
                console.print(f"[red]{exc}[/]")
                return 2
            if args.json:
                print(json.dumps(result.as_dict(), ensure_ascii=False, sort_keys=True))
            else:
                console.print(f"session={result.session_id}")
                console.print(f"status={result.detail}")
                if result.exit_code is not None:
                    console.print(f"exit_code={result.exit_code}")
                for cmd in result.commands:
                    console.print(f"- {' '.join(cmd)}", markup=False)
                if not args.yes:
                    console.print("Re-run with --yes to execute these commands.")
            return result.exit_code if result.exit_code is not None else (0 if result.ok else 1)
        if args.session_command == "network-apply":
            try:
                result = NetworkRuntime().apply(
                    args.session_id, subnet=args.subnet, dry_run=not args.yes
                )
            except ValueError as exc:
                console.print(f"[red]{exc}[/]")
                return 2
            if args.json:
                print(json.dumps(result.as_dict(), ensure_ascii=False, sort_keys=True))
            else:
                console.print(f"session={result.session_id} namespace={result.namespace}")
                console.print(f"applied={'yes' if result.applied else 'no'}")
                console.print(f"status={result.detail}")
                for command in result.commands:
                    console.print(f"- {' '.join(command)}", markup=False)
                if not args.yes:
                    console.print("Re-run with --yes to execute these commands.")
            return 0 if result.ok else 1
        if args.session_command == "firewall-apply":
            try:
                result = FirewallRuntime().apply(
                    args.session_id,
                    subnet=args.subnet,
                    trans_port=args.trans_port,
                    dns_port=args.dns_port,
                    dry_run=not args.yes,
                )
            except ValueError as exc:
                console.print(f"[red]{exc}[/]")
                return 2
            if args.json:
                print(json.dumps(result.as_dict(), ensure_ascii=False, sort_keys=True))
            else:
                console.print(f"session={result.session_id}")
                console.print(f"applied={'yes' if result.applied else 'no'}")
                console.print(f"status={result.detail}")
                for command in result.commands:
                    console.print(f"- {' '.join(command)}", markup=False)
                if not args.yes:
                    console.print(result.ruleset, end="", markup=False)
                    console.print("Re-run with --yes to execute these commands.")
            return 0 if result.ok else 1
        if args.session_command == "tor-port-apply":
            try:
                result = TorPortRuntime().apply(
                    args.session_id,
                    subnet=args.subnet,
                    trans_port=args.trans_port,
                    dns_port=args.dns_port,
                    dry_run=not args.yes,
                )
            except ValueError as exc:
                console.print(f"[red]{exc}[/]")
                return 2
            if args.json:
                print(json.dumps(result.as_dict(), ensure_ascii=False, sort_keys=True))
            else:
                console.print(f"session={result.session_id}")
                console.print(f"applied={'yes' if result.applied else 'no'}")
                console.print(f"status={result.detail}")
                for command in result.commands:
                    console.print(f"- {' '.join(command)}", markup=False)
                if not args.yes:
                    console.print(result.config, end="", markup=False)
                    console.print("Re-run with --yes to execute these commands.")
            return 0 if result.ok else 1
        if args.session_command == "destroy":
            try:
                tor_ports = TorPortRuntime().remove(args.session_id)
                firewall = FirewallRuntime().remove(args.session_id)
                result = NamespaceRuntime().destroy(args.session_id)
            except SessionError as exc:
                console.print(f"[red]{exc}[/]")
                return 2
            console.print(f"tor status={tor_ports.detail}")
            console.print(f"firewall status={firewall.detail}")
            console.print(f"namespace={result.namespace} status={result.detail}")
            return 0 if tor_ports.ok and firewall.ok and result.ok else 1
        if args.session_command == "tor-port-plan":
            try:
                plan = build_tor_port_plan(
                    args.bind_address,
                    trans_port=args.trans_port,
                    dns_port=args.dns_port,
                )
            except ValueError as exc:
                console.print(f"[red]{exc}[/]")
                return 2
            if args.json:
                print(json.dumps(plan.as_dict(), ensure_ascii=False, sort_keys=True))
            else:
                console.print(f"bind_address={plan.bind_address}")
                console.print(f"executable={'yes' if plan.executable else 'no'}")
                console.print(f"status={plan.reason}")
                for directive in plan.directives:
                    console.print(f"- {directive}")
            return 0
        if args.session_command == "firewall-plan":
            try:
                plan = build_firewall_plan(
                    args.session_id,
                    subnet=args.subnet,
                    trans_port=args.trans_port,
                    dns_port=args.dns_port,
                )
            except ValueError as exc:
                console.print(f"[red]{exc}[/]")
                return 2
            if args.json:
                print(json.dumps(plan.as_dict(), ensure_ascii=False, sort_keys=True))
            else:
                console.print(
                    f"session={plan.session_id} namespace={plan.namespace}"
                )
                console.print(f"executable={'yes' if plan.executable else 'no'}")
                console.print(f"status={plan.reason}")
                console.print(plan.ruleset, end="")
            return 0

    if args.command == "mac":
        if args.mac_command == "list":
            for item in active_connections():
                console.print(
                    f"- {connection_label(item, reveal_identifiers=args.reveal_identifiers)}"
                )
            return 0
        if args.mac_command == "apply":
            result = apply_mac_mode(args.connection, args.mode, reconnect=args.reconnect)
            if result.ok:
                console.print("[green]NetworkManager profile updated.[/]")
                if not args.reconnect:
                    console.print("Reconnect later for the new MAC policy to take effect.")
                return 0
            console.print(f"[red]{result.stderr or result.stdout}[/]")
            return 1

    if args.command == "about":
        print_signature()
        console.print(
            "ChxChx Security reduces accidental network exposure for explicitly protected processes. "
            f"It does not provide invisibility, anti-forensics, or whole-host anonymity in {__version__}."
        )
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
