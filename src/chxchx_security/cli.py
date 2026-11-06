from __future__ import annotations

import argparse
import json
import shlex
import sys

from rich.prompt import Confirm, Prompt

from chxchx_security import __version__
from chxchx_security.config import ConfigurationError, Settings
from chxchx_security.services.audit import doctor
from chxchx_security.services.global_runtime import GlobalRuntime
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
    ensure_service,
    protected_shell,
    rotate_identity,
    run_protected,
    service_state,
    socks_reachable,
    start_service,
    stop_service,
    verify,
)
from chxchx_security.utils.redact import mask_ip
from chxchx_security.ui import (
    checks_table,
    console,
    header,
    print_signature,
    prompt_interactive_menu,
    show_command_guide,
)


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
    tor_sub.add_parser("stop", help="Stop the Tor system service")
    verify_p = tor_sub.add_parser("verify")
    verify_p.add_argument("--reveal-ip", action="store_true")
    verify_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    rotate_p = tor_sub.add_parser(
        "new-identity",
        aliases=["rotate"],
        help="Request a new Tor circuit and report whether the exit IP changed",
    )
    rotate_p.add_argument(
        "--restart",
        action="store_true",
        help="Restart tor.service instead of using the Tor control interface",
    )
    rotate_p.add_argument(
        "--reveal-ip",
        action="store_true",
        help="Show the previous and current exit IPs",
    )
    rotate_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    run_p = sub.add_parser("run", help="Run a compatible command through torsocks")
    run_p.add_argument("argv", nargs=argparse.REMAINDER)

    sub.add_parser("shell", help="Start an ephemeral torsocks shell")

    session = sub.add_parser("session", help="Manage isolated protected sessions")
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

    global_p = sub.add_parser(
        "global",
        help="Route the whole host through Tor with a fail-closed kill switch (privileged)",
    )
    global_sub = global_p.add_subparsers(dest="global_command", required=True)
    global_plan = global_sub.add_parser(
        "plan", help="Show the non-executing whole-host ruleset and Tor config"
    )
    global_plan.add_argument("--trans-port", type=int, default=9040)
    global_plan.add_argument("--dns-port", type=int, default=5300)
    global_plan.add_argument("--allow-lan", action="store_true")
    global_plan.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    global_start = global_sub.add_parser(
        "start",
        help="Install the whole-host Tor kill switch (privileged; needs --yes)",
    )
    global_start.add_argument("--trans-port", type=int, default=9040)
    global_start.add_argument("--dns-port", type=int, default=5300)
    global_start.add_argument("--allow-lan", action="store_true")
    global_start.add_argument(
        "--yes", action="store_true", help="Actually change Tor and nftables"
    )
    global_start.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    global_stop = global_sub.add_parser(
        "stop", help="Remove the whole-host Tor kill switch (privileged)"
    )
    global_stop.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    global_status = global_sub.add_parser("status", help="Show whole-host Tor mode status")
    global_status.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

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
    console.print("Bienvenido. Elige una opción; puedes volver aquí después de cada acción.")
    console.print("Tor seguirá activo al salir del menú hasta que elijas detenerlo.")
    global_runtime = GlobalRuntime()
    last_status = 0

    while True:
        try:
            choice = prompt_interactive_menu()
            if choice == "0":
                console.print("Hasta luego.")
                return last_status
            if choice == "1":
                checks = doctor(settings)
                checks_table(checks)
                last_status = 0 if _checks_ok(checks) else 1
            elif choice == "2":
                result = start_service()
                if result.ok:
                    console.print(
                        "[green]Tor se inició y seguirá activo al salir del menú.[/]"
                    )
                    console.print("Elige 3 o ejecuta chxsec tor stop cuando quieras detenerlo.")
                else:
                    console.print(f"[red]{result.stderr or result.stdout}[/]")
                last_status = 0 if result.ok else 1
            elif choice == "3":
                if Confirm.ask(
                    "Esto detendrá Tor también para otras aplicaciones. ¿Continuar?",
                    default=False,
                ):
                    result = stop_service()
                    if result.ok:
                        console.print("[green]Tor se detuvo.[/]")
                    else:
                        console.print(f"[red]{result.stderr or result.stdout}[/]")
                    last_status = 0 if result.ok else 1
                else:
                    console.print("No se detuvo Tor.")
                    last_status = 0
            elif choice == "4":
                state = service_state()
                console.print(f"Estado del servicio Tor: {state}")
                last_status = 0 if state == "active" else 1
            elif choice == "5":
                result = verify(settings)
                if result.ok:
                    console.print(
                        f"[green]{result.detail}[/] "
                        f"(IP de salida: {result.ip or 'oculta'})"
                    )
                else:
                    console.print(f"[red]{result.detail}[/]")
                last_status = 0 if result.ok else 1
            elif choice == "6":
                console.print(
                    "[yellow]Esta shell protege programas TCP compatibles; "
                    "no es un túnel para todo el equipo.[/]"
                )
                try:
                    last_status = protected_shell(settings)
                except RuntimeError as exc:
                    console.print(f"[red]{exc}[/]")
                    last_status = 1
            elif choice == "7":
                items = active_connections()
                if not items:
                    console.print("No se encontraron perfiles activos.")
                for item in items:
                    console.print(f"- {connection_label(item)}")
                last_status = 0
            elif choice == "8":
                raw_command = Prompt.ask(
                    "Programa y argumentos, sin pipes ni redirecciones "
                    "(ej.: curl https://example.com)",
                    default="",
                )
                try:
                    command = shlex.split(raw_command)
                except ValueError as exc:
                    console.print(f"[red]No pude interpretar el comando: {exc}[/]")
                    last_status = 2
                else:
                    if not command:
                        console.print("No se escribió ningún comando.")
                    else:
                        try:
                            last_status = run_protected(settings, command)
                        except RuntimeError as exc:
                            console.print(f"[red]{exc}[/]")
                            last_status = 1
                        console.print(f"El comando terminó con código {last_status}.")
            elif choice == "9":
                show_command_guide()
            elif choice == "10":
                console.print(
                    "[yellow]Modo global: todo el tráfico del host saldrá por Tor. "
                    "UDP, ICMP e IPv6 quedarán bloqueados. La LAN también se bloquea "
                    "salvo que uses `chxsec global start --allow-lan`.[/]"
                )
                if Confirm.ask(
                    "Esto modificará nftables y Tor y requiere sudo. ¿Continuar?",
                    default=False,
                ):
                    service = ensure_service(settings)
                    if not service.ok:
                        console.print(
                            f"[red]{service.stderr or service.stdout or 'Tor is not available'}[/]"
                        )
                        last_status = 1
                    else:
                        result = global_runtime.start(dry_run=False)
                        console.print(f"Estado: {result.detail}")
                        last_status = 0 if result.ok else 1
                else:
                    console.print("No se activó el modo global.")
                    last_status = 0
            elif choice == "11":
                console.print(
                    "[yellow]Cambiar de identidad no borra cookies, cuentas ni huellas. "
                    "Tor puede reutilizar la misma salida.[/]"
                )
                if Confirm.ask(
                    "¿Pedir una nueva identidad a Tor ahora?", default=False
                ):
                    result = rotate_identity(settings)
                    console.print(result.detail)
                    if result.ok:
                        previous = mask_ip(result.previous_ip) if result.previous_ip else "no disponible"
                        current = mask_ip(result.current_ip) if result.current_ip else "no disponible"
                        console.print(f"IP anterior: {previous} · IP actual: {current}")
                    last_status = 0 if result.ok else 1
                else:
                    console.print("No se cambió la identidad.")
                    last_status = 0
            elif choice == "12":
                if Confirm.ask(
                    "Esto desactivará el modo global y el tráfico saldrá directo. ¿Continuar?",
                    default=False,
                ):
                    result = global_runtime.stop()
                    console.print(f"Estado: {result.detail}")
                    last_status = 0 if result.ok else 1
                else:
                    console.print("El modo global sigue activo.")
                    last_status = 0
            elif choice == "13":
                status = global_runtime.status()
                console.print(f"Modo global: {status.state} — {status.detail}")
                last_status = 0 if status.active else 1

            Prompt.ask("Presiona Enter para volver al menú", default="")
        except KeyboardInterrupt:
            console.print("\nMenú interrumpido.")
            return 130
        except EOFError:
            console.print("\nFin de la entrada.")
            return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        settings = Settings.from_env()
    except ConfigurationError as exc:
        parser.error(str(exc))

    if args.command is None:
        if not sys.stdin.isatty():
            parser.print_help()
            return 0
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
        if args.tor_command == "stop":
            result = stop_service()
            console.print("Tor stopped" if result.ok else result.stderr or result.stdout)
            return 0 if result.ok else 1
        if args.tor_command == "verify":
            result = verify(settings, reveal_ip=args.reveal_ip)
            if args.json:
                print(_verification_json(result))
            else:
                console.print(f"{result.detail}; exit={result.ip or 'not shown'}")
            return 0 if result.ok else 1
        if args.tor_command in {"new-identity", "rotate"}:
            result = rotate_identity(settings, restart=args.restart)
            previous = (
                result.previous_ip
                if args.reveal_ip
                else (mask_ip(result.previous_ip) if result.previous_ip else None)
            )
            current = (
                result.current_ip
                if args.reveal_ip
                else (mask_ip(result.current_ip) if result.current_ip else None)
            )
            if args.json:
                print(
                    json.dumps(
                        {
                            "ok": result.ok,
                            "changed": result.changed,
                            "previous_ip": previous,
                            "current_ip": current,
                            "detail": result.detail,
                            "error": result.error_code,
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                )
            else:
                console.print(result.detail)
                if result.ok:
                    console.print(
                        f"IP anterior: {previous or 'no disponible'} · "
                        f"IP actual: {current or 'no disponible'}"
                    )
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
            if args.yes:
                service = ensure_service(settings)
                if not service.ok:
                    console.print(
                        f"[red]{service.stderr or service.stdout or 'Tor is not available'}[/]"
                    )
                    return 1
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

    if args.command == "global":
        runtime = GlobalRuntime()
        if args.global_command == "plan":
            try:
                plan = runtime.plan(
                    trans_port=args.trans_port,
                    dns_port=args.dns_port,
                    allow_lan=args.allow_lan,
                )
            except ValueError as exc:
                console.print(f"[red]{exc}[/]")
                return 2
            if args.json:
                print(json.dumps(plan.as_dict(), ensure_ascii=False, sort_keys=True))
            else:
                console.print(
                    f"trans_port={plan.trans_port} dns_port={plan.dns_port} "
                    f"tor_uid={plan.tor_uid} allow_lan={plan.allow_lan}"
                )
                console.print(f"dropin={plan.dropin_path}")
                console.print("This plan changes nothing; review it before running start.")
                console.print(plan.ruleset, end="", markup=False)
                console.print(plan.torrc, end="", markup=False)
            return 0

        if args.global_command == "start":
            if args.yes:
                service = ensure_service(settings)
                if not service.ok:
                    console.print(
                        f"[red]{service.stderr or service.stdout or 'Tor is not available'}[/]"
                    )
                    return 1
            result = runtime.start(
                trans_port=args.trans_port,
                dns_port=args.dns_port,
                allow_lan=args.allow_lan,
                dry_run=not args.yes,
            )
            if args.json:
                print(json.dumps(result.as_dict(), ensure_ascii=False, sort_keys=True))
            else:
                console.print(f"status={result.detail}")
                for command in result.commands:
                    console.print(f"- {' '.join(command)}", markup=False)
                if result.plan is not None and not result.applied:
                    console.print(result.plan.ruleset, end="", markup=False)
                    console.print(result.plan.torrc, end="", markup=False)
                if not args.yes:
                    console.print("Re-run with --yes to apply these changes.")
                elif result.ok:
                    console.print(
                        "[yellow]Todo el tráfico del host sale ahora por Tor; "
                        "UDP, ICMP e IPv6 quedan bloqueados.[/]"
                    )
            return 0 if result.ok else 1

        if args.global_command == "stop":
            result = runtime.stop()
            if args.json:
                print(json.dumps(result.as_dict(), ensure_ascii=False, sort_keys=True))
            else:
                console.print(f"status={result.detail}")
                for command in result.commands:
                    console.print(f"- {' '.join(command)}", markup=False)
            return 0 if result.ok else 1

        if args.global_command == "status":
            status = runtime.status()
            if args.json:
                print(json.dumps(status.as_dict(), ensure_ascii=False, sort_keys=True))
            else:
                console.print(f"state={status.state}")
                console.print(f"detail={status.detail}")
                console.print(f"dropin={'yes' if status.dropin else 'no'}")
                console.print(f"tables=nat:{status.nat_table} filter:{status.filter_table}")
                if status.trans_port is not None:
                    console.print(
                        f"ports=127.0.0.1:{status.trans_port}/tcp,"
                        f"127.0.0.1:{status.dns_port}/udp"
                    )
                if status.allow_lan is not None:
                    console.print(f"allow_lan={status.allow_lan}")
            return 0 if status.active else 1

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
