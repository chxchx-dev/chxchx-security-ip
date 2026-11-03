from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

console = Console()

BANNER_MAIN = r"""
   ██████╗██╗  ██╗██╗  ██╗ ██████╗██╗  ██╗██╗  ██╗
  ██╔════╝██║  ██║╚██╗██╔╝██╔════╝██║  ██║╚██╗██╔╝
  ██║     ███████║ ╚███╔╝ ██║     ███████║ ╚███╔╝
  ██║     ██╔══██║ ██╔██╗ ██║     ██╔══██║ ██╔██╗
  ╚██████╗██║  ██║██╔╝ ██╗╚██████╗██║  ██║██╔╝ ██╗
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝

              C H X C H X   S E C U R I T Y

               PRIVACY • SECURITY • CONTROL

                      by @chxchx-dev

                [ SYSTEM STATUS: SECURED ]
"""

SIGNATURE_SHORT = r"""┌─[ CHXCHX SECURITY ]──────────────────────────┐
│                                             │
│   Privacy • Security • Control              │
│                                             │
│   chxsec $ _                                │
│                                             │
│                     by @chxchx-dev          │
└─────────────────────────────────────────────┘"""


def header(version: str) -> None:
    console.print(BANNER_MAIN, markup=False, highlight=False)
    console.print(f"v{version} · privacy orchestrator", style="dim", markup=False, highlight=False)


def print_signature() -> None:
    console.print(SIGNATURE_SHORT, markup=False, highlight=False)


def checks_table(checks) -> None:
    table = Table(title="Privacy readiness")
    table.add_column("Check")
    table.add_column("State")
    table.add_column("Detail")
    for check in checks:
        table.add_row(check.name, "OK" if check.ok else "WARN", check.detail)
    console.print(table)


def prompt_interactive_menu() -> str:
    console.print()
    console.print("[bold]¿Qué quieres hacer?[/]")
    console.print("[bold cyan]1[/] Revisar el sistema — dependencias y estado de Tor.")
    console.print("[bold cyan]2[/] Iniciar Tor.")
    console.print("[bold cyan]3[/] Detener Tor — también afecta a otras aplicaciones.")
    console.print("[bold cyan]4[/] Consultar el estado de Tor.")
    console.print("[bold cyan]5[/] Verificar la conexión a través de Tor.")
    console.print("[bold cyan]6[/] Abrir una shell protegida.")
    console.print("[bold cyan]7[/] Ver perfiles activos de NetworkManager.")
    console.print("[bold cyan]8[/] Ejecutar un programa a través de Tor.")
    console.print("[bold cyan]9[/] Ver la guía de comandos y sesiones avanzadas.")
    console.print("[bold cyan]0[/] Salir.")
    return Prompt.ask(
        "Selecciona una opción",
        choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
        default="1",
    )


def show_command_guide() -> None:
    console.print()
    console.print("[bold]Guía rápida de comandos[/]")
    console.print(
        "Empieza por estas tareas; usa chxsec --help o chxsec session --help "
        "para ver todas las opciones:"
    )
    console.print()
    console.print("[cyan]chxsec doctor[/] — revisar el sistema y sus requisitos.")
    console.print("[cyan]chxsec tor status[/] — consultar el servicio y el proxy SOCKS.")
    console.print("[cyan]chxsec tor start[/] — iniciar el servicio Tor.")
    console.print("[cyan]chxsec tor stop[/] — detenerlo también para las otras aplicaciones.")
    console.print("  El servicio sigue activo al cerrar el menú; detenerlo requiere una acción explícita.")
    console.print("[cyan]chxsec tor verify[/] — comprobar que la conexión sale por Tor.")
    console.print(
        "[cyan]chxsec run -- <programa> [argumentos][/] — "
        "ejecutar un programa compatible por Tor."
    )
    console.print("  Ejemplo: chxsec run -- curl https://example.com")
    console.print("[cyan]chxsec shell[/] — abrir una shell protegida para programas TCP compatibles.")
    console.print("[cyan]chxsec mac list[/] — ver perfiles activos.")
    console.print("[cyan]chxsec mac apply \"<perfil>\" random[/] — cambiar la política MAC.")
    console.print("  Usa --reconnect solo si aceptas interrumpir la conexión.")
    console.print()
    console.print("[bold]Sesiones aisladas (avanzado)[/]")
    console.print("[cyan]chxsec session tools[/] — comprobar herramientas disponibles.")
    console.print("[cyan]chxsec session plan demo[/] — revisar el plan general.")
    console.print("[cyan]chxsec session network-plan demo[/] — revisar la red propuesta.")
    console.print("[cyan]chxsec session firewall-plan demo[/] — revisar el firewall.")
    console.print("[cyan]chxsec session tor-port-plan 10.203.0.1[/] — revisar listeners Tor.")
    console.print("[cyan]chxsec session start demo -- curl https://example.com[/] — simular.")
    console.print("[cyan]chxsec session start --yes demo -- curl https://example.com[/]")
    console.print("  Este último comando aplica la sesión y requiere privilegios.")
    console.print("  Conserva el ID; [cyan]chxsec session destroy demo[/] limpia sus recursos.")
    console.print()
    console.print(
        "La protección cubre solo los procesos que ejecutas con ChxChx; "
        "no convierte todo el equipo en anónimo."
    )
    console.print("Para navegar de forma anónima, usa Tor Browser.")
