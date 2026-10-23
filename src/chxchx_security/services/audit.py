from __future__ import annotations

import glob
import platform
from dataclasses import dataclass

from chxchx_security.config import Settings
from chxchx_security.services.tor import service_state, socks_reachable
from chxchx_security.utils.process import exists, run


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _os_release_data() -> dict[str, str]:
    try:
        data = {}
        with open("/etc/os-release", "r", encoding="utf-8") as handle:
            for line in handle:
                if "=" in line:
                    key, val = line.rstrip().split("=", 1)
                    data[key] = val.strip('"')
    except OSError:
        return {"NAME": platform.system()}
    return data


def _os_check() -> Check:
    release = _os_release_data()
    distro_id = release.get("ID", "").lower()
    package_manager = {
        "fedora": "dnf",
        "ubuntu": "apt-get",
        "kali": "apt-get",
    }.get(distro_id)
    supported = platform.system() == "Linux" and package_manager is not None and exists(package_manager)
    version = release.get("VERSION_ID", "")
    detail = f"{release.get('NAME', 'Linux')} {version}".strip()
    if not supported:
        detail = f"unsupported or missing package manager: {detail}"
    return Check("OS", supported, detail)


def _clock_check() -> Check:
    if not exists("timedatectl"):
        return Check("System clock", False, "timedatectl not found")
    result = run(
        ["timedatectl", "show", "-p", "NTPSynchronized", "--value"], timeout=5
    )
    if result.ok and result.stdout.strip().lower() == "yes":
        return Check("System clock", True, "synchronized")
    return Check("System clock", False, "not synchronized")


def _session_dropin_check() -> Check:
    stale = sorted(glob.glob("/etc/tor/torrc.d/chxsec-*.conf"))
    if not stale:
        return Check("Session Tor drop-ins", True, "none")
    return Check(
        "Session Tor drop-ins",
        False,
        f"{len(stale)} present; if no session is active, run `chxsec session destroy <id>` "
        "(a stale drop-in can stop Tor from starting after a reboot)",
    )


def doctor(settings: Settings) -> list[Check]:
    tor_state = service_state()
    checks = [
        _os_check(),
        Check("Tor binary", exists("tor"), "installed" if exists("tor") else "missing"),
        Check("torsocks", exists("torsocks"), "installed" if exists("torsocks") else "missing"),
        Check("curl", exists("curl"), "installed" if exists("curl") else "missing"),
        Check("NetworkManager CLI", exists("nmcli"), "installed" if exists("nmcli") else "missing"),
        Check("Tor service", tor_state == "active", tor_state),
        Check("Tor SOCKS", socks_reachable(settings), f"{settings.tor_socks_host}:{settings.tor_socks_port}"),
        _clock_check(),
        _session_dropin_check(),
    ]
    if exists("firewall-cmd"):
        state = run(["firewall-cmd", "--state"], timeout=5)
        checks.append(Check("firewalld", state.ok, state.stdout or state.stderr))
    return checks
