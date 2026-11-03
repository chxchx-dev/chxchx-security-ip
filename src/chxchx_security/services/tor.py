from __future__ import annotations

import json
import os
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from chxchx_security.config import Settings
from chxchx_security.utils.process import CmdResult, exists, run
from chxchx_security.utils.redact import mask_ip


@dataclass(frozen=True)
class TorVerification:
    ok: bool
    is_tor: bool
    ip: str | None
    detail: str
    error_code: str | None = None


VERIFY_ATTEMPTS = 3
VERIFY_RETRY_DELAY_SECONDS = 0.5


def socks_reachable(settings: Settings) -> bool:
    try:
        with socket.create_connection(
            (settings.tor_socks_host, settings.tor_socks_port), timeout=1.5
        ):
            return True
    except OSError:
        return False


def service_state() -> str:
    if not exists("systemctl"):
        return "unavailable"
    result = run(["systemctl", "is-active", "tor.service"], timeout=5)
    return result.stdout or result.stderr or "unknown"


def start_service() -> CmdResult:
    if not exists("systemctl"):
        return CmdResult(False, 127, "", "systemctl not found")
    return run(["sudo", "systemctl", "start", "tor.service"], timeout=30)

def stop_service() -> CmdResult:
    if not exists("systemctl"):
        return CmdResult(False, 127, "", "systemctl not found")
    return run(["sudo", "systemctl", "stop", "tor.service"], timeout=30)


def verify(settings: Settings, *, reveal_ip: bool = False) -> TorVerification:
    if not exists("curl"):
        return TorVerification(False, False, None, "curl is required", "missing_dependency")
    if not socks_reachable(settings):
        return TorVerification(
            False,
            False,
            None,
            "Tor SOCKS port is not reachable",
            "socks_unreachable",
        )

    proxy = f"{settings.tor_socks_host}:{settings.tor_socks_port}"
    argv = [
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        str(settings.http_timeout_seconds),
        "--socks5-hostname",
        proxy,
        settings.tor_check_url,
    ]
    result = None
    for attempt in range(1, VERIFY_ATTEMPTS + 1):
        result = run(argv, timeout=settings.http_timeout_seconds + 3)
        if result.ok:
            break
        if attempt < VERIFY_ATTEMPTS:
            time.sleep(VERIFY_RETRY_DELAY_SECONDS)

    assert result is not None
    if not result.ok:
        error_code = "timeout" if result.returncode == 124 else "check_request_failed"
        detail = (
            "Tor check timed out"
            if error_code == "timeout"
            else f"Tor check request failed after {VERIFY_ATTEMPTS} attempts"
        )
        return TorVerification(False, False, None, detail, error_code)

    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return TorVerification(
            False, False, None, "Tor check returned invalid JSON", "invalid_response"
        )

    if not isinstance(payload, dict):
        return TorVerification(
            False, False, None, "Tor check returned an invalid response", "invalid_response"
        )

    is_tor = payload.get("IsTor") is True
    raw_ip = payload.get("IP") if isinstance(payload.get("IP"), str) else None
    shown_ip = raw_ip if reveal_ip else (mask_ip(raw_ip) if raw_ip else None)
    return TorVerification(
        ok=is_tor,
        is_tor=is_tor,
        ip=shown_ip,
        detail="Tor path verified" if is_tor else "Endpoint did not confirm Tor",
        error_code=None if is_tor else "not_tor",
    )


def require_verified_route(settings: Settings) -> None:
    """Refuse protected execution unless the configured route is confirmed as Tor."""
    result = verify(settings)
    if not result.ok:
        code = f" [{result.error_code}]" if result.error_code else ""
        raise RuntimeError(f"Tor route is not verified{code}: {result.detail}")


def protected_argv(settings: Settings, command: list[str]) -> list[str]:
    if not command:
        raise ValueError("No command supplied")
    return [
        "torsocks",
        "--isolate",
        "--address",
        settings.tor_socks_host,
        "--port",
        str(settings.tor_socks_port),
        *command,
    ]


def run_protected(settings: Settings, command: list[str]) -> int:
    if not exists("torsocks"):
        raise RuntimeError("torsocks is not installed")
    require_verified_route(settings)
    argv = protected_argv(settings, command)
    return subprocess.call(argv)


def protected_shell(settings: Settings) -> int:
    if not exists("torsocks"):
        raise RuntimeError("torsocks is not installed")
    require_verified_route(settings)

    runtime_parent = Path(os.getenv("XDG_RUNTIME_DIR", "/dev/shm"))
    runtime_parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="chxsec-", dir=runtime_parent) as tmp:
        os.chmod(tmp, 0o700)
        env = os.environ.copy()
        env.update(
            {
                "HISTFILE": "/dev/null",
                "HISTSIZE": "0",
                "SAVEHIST": "0",
                "TMPDIR": tmp,
                "CHXSEC_PROTECTED_SHELL": "1",
            }
        )
        old_umask = os.umask(0o077)
        try:
            return subprocess.call(
                [
                    "torsocks",
                    "--isolate",
                    "--address",
                    settings.tor_socks_host,
                    "--port",
                    str(settings.tor_socks_port),
                    "--shell",
                ],
                env=env,
            )
        finally:
            os.umask(old_umask)
