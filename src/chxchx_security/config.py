from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigurationError(ValueError):
    """Raised when an environment setting cannot be used safely."""


def _parse_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _parse_int(
    value: str | None,
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int | None = None,
) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigurationError(f"{name} must be an integer") from exc
    if parsed < minimum:
        raise ConfigurationError(f"{name} must be >= {minimum}")
    if maximum is not None and parsed > maximum:
        raise ConfigurationError(f"{name} must be <= {maximum}")
    return parsed


def _load_env_file(path: Path) -> None:
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def load_env() -> Path | None:
    explicit = os.getenv("CHXSEC_ENV_FILE")
    candidates = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    candidates.extend(
        [
            Path.cwd() / ".env",
            Path.home() / ".config" / "chxchx-security" / ".env",
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            _load_env_file(candidate)
            return candidate
    return None


@dataclass(frozen=True)
class Settings:
    app_name: str
    tor_socks_host: str
    tor_socks_port: int
    tor_check_url: str
    http_timeout_seconds: int
    allow_direct_network_tests: bool
    enable_runtime_logs: bool
    log_level: str
    auto_start_tor: bool = True
    tor_control_host: str = "127.0.0.1"
    tor_control_port: int = 9051
    tor_control_socket: str = "/run/tor/control"
    tor_control_cookie: str = ""

    @classmethod
    def from_env(cls) -> "Settings":
        load_env()
        return cls(
            app_name=os.getenv("CHXSEC_APP_NAME", "ChxChx Security"),
            tor_socks_host=os.getenv("CHXSEC_TOR_SOCKS_HOST", "127.0.0.1"),
            tor_socks_port=_parse_int(
                os.getenv("CHXSEC_TOR_SOCKS_PORT"),
                "CHXSEC_TOR_SOCKS_PORT",
                default=9050,
                minimum=1,
                maximum=65535,
            ),
            tor_check_url=os.getenv(
                "CHXSEC_TOR_CHECK_URL", "https://check.torproject.org/api/ip"
            ),
            http_timeout_seconds=_parse_int(
                os.getenv("CHXSEC_HTTP_TIMEOUT_SECONDS"),
                "CHXSEC_HTTP_TIMEOUT_SECONDS",
                default=15,
                minimum=1,
            ),
            allow_direct_network_tests=_parse_bool(
                os.getenv("CHXSEC_ALLOW_DIRECT_NETWORK_TESTS"), False
            ),
            enable_runtime_logs=_parse_bool(
                os.getenv("CHXSEC_ENABLE_RUNTIME_LOGS"), False
            ),
            log_level=os.getenv("CHXSEC_LOG_LEVEL", "WARNING").upper(),
            auto_start_tor=_parse_bool(os.getenv("CHXSEC_AUTO_START_TOR"), True),
            tor_control_host=os.getenv("CHXSEC_TOR_CONTROL_HOST", "127.0.0.1"),
            tor_control_port=_parse_int(
                os.getenv("CHXSEC_TOR_CONTROL_PORT"),
                "CHXSEC_TOR_CONTROL_PORT",
                default=9051,
                minimum=1,
                maximum=65535,
            ),
            tor_control_socket=os.getenv(
                "CHXSEC_TOR_CONTROL_SOCKET", "/run/tor/control"
            ),
            tor_control_cookie=os.getenv("CHXSEC_TOR_CONTROL_COOKIE", ""),
        )
