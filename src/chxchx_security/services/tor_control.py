from __future__ import annotations

import hashlib
import os
import re
import socket
from dataclasses import dataclass

from chxchx_security.config import Settings

CONTROL_TIMEOUT_SECONDS = 5.0
DEFAULT_COOKIE_PATHS = (
    "/run/tor/control.authcookie",
    "/var/run/tor/control.authcookie",
)
_PASSWORD_ENV = "CHXSEC_TOR_CONTROL_PASSWORD"
_SAFE_SERVER = b"Tor safe cookie authentication server-to-controller hash"
_SAFE_CLIENT = b"Tor safe cookie authentication controller-to-server hash"


class TorControlError(RuntimeError):
    """Raised when Tor's control interface cannot rotate the circuit."""


@dataclass(frozen=True)
class ProtocolInfo:
    methods: tuple[str, ...]
    cookiefile: str | None


def parse_protocolinfo(lines: list[str]) -> ProtocolInfo:
    methods: tuple[str, ...] = ()
    cookiefile: str | None = None
    for line in lines:
        match = re.search(r"AUTH METHODS=([A-Za-z0-9_,]+)", line)
        if match:
            methods = tuple(match.group(1).split(","))
        match = re.search(r'COOKIEFILE="([^"]+)"', line)
        if match:
            cookiefile = match.group(1)
    return ProtocolInfo(methods, cookiefile)


def _readline(sock: socket.socket, buffer: bytearray) -> str:
    while b"\r\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            raise TorControlError("Tor closed the control connection")
        buffer.extend(chunk)
    line, _, rest = buffer.partition(b"\r\n")
    buffer[:] = rest
    return line.decode("utf-8", "replace")


def _read_reply(sock: socket.socket, buffer: bytearray) -> list[str]:
    lines: list[str] = []
    while True:
        line = _readline(sock, buffer)
        lines.append(line)
        if len(line) < 4:
            raise TorControlError(f"invalid Tor control reply: {line!r}")
        code, separator = line[:3], line[3]
        if separator == "+":
            while True:
                data = _readline(sock, buffer)
                lines.append(data)
                if data == ".":
                    break
            continue
        if separator == " ":
            if code.startswith("2"):
                return lines
            raise TorControlError(f"Tor control error: {line}")
        if separator == "-":
            continue
        raise TorControlError(f"invalid Tor control reply: {line!r}")


def _command(sock: socket.socket, buffer: bytearray, command: str) -> list[str]:
    sock.sendall((command + "\r\n").encode("utf-8"))
    return _read_reply(sock, buffer)


def _connect(settings: Settings) -> socket.socket:
    path = settings.tor_control_socket
    if path and os.path.exists(path):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(CONTROL_TIMEOUT_SECONDS)
        try:
            sock.connect(path)
        except OSError as exc:
            sock.close()
            raise TorControlError(f"cannot connect to Tor control socket: {exc}") from exc
        return sock

    try:
        sock = socket.create_connection(
            (settings.tor_control_host, settings.tor_control_port),
            timeout=CONTROL_TIMEOUT_SECONDS,
        )
    except OSError as exc:
        raise TorControlError(
            "Tor control port is not reachable; enable ControlPort/CookieAuthentication "
            "or set CHXSEC_TOR_CONTROL_SOCKET"
        ) from exc
    sock.settimeout(CONTROL_TIMEOUT_SECONDS)
    return sock


def _cookie_path(settings: Settings, info: ProtocolInfo) -> str | None:
    if settings.tor_control_cookie:
        return settings.tor_control_cookie
    if info.cookiefile:
        return info.cookiefile
    for candidate in DEFAULT_COOKIE_PATHS:
        if os.path.exists(candidate):
            return candidate
    return None


def _read_cookie(settings: Settings, info: ProtocolInfo) -> bytes:
    path = _cookie_path(settings, info)
    if not path:
        raise TorControlError(
            "Tor uses cookie authentication but no cookie file was found; "
            "set CHXSEC_TOR_CONTROL_COOKIE"
        )
    try:
        with open(path, "rb") as handle:
            cookie = handle.read()
    except OSError as exc:
        raise TorControlError(
            "cannot read Tor's control cookie; add your user to the Tor control "
            f"group (toranon on Fedora, debian-tor on Debian) or set "
            f"CHXSEC_TOR_CONTROL_COOKIE ({exc.__class__.__name__})"
        ) from exc
    if not cookie:
        raise TorControlError("Tor's control cookie is empty")
    return cookie


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _authenticate(
    sock: socket.socket,
    buffer: bytearray,
    settings: Settings,
    info: ProtocolInfo,
) -> None:
    if "COOKIE" in info.methods:
        cookie = _read_cookie(settings, info)
        _command(sock, buffer, f"AUTHENTICATE {cookie.hex()}")
        return
    if "SAFECOOKIE" in info.methods:
        cookie = _read_cookie(settings, info)
        client_nonce = os.urandom(32)
        reply = _command(sock, buffer, f"AUTHCHALLENGE SAFECOOKIE {client_nonce.hex()}")
        server_hash = None
        server_nonce = None
        for line in reply:
            match = re.search(r"SERVERHASH=([0-9A-Fa-f]+)", line)
            if match:
                server_hash = bytes.fromhex(match.group(1))
            match = re.search(r"SERVERNONCE=([0-9A-Fa-f]+)", line)
            if match:
                server_nonce = bytes.fromhex(match.group(1))
        if server_hash is None or server_nonce is None:
            raise TorControlError("Tor returned an invalid SAFECOOKIE challenge")
        expected = hashlib.sha256(
            _SAFE_SERVER + cookie + client_nonce + server_nonce
        ).digest()
        if server_hash != expected:
            raise TorControlError("Tor SAFECOOKIE server hash did not match")
        client_hash = hashlib.sha256(
            _SAFE_CLIENT + cookie + client_nonce + server_nonce
        ).digest()
        _command(sock, buffer, f"AUTHENTICATE {client_hash.hex()}")
        return
    password = os.getenv(_PASSWORD_ENV)
    if password:
        _command(sock, buffer, f"AUTHENTICATE {_quote(password)}")
        return
    if "NULL" in info.methods or not info.methods:
        _command(sock, buffer, "AUTHENTICATE")
        return
    raise TorControlError(
        "Tor requires an authentication method chxsec does not support; "
        "enable CookieAuthentication 1"
    )


def request_newnym(settings: Settings) -> None:
    """Ask Tor for a new circuit and therefore a new exit node."""
    sock = _connect(settings)
    buffer = bytearray()
    try:
        info = parse_protocolinfo(_command(sock, buffer, "PROTOCOLINFO 1"))
        _authenticate(sock, buffer, settings, info)
        _command(sock, buffer, "SIGNAL NEWNYM")
    finally:
        sock.close()
