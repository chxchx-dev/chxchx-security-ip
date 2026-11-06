import builtins

import pytest

from chxchx_security.config import Settings
from chxchx_security.services import tor_control
from chxchx_security.services.tor_control import (
    ProtocolInfo,
    TorControlError,
    parse_protocolinfo,
)


def settings(**overrides):
    values = dict(
        app_name="x",
        tor_socks_host="127.0.0.1",
        tor_socks_port=9050,
        tor_check_url="https://check.torproject.org/api/ip",
        http_timeout_seconds=10,
        allow_direct_network_tests=False,
        enable_runtime_logs=False,
        log_level="WARNING",
    )
    values.update(overrides)
    return Settings(**values)


def test_parse_protocolinfo_extracts_methods_and_cookie():
    info = parse_protocolinfo(
        [
            "250-PROTOCOLINFO 1",
            '250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/run/tor/control.authcookie"',
            '250-VERSION Tor="0.4.9.14"',
            "250 OK",
        ]
    )

    assert info.methods == ("COOKIE", "SAFECOOKIE")
    assert info.cookiefile == "/run/tor/control.authcookie"


def test_request_newnym_authenticates_and_signals(monkeypatch):
    sent = []
    replies = iter(
        [
            [
                "250-PROTOCOLINFO 1",
                "250-AUTH METHODS=NULL",
                "250 OK",
            ],
            ["250 OK"],
            ["250 OK"],
        ]
    )

    class FakeSocket:
        def close(self):
            pass

    monkeypatch.setattr(tor_control, "_connect", lambda _settings: FakeSocket())
    monkeypatch.setattr(
        tor_control,
        "_command",
        lambda _sock, _buffer, command: sent.append(command) or next(replies),
    )

    tor_control.request_newnym(settings())

    assert sent == ["PROTOCOLINFO 1", "AUTHENTICATE", "SIGNAL NEWNYM"]


def test_cookie_authentication_uses_the_cookie_hex(monkeypatch, tmp_path):
    cookie = tmp_path / "control.authcookie"
    cookie.write_bytes(b"\x00\x01\xfe\xff")
    sent = []
    monkeypatch.setattr(
        tor_control,
        "_command",
        lambda _sock, _buffer, command: sent.append(command) or ["250 OK"],
    )

    tor_control._authenticate(
        object(),
        bytearray(),
        settings(tor_control_cookie=str(cookie)),
        ProtocolInfo(("COOKIE",), None),
    )

    assert sent == ["AUTHENTICATE 0001feff"]


def test_cookie_authentication_explains_group_permissions(monkeypatch):
    monkeypatch.setattr(
        builtins,
        "open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(PermissionError()),
    )

    with pytest.raises(TorControlError) as error:
        tor_control._authenticate(
            object(),
            bytearray(),
            settings(tor_control_cookie="/run/tor/control.authcookie"),
            ProtocolInfo(("COOKIE",), None),
        )

    assert "toranon" in str(error.value)
    assert "debian-tor" in str(error.value)


def test_password_authentication_quotes_the_value(monkeypatch):
    monkeypatch.setenv("CHXSEC_TOR_CONTROL_PASSWORD", 'a"b\\c')
    sent = []
    monkeypatch.setattr(
        tor_control,
        "_command",
        lambda _sock, _buffer, command: sent.append(command) or ["250 OK"],
    )

    tor_control._authenticate(
        object(),
        bytearray(),
        settings(),
        ProtocolInfo(("HASHEDPASSWORD",), None),
    )

    assert sent == ['AUTHENTICATE "a\\"b\\\\c"']
