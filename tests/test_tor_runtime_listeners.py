from chxchx_security.services.tor_runtime import TorPortRuntime
from chxchx_security.utils.process import CmdResult


def test_missing_dns_listener_fails_even_when_transport_listener_is_ready():
    calls = []

    def runner(command):
        command = tuple(command)
        calls.append(command)
        output = "LISTEN 0 4096 10.203.0.1:9040 0.0.0.0:*" if command[1] == "-Hltn" else ""
        return CmdResult(True, 0, output, "")

    runtime = TorPortRuntime(
        runner=runner, privileged_prefix=(), sleep=lambda _seconds: None
    )

    assert runtime._wait_listening("10.203.0.1", 9040, 5300) is False
    assert calls == [
        ("ss", "-Hltn", "sport = :9040"),
        ("ss", "-Hlun", "sport = :5300"),
    ] * 10
