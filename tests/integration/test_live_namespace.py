import os
import uuid

import pytest

from chxchx_security.services.namespace_runtime import NamespaceRuntime
from chxchx_security.services.firewall_plan import table_names
from chxchx_security.services.firewall_runtime import FirewallRuntime
from chxchx_security.services.network_runtime import NetworkRuntime
from chxchx_security.services.session_runtime import SessionRuntime
from chxchx_security.services.tor_runtime import TorPortRuntime, dropin_path
from chxchx_security.services.tor import service_state
from chxchx_security.utils.process import exists
from chxchx_security.utils.process import run


pytestmark = pytest.mark.live


def test_live_namespace_create_and_destroy():
    if os.getenv("CHXSEC_RUN_NAMESPACE_TESTS") != "1":
        pytest.skip("set CHXSEC_RUN_NAMESPACE_TESTS=1 to run namespace tests")

    if os.geteuid() != 0:
        sudo_check = run(["sudo", "-n", "true"], timeout=5)
        if not sudo_check.ok:
            pytest.skip("namespace test requires root or passwordless sudo")

    session_id = f"it-ns-{uuid.uuid4().hex[:8]}"
    runtime = NamespaceRuntime()
    result = runtime.create(session_id)
    try:
        assert result.ok is True, result.detail
        assert result.network_ready is False
    finally:
        if result.ok:
            destroyed = runtime.destroy(session_id)
            assert destroyed.ok is True, destroyed.detail


def test_live_network_apply_and_destroy():
    if os.getenv("CHXSEC_RUN_NAMESPACE_TESTS") != "1":
        pytest.skip("set CHXSEC_RUN_NAMESPACE_TESTS=1 to run namespace tests")

    if os.geteuid() != 0:
        sudo_check = run(["sudo", "-n", "true"], timeout=5)
        if not sudo_check.ok:
            pytest.skip("namespace test requires root or passwordless sudo")

    session_id = f"it-net-{uuid.uuid4().hex[:8]}"
    result = NetworkRuntime().apply(session_id, subnet="10.203.9.0/30")
    try:
        assert result.ok is True, result.detail
        routes = run(["sudo", "ip", "netns", "exec", f"chxsec-{session_id}", "ip", "route"])
        assert "default" not in routes.stdout
    finally:
        if result.applied:
            destroyed = NamespaceRuntime().destroy(session_id)
            assert destroyed.ok is True, destroyed.detail


def test_live_firewall_apply_and_remove_leaves_other_rules_untouched():
    if os.getenv("CHXSEC_RUN_NAMESPACE_TESTS") != "1":
        pytest.skip("set CHXSEC_RUN_NAMESPACE_TESTS=1 to run namespace tests")

    if os.geteuid() != 0:
        sudo_check = run(["sudo", "-n", "true"], timeout=5)
        if not sudo_check.ok:
            pytest.skip("namespace test requires root or passwordless sudo")

    def ruleset():
        return run(["sudo", "nft", "-s", "list", "ruleset"]).stdout

    session_id = f"it-fw-{uuid.uuid4().hex[:8]}"
    before = ruleset()
    runtime = FirewallRuntime()
    filter_table, nat_table = table_names(session_id)
    result = runtime.apply(session_id, subnet="10.203.10.0/30")
    try:
        assert result.ok is True, result.detail
        during = ruleset()
        assert filter_table in during and nat_table in during
        assert runtime.apply(session_id, subnet="10.203.10.0/30").ok is False
    finally:
        if result.applied:
            removed = runtime.remove(session_id)
            assert removed.ok is True, removed.detail
    assert ruleset() == before


def test_live_tor_ports_apply_and_remove():
    if os.getenv("CHXSEC_RUN_NAMESPACE_TESTS") != "1":
        pytest.skip("set CHXSEC_RUN_NAMESPACE_TESTS=1 to run namespace tests")

    if os.geteuid() != 0:
        sudo_check = run(["sudo", "-n", "true"], timeout=5)
        if not sudo_check.ok:
            pytest.skip("namespace test requires root or passwordless sudo")
    if service_state() != "active":
        pytest.skip("tor.service must be active")

    session_id = f"it-tor-{uuid.uuid4().hex[:8]}"
    subnet = "10.203.11.0/30"
    network = NetworkRuntime().apply(session_id, subnet=subnet)
    tor = TorPortRuntime()
    tor_result = None
    try:
        assert network.ok is True, network.detail
        tor_result = tor.apply(session_id, subnet=subnet, trans_port=19040, dns_port=15300)
        assert tor_result.ok is True, tor_result.detail
        assert os.path.exists(dropin_path(session_id))
        assert service_state() == "active"
    finally:
        if tor_result is not None and tor_result.applied:
            removed = tor.remove(session_id)
            assert removed.ok is True, removed.detail
        if network.applied:
            destroyed = NamespaceRuntime().destroy(session_id)
            assert destroyed.ok is True, destroyed.detail
    assert not os.path.exists(dropin_path(session_id))
    assert service_state() == "active"


def test_live_session_start_routes_disables_ipv6_and_drops_unredirected_traffic():
    if os.getenv("CHXSEC_RUN_NAMESPACE_TESTS") != "1":
        pytest.skip("set CHXSEC_RUN_NAMESPACE_TESTS=1 to run namespace tests")

    if os.geteuid() != 0:
        sudo_check = run(["sudo", "-n", "true"], timeout=5)
        if not sudo_check.ok:
            pytest.skip("namespace test requires root or passwordless sudo")
    if not exists("python3"):
        pytest.skip("python3 is required for the network probes")

    session_id = f"it-start-{uuid.uuid4().hex[:8]}"
    filter_table, _ = table_names(session_id)
    probes: dict[str, str] = {}

    def executor(argv):
        probe = run(list(argv), timeout=45)
        probes["output"] = probe.stdout
        counters = run(
            ["sudo", "nft", "-a", "list", "table", "inet", filter_table],
            timeout=10,
        )
        probes["counters_after_udp_attempt"] = counters.stdout
        probes["counter_query_ok"] = "yes" if counters.ok else "no"
        return 0 if probe.ok else probe.returncode

    forwarding = run(["sysctl", "-n", "net.ipv4.ip_forward"], timeout=5)
    assert forwarding.ok, "could not read net.ipv4.ip_forward"
    previous_forwarding = forwarding.stdout.strip()
    assert previous_forwarding in {"0", "1"}, "unexpected ip_forward value"

    if previous_forwarding == "0":
        enabled = run(["sysctl", "-w", "net.ipv4.ip_forward=1"], timeout=5)
        assert enabled.ok, "could not enable forwarding for the firewall counter probe"

    runtime = SessionRuntime(executor=executor)
    try:
        result = runtime.start(
            session_id,
            [
                "sh",
                "-c",
                "set -eu; "
                "echo ROUTE4:; ip route show; "
                "echo IPV6FLAG:; cat /proc/sys/net/ipv6/conf/all/disable_ipv6; "
                "echo ROUTE6:; ip -6 route show; "
                "echo DNSCONF:; cat /etc/resolv.conf; "
                "echo TORCHECK:; "
                "python3 -c 'import json,urllib.request; "
                "opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); "
                "response=opener.open(\"https://check.torproject.org/api/ip\",timeout=30); "
                "data=json.load(response); ok=data.get(\"IsTor\") is True; "
                "print(\"TOR_OK\" if ok else \"TOR_NOT_CONFIRMED\"); "
                "raise SystemExit(0 if ok else 1)'; "
                "python3 -c 'import socket; "
                "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                "s.sendto(b\"chxsec-leak-probe\",(\"198.51.100.7\",12345)); s.close()'",
            ],
            subnet="10.203.12.0/30",
            trans_port=19040,
            dns_port=15300,
        )
    finally:
        if previous_forwarding == "0":
            restored = run(
                ["sysctl", "-w", "net.ipv4.ip_forward=0"],
                timeout=5,
            )
            assert restored.ok, "could not restore net.ipv4.ip_forward"

    assert result.ok is True, result.detail
    output = probes["output"]
    route4 = output.split("ROUTE4:\n", 1)[1].split("IPV6FLAG:", 1)[0]
    ipv6_flag = output.split("IPV6FLAG:\n", 1)[1].split("ROUTE6:", 1)[0].strip()
    route6 = output.split("ROUTE6:\n", 1)[1].split("DNSCONF:", 1)[0].strip()
    dns_config = output.split("DNSCONF:\n", 1)[1].split("TORCHECK:", 1)[0]
    assert "default via 10.203.12.1" in route4
    assert ipv6_flag == "1"
    assert route6 == ""
    assert "nameserver 10.203.12.1" in dns_config
    assert "TOR_OK" in output
    assert probes["counter_query_ok"] == "yes"

    dropped_rules = [
        line
        for line in probes["counters_after_udp_attempt"].splitlines()
        if 'iifname "chxh-' in line and " counter packets " in line and " drop" in line
    ]
    assert dropped_rules, "nftables did not report the session's forward-drop counter"
    packet_count = int(dropped_rules[0].split("packets", 1)[1].split()[0])
    assert packet_count > 0, "the unredirected UDP probe did not hit the nftables drop rule"

    namespaces = run(["sudo", "ip", "netns", "list"], timeout=5).stdout
    assert f"chxsec-{session_id}" not in namespaces
    assert not os.path.exists(f"/etc/netns/chxsec-{session_id}/resolv.conf")
    filter_after = run(
        ["sudo", "nft", "list", "table", "inet", filter_table], timeout=5
    )
    assert not filter_after.ok, "session nftables filter table was left behind"
