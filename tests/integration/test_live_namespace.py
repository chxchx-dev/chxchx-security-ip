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
        if result.network_ready:
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
        if network.network_ready:
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
    if not exists("nc"):
        pytest.skip("nc is required for this leak test")

    session_id = f"it-start-{uuid.uuid4().hex[:8]}"
    filter_table, _ = table_names(session_id)
    probes: dict[str, str] = {}

    def executor(argv):
        probe = run(list(argv), timeout=15)
        probes["output"] = probe.stdout
        counters = run(["sudo", "nft", "-a", "list", "table", "inet", filter_table], timeout=10)
        probes["counters_before_leak_attempt"] = counters.stdout
        return 0 if probe.ok else probe.returncode

    runtime = SessionRuntime(executor=executor)
    result = runtime.start(
        session_id,
        [
            "sh", "-c",
            "echo ROUTE4:; ip route show; "
            "echo IPV6FLAG:; cat /proc/sys/net/ipv6/conf/all/disable_ipv6; "
            "echo ROUTE6:; ip -6 route show; echo END; "
            "nc -u -w1 -z 198.51.100.7 12345 || true",
        ],
        subnet="10.203.12.0/30",
        trans_port=19040,
        dns_port=15300,
    )

    assert result.ok is True, result.detail
    output = probes["output"]
    route4 = output.split("ROUTE4:\n", 1)[1].split("IPV6FLAG:", 1)[0]
    ipv6_flag = output.split("IPV6FLAG:\n", 1)[1].split("ROUTE6:", 1)[0].strip()
    route6 = output.split("ROUTE6:\n", 1)[1].split("END", 1)[0].strip()

    assert "default via 10.203.12.1" in route4
    assert ipv6_flag == "1"
    assert route6 == ""
    assert 'oifname "chxh-' in probes["counters_before_leak_attempt"]

    namespaces = run(["sudo", "ip", "netns", "list"], timeout=5).stdout
    assert f"chxsec-{session_id}" not in namespaces
