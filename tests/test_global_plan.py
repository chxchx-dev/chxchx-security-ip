import pytest

from chxchx_security.services.global_plan import (
    DROPIN_PATH,
    FILTER_TABLE,
    NAT_TABLE,
    GlobalPlanError,
    build_global_plan,
)


def test_global_plan_redirects_tcp_and_dns_through_tor():
    plan = build_global_plan(tor_uid=967)

    assert plan.executable is False
    assert plan.nat_table == NAT_TABLE
    assert plan.filter_table == FILTER_TABLE
    assert plan.dropin_path == DROPIN_PATH
    assert "meta l4proto tcp redirect to :9040" in plan.ruleset
    assert "udp dport 53 redirect to :5300" in plan.ruleset
    assert "meta skuid 967 return" in plan.ruleset
    assert "meta skuid 967 accept" in plan.ruleset
    assert "TransPort 127.0.0.1:9040" in plan.torrc
    assert "DNSPort 127.0.0.1:5300" in plan.torrc
    assert "AutomapHostsOnResolve 1" in plan.torrc


def test_global_plan_is_fail_closed_for_udp_icmp_and_ipv6():
    plan = build_global_plan(tor_uid=967)

    assert "meta l4proto udp counter drop" in plan.ruleset
    assert "meta l4proto tcp counter drop" in plan.ruleset
    assert "meta l4proto icmp counter drop" in plan.ruleset
    assert "meta l4proto ipv6-icmp counter drop" in plan.ruleset
    assert plan.ruleset.rstrip().endswith("counter drop\n    }\n}")
    assert "10.0.0.0/8" not in plan.ruleset


def test_global_plan_can_opt_into_lan_traffic():
    plan = build_global_plan(tor_uid=967, allow_lan=True)

    assert "10.0.0.0/8" in plan.ruleset
    assert "192.168.0.0/16" in plan.ruleset
    assert plan.allow_lan is True


def test_global_plan_rejects_root_tor_and_invalid_ports():
    with pytest.raises(GlobalPlanError):
        build_global_plan(tor_uid=0)
    with pytest.raises(GlobalPlanError):
        build_global_plan(tor_uid=967, trans_port=9040, dns_port=9040)
    with pytest.raises(GlobalPlanError):
        build_global_plan(tor_uid=967, trans_port=0)
