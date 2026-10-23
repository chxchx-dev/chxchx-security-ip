from chxchx_security.services.firewall_plan import build_firewall_plan


def test_firewall_plan_is_fail_closed_and_uses_private_tor_redirects():
    plan = build_firewall_plan("demo", subnet="10.203.0.0/30")

    assert plan.executable is False
    assert "policy drop" not in plan.ruleset
    assert 'iifname "chxh-2a97516c" counter drop' in plan.ruleset
    assert 'oifname "chxh-2a97516c" counter drop' in plan.ruleset
    assert "meta l4proto tcp redirect to :9040" in plan.ruleset
    assert "tcp dport 53" not in plan.ruleset
    assert "udp dport 53 redirect to :5300" in plan.ruleset
    assert "chxsec_nat_2a97516c" in plan.ruleset


def test_firewall_plan_reuses_network_and_tor_validation():
    plan = build_firewall_plan(
        "demo",
        subnet="10.203.0.0/30",
        trans_port=19040,
        dns_port=15353,
    )

    assert plan.trans_port == 19040
    assert plan.dns_port == 15353
    assert ":19040" in plan.ruleset
    assert ":15353" in plan.ruleset


def test_firewall_rules_never_touch_other_interfaces():
    plan = build_firewall_plan("demo", subnet="10.203.0.0/30")
    forward = plan.ruleset.split("chain forward", 1)[1].split("chain output", 1)[0]

    for line in forward.splitlines():
        if line.strip().endswith("drop"):
            assert "chxh-2a97516c" in line


def test_forward_drop_rules_are_countable_for_leak_tests():
    plan = build_firewall_plan("demo", subnet="10.203.0.0/30")

    assert "counter drop" in plan.ruleset


def test_gateway_address_is_only_reachable_from_the_session_interface():
    plan = build_firewall_plan("demo", subnet="10.203.0.0/30")

    assert 'ip daddr 10.203.0.1 iifname != "chxh-2a97516c" drop' in plan.ruleset
