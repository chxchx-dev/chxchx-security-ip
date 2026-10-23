import pytest

from chxchx_security.services.network_plan import (
    NetworkPlanError,
    build_network_plan,
    interface_names,
)


def test_interface_names_are_safe_and_fit_linux_limits():
    host, namespace = interface_names("demo-session")

    assert len(host) <= 15
    assert len(namespace) <= 15
    assert host != namespace
    assert "demo-session" not in host


def test_network_plan_contains_veth_and_rollback_steps():
    plan = build_network_plan("demo", subnet="10.203.0.0/30")

    assert plan.executable is False
    assert plan.host_address == "10.203.0.1/30"
    assert plan.namespace_address == "10.203.0.2/30"
    assert plan.trans_port == 9040
    assert plan.dns_port == 5300
    assert plan.steps[0].name == "create veth pair"
    assert plan.steps[-1].status == "rollback"


@pytest.mark.parametrize("subnet", ["192.168.1.0/24", "8.8.8.0/30", "not-a-network"])
def test_network_plan_rejects_unsafe_subnets(subnet):
    with pytest.raises(NetworkPlanError):
        build_network_plan("demo", subnet=subnet)
