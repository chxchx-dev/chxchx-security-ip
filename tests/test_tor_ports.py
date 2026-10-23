import pytest

from chxchx_security.services.tor_ports import (
    TorPortPlanError,
    build_tor_port_plan,
)


def test_tor_port_plan_renders_private_listeners_without_executing():
    plan = build_tor_port_plan("10.203.0.1")

    assert plan.executable is False
    assert plan.directives == (
        "TransPort 10.203.0.1:9040",
        "DNSPort 10.203.0.1:5300",
    )
    assert plan.render() == "TransPort 10.203.0.1:9040\nDNSPort 10.203.0.1:5300\n"


@pytest.mark.parametrize("address", ["0.0.0.0", "127.0.0.1", "8.8.8.8", "::1"])
def test_tor_port_plan_rejects_unsafe_bind_addresses(address):
    with pytest.raises(TorPortPlanError):
        build_tor_port_plan(address)


def test_tor_port_plan_rejects_duplicate_or_invalid_ports():
    with pytest.raises(TorPortPlanError):
        build_tor_port_plan("10.203.0.1", trans_port=9040, dns_port=9040)
    with pytest.raises(TorPortPlanError):
        build_tor_port_plan("10.203.0.1", trans_port=0)
