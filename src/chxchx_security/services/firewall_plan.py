from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from chxchx_security.services.network_plan import build_network_plan, interface_names
from chxchx_security.services.tor_ports import build_tor_port_plan


@dataclass(frozen=True)
class FirewallPlan:
    session_id: str
    namespace: str
    host_interface: str
    namespace_address: str
    host_address: str
    trans_port: int
    dns_port: int
    filter_table: str
    nat_table: str
    executable: bool
    reason: str
    ruleset: str

    def as_dict(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "namespace": self.namespace,
            "host_interface": self.host_interface,
            "namespace_address": self.namespace_address,
            "host_address": self.host_address,
            "trans_port": self.trans_port,
            "dns_port": self.dns_port,
            "filter_table": self.filter_table,
            "nat_table": self.nat_table,
            "executable": self.executable,
            "reason": self.reason,
            "ruleset": self.ruleset,
        }


def _table_suffix(interface: str) -> str:
    return interface.removeprefix("chxh-")


def table_names(session_id: str) -> tuple[str, str]:
    suffix = _table_suffix(interface_names(session_id)[0])
    return f"chxsec_{suffix}", f"chxsec_nat_{suffix}"


def _ruleset(
    *,
    filter_table: str,
    nat_table: str,
    host_interface: str,
    host_ip: str,
    namespace_address: str,
    trans_port: int,
    dns_port: int,
) -> str:
    return f'''table inet {filter_table} {{
    chain input {{
        type filter hook input priority -10; policy accept;
        ip daddr {host_ip} iifname != "{host_interface}" drop
        iifname "{host_interface}" ip saddr {namespace_address} tcp dport {trans_port} accept
        iifname "{host_interface}" ip saddr {namespace_address} udp dport {dns_port} accept
        iifname "{host_interface}" drop
    }}

    chain forward {{
        type filter hook forward priority -10; policy accept;
        iifname "{host_interface}" counter drop
        oifname "{host_interface}" counter drop
    }}

    chain output {{
        type filter hook output priority -10; policy accept;
        oifname "{host_interface}" ip daddr {namespace_address} accept
    }}
}}

table ip {nat_table} {{
    chain prerouting {{
        type nat hook prerouting priority -100; policy accept;
        iifname "{host_interface}" ip saddr {namespace_address} meta l4proto tcp redirect to :{trans_port}
        iifname "{host_interface}" ip saddr {namespace_address} udp dport 53 redirect to :{dns_port}
    }}
}}
'''


def build_firewall_plan(
    session_id: str,
    *,
    subnet: str,
    trans_port: int = 9040,
    dns_port: int = 5300,
) -> FirewallPlan:
    network = build_network_plan(
        session_id,
        subnet=subnet,
        trans_port=trans_port,
        dns_port=dns_port,
    )
    tor = build_tor_port_plan(
        str(ipaddress.ip_interface(network.host_address).ip),
        trans_port=network.trans_port,
        dns_port=network.dns_port,
    )
    filter_table, nat_table = table_names(session_id)
    ruleset = _ruleset(
        filter_table=filter_table,
        nat_table=nat_table,
        host_interface=network.host_interface,
        host_ip=network.host_address.split("/", 1)[0],
        namespace_address=network.namespace_address.split("/", 1)[0],
        trans_port=tor.trans_port,
        dns_port=tor.dns_port,
    )
    return FirewallPlan(
        session_id=network.session_id,
        namespace=network.namespace,
        host_interface=network.host_interface,
        namespace_address=network.namespace_address,
        host_address=network.host_address,
        trans_port=tor.trans_port,
        dns_port=tor.dns_port,
        filter_table=filter_table,
        nat_table=nat_table,
        executable=False,
        reason="ruleset is rendered only; nftables state is not changed",
        ruleset=ruleset,
    )
