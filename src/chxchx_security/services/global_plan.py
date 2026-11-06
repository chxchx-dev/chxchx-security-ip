from __future__ import annotations

from dataclasses import dataclass

NAT_TABLE = "chxsec_global_nat"
FILTER_TABLE = "chxsec_global_filter"
DROPIN_PATH = "/etc/tor/torrc.d/chxsec-global.conf"

PRIVATE_IPV4 = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
)


class GlobalPlanError(ValueError):
    """Raised when a whole-host Tor plan would be unsafe or invalid."""


def _port(value: int, name: str) -> int:
    if not 1 <= value <= 65535:
        raise GlobalPlanError(f"{name} must be between 1 and 65535")
    return value


@dataclass(frozen=True)
class GlobalPlan:
    trans_port: int
    dns_port: int
    tor_uid: int
    allow_lan: bool
    nat_table: str
    filter_table: str
    dropin_path: str
    ruleset: str
    torrc: str
    executable: bool
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "trans_port": self.trans_port,
            "dns_port": self.dns_port,
            "tor_uid": self.tor_uid,
            "allow_lan": self.allow_lan,
            "nat_table": self.nat_table,
            "filter_table": self.filter_table,
            "dropin_path": self.dropin_path,
            "ruleset": self.ruleset,
            "torrc": self.torrc,
            "executable": self.executable,
            "reason": self.reason,
        }


def _lan_nat_rule(allow_lan: bool) -> str:
    if not allow_lan:
        return ""
    addresses = ", ".join(PRIVATE_IPV4)
    return f"        ip daddr {{ {addresses} }} return\n"


def _lan_filter_rule(allow_lan: bool) -> str:
    if not allow_lan:
        return ""
    addresses = ", ".join(PRIVATE_IPV4)
    return f"        ip daddr {{ {addresses} }} accept\n"


def _ruleset(
    *,
    trans_port: int,
    dns_port: int,
    tor_uid: int,
    allow_lan: bool,
) -> str:
    return f'''table ip {NAT_TABLE} {{
    chain output {{
        type nat hook output priority -100; policy accept;
        # Never redirect loopback or Tor's own traffic back into Tor.
        oifname "lo" return
        ip daddr 127.0.0.0/8 return
        meta skuid {tor_uid} return
{_lan_nat_rule(allow_lan)}        meta l4proto tcp redirect to :{trans_port}
        udp dport 53 redirect to :{dns_port}
    }}
}}

table inet {FILTER_TABLE} {{
    chain output {{
        type filter hook output priority 0; policy accept;
        # Local traffic and Tor itself are the only allowed direct paths.
        oifname "lo" accept
        ip daddr 127.0.0.0/8 accept
        ip6 daddr ::1 accept
        meta skuid {tor_uid} accept
        # Keep DHCPv4 alive so the host can renew its lease.
        udp sport 68 udp dport 67 accept
        udp sport 67 udp dport 68 accept
{_lan_filter_rule(allow_lan)}        # Tor cannot carry UDP or ICMP; dropping is fail-closed.
        meta l4proto udp counter drop
        meta l4proto tcp counter drop
        meta l4proto icmp counter drop
        meta l4proto ipv6-icmp counter drop
        counter drop
    }}
}}
'''


def _torrc(trans_port: int, dns_port: int) -> str:
    return (
        "# Managed by chxsec global mode; remove with `chxsec global stop`\n"
        f"TransPort 127.0.0.1:{trans_port}\n"
        f"DNSPort 127.0.0.1:{dns_port}\n"
        "AutomapHostsOnResolve 1\n"
        "VirtualAddrNetworkIPv4 10.192.0.0/10\n"
    )


def build_global_plan(
    *,
    trans_port: int = 9040,
    dns_port: int = 5300,
    tor_uid: int,
    allow_lan: bool = False,
) -> GlobalPlan:
    trans_port = _port(trans_port, "TransPort")
    dns_port = _port(dns_port, "DNSPort")
    if trans_port == dns_port:
        raise GlobalPlanError("TransPort and DNSPort must use different ports")
    if tor_uid <= 0:
        raise GlobalPlanError(
            "Tor must run as a non-root user for whole-host routing; "
            "the redirect loop would be impossible to separate safely"
        )
    return GlobalPlan(
        trans_port=trans_port,
        dns_port=dns_port,
        tor_uid=tor_uid,
        allow_lan=allow_lan,
        nat_table=NAT_TABLE,
        filter_table=FILTER_TABLE,
        dropin_path=DROPIN_PATH,
        ruleset=_ruleset(
            trans_port=trans_port,
            dns_port=dns_port,
            tor_uid=tor_uid,
            allow_lan=allow_lan,
        ),
        torrc=_torrc(trans_port, dns_port),
        executable=False,
        reason="plan is rendered only; Tor, nftables and the host network are not changed",
    )
