from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass

from chxchx_security.services.session import namespace_name, validate_session_id


class NetworkPlanError(ValueError):
    """Raised when a namespace network plan is unsafe or invalid."""


def _port(value: int, name: str) -> int:
    if not 1 <= value <= 65535:
        raise NetworkPlanError(f"{name} must be between 1 and 65535")
    return value


def _subnet(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise NetworkPlanError("subnet must be a valid IPv4 network") from exc
    if not isinstance(network, ipaddress.IPv4Network) or network.prefixlen != 30:
        raise NetworkPlanError("subnet must be a private IPv4 /30 network")
    if not network.is_private:
        raise NetworkPlanError("subnet must be private")
    return network


def interface_names(session_id: str) -> tuple[str, str]:
    validate_session_id(session_id)
    digest = hashlib.sha256(session_id.encode("ascii")).hexdigest()[:8]
    return f"chxh-{digest}", f"chxn-{digest}"


@dataclass(frozen=True)
class NetworkStep:
    name: str
    command: tuple[str, ...] | None
    status: str

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "command": list(self.command) if self.command else None,
            "status": self.status,
        }


@dataclass(frozen=True)
class NetworkPlan:
    session_id: str
    namespace: str
    subnet: str
    host_address: str
    namespace_address: str
    host_interface: str
    namespace_interface: str
    trans_port: int
    dns_port: int
    executable: bool
    reason: str
    steps: tuple[NetworkStep, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "session_id": self.session_id,
            "namespace": self.namespace,
            "subnet": self.subnet,
            "host_address": self.host_address,
            "namespace_address": self.namespace_address,
            "host_interface": self.host_interface,
            "namespace_interface": self.namespace_interface,
            "trans_port": self.trans_port,
            "dns_port": self.dns_port,
            "executable": self.executable,
            "reason": self.reason,
            "steps": [step.as_dict() for step in self.steps],
        }


def build_network_plan(
    session_id: str,
    *,
    subnet: str,
    trans_port: int = 9040,
    dns_port: int = 5300,
) -> NetworkPlan:
    validate_session_id(session_id)
    network = _subnet(subnet)
    trans_port = _port(trans_port, "TransPort")
    dns_port = _port(dns_port, "DNSPort")
    host_ip, namespace_ip = list(network.hosts())
    prefix_length = network.prefixlen
    host_interface, namespace_interface = interface_names(session_id)
    namespace = namespace_name(session_id)
    prefix = ("sudo",)

    steps = (
        NetworkStep(
            "create veth pair",
            (
                *prefix,
                "ip",
                "link",
                "add",
                host_interface,
                "type",
                "veth",
                "peer",
                "name",
                namespace_interface,
            ),
            "planned",
        ),
        NetworkStep(
            "move namespace interface",
            (*prefix, "ip", "link", "set", namespace_interface, "netns", namespace),
            "planned",
        ),
        NetworkStep(
            "assign host gateway",
            (
                *prefix,
                "ip",
                "addr",
                "add",
                f"{host_ip}/{prefix_length}",
                "dev",
                host_interface,
            ),
            "planned",
        ),
        NetworkStep(
            "assign namespace address",
            (
                *prefix,
                "ip",
                "netns",
                "exec",
                namespace,
                "ip",
                "addr",
                "add",
                f"{namespace_ip}/{prefix_length}",
                "dev",
                namespace_interface,
            ),
            "planned",
        ),
        NetworkStep(
            "bring up host interface",
            (*prefix, "ip", "link", "set", host_interface, "up"),
            "planned",
        ),
        NetworkStep(
            "bring up namespace interface",
            (
                *prefix,
                "ip",
                "netns",
                "exec",
                namespace,
                "ip",
                "link",
                "set",
                namespace_interface,
                "up",
            ),
            "planned",
        ),
        NetworkStep(
            "route namespace traffic through Tor",
            None,
            "blocked_until_tor_ports",
        ),
        NetworkStep(
            "install namespace-scoped nftables",
            None,
            "blocked_until_firewall",
        ),
        NetworkStep(
            "rollback veth pair",
            (*prefix, "ip", "link", "delete", host_interface),
            "rollback",
        ),
    )
    return NetworkPlan(
        session_id=session_id,
        namespace=namespace,
        subnet=str(network),
        host_address=f"{host_ip}/30",
        namespace_address=f"{namespace_ip}/30",
        host_interface=host_interface,
        namespace_interface=namespace_interface,
        trans_port=trans_port,
        dns_port=dns_port,
        executable=False,
        reason="Tor TransPort/DNSPort wiring and fail-closed nftables are not implemented",
        steps=steps,
    )
