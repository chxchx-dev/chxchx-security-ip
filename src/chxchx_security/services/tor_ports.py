from __future__ import annotations

import ipaddress
from dataclasses import dataclass


class TorPortPlanError(ValueError):
    """Raised when a Tor listener plan would be unsafe or invalid."""


def _port(value: int, name: str) -> int:
    if not 1 <= value <= 65535:
        raise TorPortPlanError(f"{name} must be between 1 and 65535")
    return value


def _bind_address(value: str) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise TorPortPlanError("bind address must be a valid IPv4 address") from exc
    if not isinstance(address, ipaddress.IPv4Address):
        raise TorPortPlanError("bind address must be an IPv4 address")
    if address.is_unspecified or address.is_loopback:
        raise TorPortPlanError("bind address must not be wildcard or loopback")
    if address.is_link_local or not address.is_private:
        raise TorPortPlanError("bind address must be a private IPv4 address")
    return address


@dataclass(frozen=True)
class TorPortPlan:
    bind_address: str
    trans_port: int
    dns_port: int
    executable: bool
    reason: str

    @property
    def directives(self) -> tuple[str, ...]:
        return (
            f"TransPort {self.bind_address}:{self.trans_port}",
            f"DNSPort {self.bind_address}:{self.dns_port}",
        )

    def render(self) -> str:
        return "\n".join(self.directives) + "\n"

    def as_dict(self) -> dict[str, object]:
        return {
            "bind_address": self.bind_address,
            "trans_port": self.trans_port,
            "dns_port": self.dns_port,
            "directives": list(self.directives),
            "executable": self.executable,
            "reason": self.reason,
        }


def build_tor_port_plan(
    bind_address: str,
    *,
    trans_port: int = 9040,
    dns_port: int = 5300,
) -> TorPortPlan:
    address = _bind_address(bind_address)
    trans_port = _port(trans_port, "TransPort")
    dns_port = _port(dns_port, "DNSPort")
    if trans_port == dns_port:
        raise TorPortPlanError("TransPort and DNSPort must use different ports")
    return TorPortPlan(
        bind_address=str(address),
        trans_port=trans_port,
        dns_port=dns_port,
        executable=False,
        reason="configuration is rendered only; Tor config and service state are not modified",
    )
