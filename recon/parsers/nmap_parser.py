"""Parser for Nmap XML output (-oX).

Parses XML safely without external entity expansion, extracting open ports,
services, and detected product/version information.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


@dataclass
class PortFinding:
    """Represents an open network port and associated service fingerprint."""

    port: int
    protocol: str
    state: str
    service: str
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
        }


@dataclass
class HostPorts:
    """Represents a discovered host and its list of open ports."""

    host: str
    ip: Optional[str] = None
    status: str = "up"
    ports: List[PortFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host,
            "ip": self.ip,
            "status": self.status,
            "ports": [p.to_dict() for p in self.ports],
        }


def parse_nmap_xml(content_or_file: Union[str, Path]) -> List[HostPorts]:
    """Parse Nmap XML output safely.

    Extracts hosts where status is 'up' and details of ports where state is 'open'.
    """
    if isinstance(content_or_file, Path) or (
        isinstance(content_or_file, str) and Path(content_or_file).is_file()
    ):
        raw_xml = Path(content_or_file).read_text(encoding="utf-8")
    else:
        raw_xml = str(content_or_file)

    if not raw_xml.strip():
        return []

    try:
        # Safe XML parsing with standard library (no network / no DTD resolution)
        root = ET.fromstring(raw_xml)
    except ET.ParseError:
        return []

    hosts_result: List[HostPorts] = []

    for host_node in root.findall("host"):
        status_node = host_node.find("status")
        if status_node is not None and status_node.attrib.get("state") != "up":
            continue

        # Extract address
        ip_addr: Optional[str] = None
        for addr_node in host_node.findall("address"):
            if addr_node.attrib.get("addrtype") in ("ipv4", "ipv6"):
                ip_addr = addr_node.attrib.get("addr")
                break

        # Extract hostname
        host_name: Optional[str] = None
        hostnames_node = host_node.find("hostnames")
        if hostnames_node is not None:
            for hn in hostnames_node.findall("hostname"):
                host_name = hn.attrib.get("name")
                if host_name:
                    break

        identifier = host_name or ip_addr or "unknown-host"
        open_ports: List[PortFinding] = []

        ports_node = host_node.find("ports")
        if ports_node is not None:
            for port_elem in ports_node.findall("port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.attrib.get("state") != "open":
                    continue

                port_id = int(port_elem.attrib.get("portid", 0))
                proto = port_elem.attrib.get("protocol", "tcp")

                service_elem = port_elem.find("service")
                service_name = "unknown"
                product = None
                version = None
                extra_info = None

                if service_elem is not None:
                    service_name = service_elem.attrib.get("name", "unknown")
                    product = service_elem.attrib.get("product")
                    version = service_elem.attrib.get("version")
                    extra_info = service_elem.attrib.get("extrainfo")

                open_ports.append(
                    PortFinding(
                        port=port_id,
                        protocol=proto,
                        state="open",
                        service=service_name,
                        product=product,
                        version=version,
                        extra_info=extra_info,
                    )
                )

        if open_ports or ip_addr:
            hosts_result.append(
                HostPorts(
                    host=identifier,
                    ip=ip_addr,
                    status="up",
                    ports=open_ports,
                )
            )

    return hosts_result
