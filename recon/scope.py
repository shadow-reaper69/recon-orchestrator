"""Scope parsing and target validation module for safe reconnaissance.

Enforces strict boundary checking against domain hierarchies and CIDR blocks.
Validates target syntax to prevent command/flag injection.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set, Union


# Strict regex for domain names / hostnames according to RFC 1123
_DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.?$"
)

# Reject any string starting with hyphen or containing dangerous metacharacters
_DANGEROUS_CHARS = re.compile(r"[\s;\|\&\$\`\<\>\(\)\"\'\\*?!\x00-\x1f]")


def validate_target(target: str) -> str:
    """Validate that a target string is a safe, well-formed domain, IP, or CIDR.

    Rejects strings containing whitespace, control characters, shell metacharacters,
    or leading hyphens (which could be parsed as command-line flags).

    Args:
        target: The target string to validate.

    Returns:
        The validated target string stripped of whitespace.

    Raises:
        ValueError: If the target is malformed or contains prohibited characters.
    """
    if not target or not isinstance(target, str):
        raise ValueError("Target must be a non-empty string.")

    cleaned = target.strip()
    if not cleaned:
        raise ValueError("Target cannot be blank.")

    if cleaned.startswith("-"):
        raise ValueError(f"Target '{cleaned}' rejected: Cannot start with a hyphen (flag injection protection).")

    if _DANGEROUS_CHARS.search(cleaned):
        raise ValueError(f"Target '{cleaned}' rejected: Contains illegal metacharacters or whitespace.")

    # Check if target is a CIDR network
    if "/" in cleaned:
        try:
            ipaddress.ip_network(cleaned, strict=False)
            return cleaned
        except ValueError as err:
            raise ValueError(f"Target '{cleaned}' is not a valid CIDR network: {err}") from err

    # Check if target is a single IP address
    try:
        ipaddress.ip_address(cleaned)
        return cleaned
    except ValueError:
        pass

    # Check if target is a valid domain name
    if _DOMAIN_REGEX.match(cleaned):
        return cleaned.lower()

    raise ValueError(f"Target '{cleaned}' is neither a valid IP address, CIDR, nor domain name.")


@dataclass
class Scope:
    """Represents an approved assessment scope with domain and network allowlists."""

    domains: Set[str] = field(default_factory=set)
    networks: List[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = field(default_factory=list)
    raw_entries: List[str] = field(default_factory=list)

    @classmethod
    def from_file(cls, scope_path: Union[str, Path]) -> Scope:
        """Parse a scope file containing one domain, IP, or CIDR per line.

        Ignores blank lines and comments starting with '#'.
        """
        path = Path(scope_path)
        if not path.is_file():
            raise FileNotFoundError(f"Scope file not found: {scope_path}")

        scope = cls()
        with path.open("r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    validated = validate_target(line)
                except ValueError as exc:
                    raise ValueError(f"Invalid scope entry on line {line_no} in {scope_path}: {exc}") from exc

                scope.raw_entries.append(validated)

                if "/" in validated:
                    scope.networks.append(ipaddress.ip_network(validated, strict=False))
                else:
                    try:
                        ip_obj = ipaddress.ip_address(validated)
                        # Treat single IP as /32 or /128 network for uniform containment check
                        prefix = 32 if ip_obj.version == 4 else 128
                        scope.networks.append(ipaddress.ip_network(f"{validated}/{prefix}"))
                    except ValueError:
                        # Domain
                        scope.domains.add(validated.lower())

        if not scope.domains and not scope.networks:
            raise ValueError(f"Scope file {scope_path} contains no valid domains, IPs, or CIDRs.")

        return scope

    def is_in_scope(self, target: str) -> bool:
        """Check whether a given target (domain, hostname, or IP) falls within scope.

        - A domain matches if it equals an in-scope domain or is a subdomain of it.
        - An IP matches if it falls inside any in-scope CIDR network.

        Args:
            target: The candidate domain, subdomain, or IP.

        Returns:
            True if in-scope, False otherwise.
        """
        try:
            validated = validate_target(target)
        except ValueError:
            return False

        # If it's an IP, test network containment
        try:
            ip_obj = ipaddress.ip_address(validated)
            return any(ip_obj in net for net in self.networks)
        except ValueError:
            pass

        # It is a domain/hostname
        candidate = validated.lower()

        # Direct domain match
        if candidate in self.domains:
            return True

        # Subdomain match: candidate ends with '.<in_scope_domain>'
        for allowed_domain in self.domains:
            if candidate.endswith(f".{allowed_domain}"):
                return True

        return False
