"""Configuration dataclasses and loaders for the reconnaissance pipeline."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ToolTimeouts:
    """Per-tool timeout configuration in seconds."""

    subfinder: int = 180
    httpx: int = 120
    nmap: int = 300
    nuclei: int = 300


@dataclass
class ScanDefaults:
    """Conservative defaults for network and scanner activity."""

    # Concurrency and rate limits
    rate_limit: int = 25  # Requests per second (conservative)
    threads: int = 10     # Thread pool limit
    
    # Nmap safety limits
    nmap_timing: str = "-T3"  # -T3 (normal) or lower (-T2 / -T1). Higher than T3 is discouraged.
    nmap_top_ports: int = 100  # Default to top 100 ports instead of all 65535
    
    # Nuclei non-intrusive safety restrictions
    nuclei_severities: List[str] = field(
        default_factory=lambda: ["info", "low", "medium", "high", "critical"]
    )
    nuclei_exclude_tags: List[str] = field(
        default_factory=lambda: ["intrusive", "dos", "fuzz"]
    )


@dataclass
class ReconConfig:
    """Master configuration for a pipeline execution."""

    scope_file: Path
    authorized: bool = False
    output_dir: Path = field(default_factory=lambda: Path("runs"))
    skipped_stages: List[str] = field(default_factory=list)
    resume: bool = False
    verbose: bool = False
    
    timeouts: ToolTimeouts = field(default_factory=ToolTimeouts)
    scan: ScanDefaults = field(default_factory=ScanDefaults)

    @classmethod
    def from_dict(cls, data: Dict[str, Any], scope_file: Path, authorized: bool) -> ReconConfig:
        """Create config from dictionary and explicit CLI flags."""
        timeouts_data = data.get("timeouts", {})
        scan_data = data.get("scan", {})

        return cls(
            scope_file=scope_file,
            authorized=authorized,
            output_dir=Path(data.get("output_dir", "runs")),
            skipped_stages=data.get("skip", []),
            resume=data.get("resume", False),
            verbose=data.get("verbose", False),
            timeouts=ToolTimeouts(
                subfinder=timeouts_data.get("subfinder", 180),
                httpx=timeouts_data.get("httpx", 120),
                nmap=timeouts_data.get("nmap", 300),
                nuclei=timeouts_data.get("nuclei", 300),
            ),
            scan=ScanDefaults(
                rate_limit=scan_data.get("rate_limit", 25),
                threads=scan_data.get("threads", 10),
                nmap_timing=scan_data.get("nmap_timing", "-T3"),
                nmap_top_ports=scan_data.get("nmap_top_ports", 100),
                nuclei_severities=scan_data.get(
                    "nuclei_severities", ["info", "low", "medium", "high", "critical"]
                ),
                nuclei_exclude_tags=scan_data.get(
                    "nuclei_exclude_tags", ["intrusive", "dos", "fuzz"]
                ),
            ),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize configuration to a dictionary."""
        d = asdict(self)
        d["scope_file"] = str(self.scope_file)
        d["output_dir"] = str(self.output_dir)
        return d
