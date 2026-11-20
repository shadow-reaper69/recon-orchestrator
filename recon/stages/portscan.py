"""Stage 3: Port and service scanning using Nmap."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Tuple

from recon.config import ReconConfig
from recon.parsers.nmap_parser import HostPorts, parse_nmap_xml
from recon.runner import SafeRunner
from recon.scope import Scope, validate_target

logger = logging.getLogger("recon.stages.portscan")


def run_portscan_stage(
    config: ReconConfig,
    scope: Scope,
    runner: SafeRunner,
    raw_dir: Path,
    targets: List[str],
) -> Tuple[str, List[HostPorts]]:
    """Execute Nmap with conservative parameters (-sV, -T3, top ports) on in-scope hosts.

    Returns:
        Tuple of (status_message, list_of_host_ports)
    """
    if "nmap" in config.skipped_stages:
        logger.info("Stage 'nmap' skipped via configuration.")
        return "skipped (user request)", []

    raw_output = raw_dir / "nmap.xml"

    if config.resume and raw_output.is_file() and raw_output.stat().st_size > 0:
        logger.info("Resuming portscan stage from existing file: %s", raw_output)
        hosts = parse_nmap_xml(raw_output)
        in_scope_hosts = [h for h in hosts if scope.is_in_scope(h.host) or (h.ip and scope.is_in_scope(h.ip))]
        return f"resumed ({len(in_scope_hosts)} hosts scanned)", in_scope_hosts

    tool_info = runner.check_tool("nmap")
    if not tool_info.installed:
        msg = f"Skipping nmap: {tool_info.error_message or 'nmap not installed.'}"
        logger.warning(msg)
        return msg, []

    # Gather candidate hosts from previous stages and scope entries
    candidate_set = set(targets)
    for entry in scope.raw_entries:
        candidate_set.add(entry)

    valid_in_scope_targets: List[str] = []
    for tgt in candidate_set:
        try:
            clean = validate_target(tgt)
            if scope.is_in_scope(clean):
                valid_in_scope_targets.append(clean)
            else:
                logger.debug("Target out of scope, skipped for nmap: %s", clean)
        except ValueError:
            continue

    if not valid_in_scope_targets:
        msg = "No in-scope targets available for Nmap port scan."
        logger.info(msg)
        return msg, []

    input_file = raw_dir / "nmap_targets.txt"
    input_file.write_text("\n".join(valid_in_scope_targets) + "\n", encoding="utf-8")

    # Safe conservative timing flag: enforce <= -T3
    timing = config.scan.nmap_timing
    if timing not in ("-T0", "-T1", "-T2", "-T3"):
        logger.warning("Nmap timing %s is aggressive; resetting to safe default -T3.", timing)
        timing = "-T3"

    cmd = [
        str(tool_info.path or "nmap"),
        "-sV",
        timing,
        "--top-ports",
        str(config.scan.nmap_top_ports),
        "-oX",
        str(raw_output),
        "-iL",
        str(input_file),
    ]

    logger.info(
        "Starting Nmap port scan against %d host(s) (top %d ports, %s)...",
        len(valid_in_scope_targets),
        config.scan.nmap_top_ports,
        timing,
    )
    result = runner.run(cmd, timeout=config.timeouts.nmap)

    if result.timed_out:
        msg = f"Nmap timed out after {config.timeouts.nmap}s."
        logger.warning(msg)
        return msg, []

    if not raw_output.is_file() or raw_output.stat().st_size == 0:
        if result.returncode != 0:
            msg = f"Nmap exited with code {result.returncode}: {result.stderr.strip()}"
            logger.warning(msg)
            return msg, []
        msg = "Nmap completed with no XML output generated."
        logger.info(msg)
        return msg, []

    hosts_result = parse_nmap_xml(raw_output)
    in_scope_results = [
        h for h in hosts_result
        if scope.is_in_scope(h.host) or (h.ip and scope.is_in_scope(h.ip))
    ]

    total_ports = sum(len(h.ports) for h in in_scope_results)
    logger.info("Nmap discovered %d open port(s) across %d host(s).", total_ports, len(in_scope_results))
    return f"completed ({total_ports} open ports on {len(in_scope_results)} hosts)", in_scope_results
