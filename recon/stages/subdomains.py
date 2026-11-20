"""Stage 1: Subdomain discovery using Subfinder."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Tuple

from recon.config import ReconConfig
from recon.parsers.subfinder_parser import parse_subfinder_output
from recon.runner import SafeRunner
from recon.scope import Scope, validate_target

logger = logging.getLogger("recon.stages.subdomains")


def run_subdomains_stage(
    config: ReconConfig,
    scope: Scope,
    runner: SafeRunner,
    raw_dir: Path,
) -> Tuple[str, List[str]]:
    """Execute Subfinder against in-scope root domains.

    Returns:
        Tuple of (status_message, list_of_in_scope_discovered_subdomains)
    """
    if "subfinder" in config.skipped_stages:
        logger.info("Stage 'subfinder' skipped via configuration.")
        return "skipped (user request)", []

    raw_output = raw_dir / "subfinder.txt"

    # Resume handling
    if config.resume and raw_output.is_file() and raw_output.stat().st_size > 0:
        logger.info("Resuming subdomains stage from existing file: %s", raw_output)
        all_hosts = parse_subfinder_output(raw_output)
        in_scope_hosts = [h for h in all_hosts if scope.is_in_scope(h)]
        return f"resumed ({len(in_scope_hosts)} in-scope hosts)", in_scope_hosts

    tool_info = runner.check_tool("subfinder")
    if not tool_info.installed:
        msg = f"Skipping subfinder: {tool_info.error_message or 'subfinder not installed.'}"
        logger.warning(msg)
        return msg, []

    # Filter domains from scope that are eligible for subfinder
    root_domains: List[str] = []
    for entry in scope.domains:
        try:
            val = validate_target(entry)
            root_domains.append(val)
        except ValueError:
            continue

    if not root_domains:
        msg = "No root domains found in scope for subfinder to query."
        logger.info(msg)
        return msg, []

    # Write root domains to input file
    domains_file = raw_dir / "subfinder_input.txt"
    domains_file.write_text("\n".join(root_domains) + "\n", encoding="utf-8")

    cmd = [
        str(tool_info.path or "subfinder"),
        "-dL",
        str(domains_file),
        "-o",
        str(raw_output),
        "-silent",
    ]

    logger.info("Starting Subfinder on %d in-scope root domain(s)...", len(root_domains))
    result = runner.run(cmd, timeout=config.timeouts.subfinder)

    if result.timed_out:
        msg = f"Subfinder timed out after {config.timeouts.subfinder}s."
        logger.warning(msg)
        return msg, []

    if not raw_output.is_file() or raw_output.stat().st_size == 0:
        if result.returncode != 0:
            msg = f"Subfinder exited with return code {result.returncode}: {result.stderr.strip()}"
            logger.warning(msg)
            return msg, []
        msg = "Subfinder produced no output."
        logger.info(msg)
        return msg, []

    # Parse and enforce scope verification
    all_hosts = parse_subfinder_output(raw_output)
    in_scope_hosts: List[str] = []
    for host in all_hosts:
        if scope.is_in_scope(host):
            in_scope_hosts.append(host)
        else:
            logger.debug("Subdomain out-of-scope, skipped: %s", host)

    logger.info("Subfinder discovered %d total hosts, %d in-scope.", len(all_hosts), len(in_scope_hosts))
    return f"completed ({len(in_scope_hosts)} in-scope hosts discovered)", in_scope_hosts
