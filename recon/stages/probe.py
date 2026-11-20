"""Stage 2: HTTP probing using ProjectDiscovery httpx."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Tuple

from recon.config import ReconConfig
from recon.parsers.httpx_parser import HttpService, parse_httpx_jsonl
from recon.runner import SafeRunner
from recon.scope import Scope, validate_target

logger = logging.getLogger("recon.stages.probe")


def run_probe_stage(
    config: ReconConfig,
    scope: Scope,
    runner: SafeRunner,
    raw_dir: Path,
    targets: List[str],
) -> Tuple[str, List[HttpService]]:
    """Execute httpx on in-scope discovered hosts and networks.

    Returns:
        Tuple of (status_message, list_of_discovered_http_services)
    """
    if "httpx" in config.skipped_stages:
        logger.info("Stage 'httpx' skipped via configuration.")
        return "skipped (user request)", []

    raw_output = raw_dir / "httpx.jsonl"

    if config.resume and raw_output.is_file() and raw_output.stat().st_size > 0:
        logger.info("Resuming probe stage from existing file: %s", raw_output)
        services = parse_httpx_jsonl(raw_output)
        in_scope_services = [s for s in services if scope.is_in_scope(s.host)]
        return f"resumed ({len(in_scope_services)} live HTTP services)", in_scope_services

    tool_info = runner.check_tool("httpx")
    if not tool_info.installed or not tool_info.vendor_verified:
        msg = f"Skipping httpx: {tool_info.error_message or 'httpx (ProjectDiscovery) not installed.'}"
        logger.warning(msg)
        return msg, []

    # Combine targets and initial scope hosts, strictly filtering by scope
    candidate_targets = set(targets)
    for entry in scope.raw_entries:
        if "/" not in entry:
            candidate_targets.add(entry)

    valid_in_scope_targets: List[str] = []
    for tgt in candidate_targets:
        try:
            clean = validate_target(tgt)
            if scope.is_in_scope(clean):
                valid_in_scope_targets.append(clean)
            else:
                logger.debug("Target out of scope, skipped for httpx: %s", clean)
        except ValueError:
            continue

    if not valid_in_scope_targets:
        msg = "No in-scope targets available for HTTP probing."
        logger.info(msg)
        return msg, []

    input_file = raw_dir / "httpx_input.txt"
    input_file.write_text("\n".join(valid_in_scope_targets) + "\n", encoding="utf-8")

    # Confirmed ProjectDiscovery httpx flags
    cmd = [
        str(tool_info.path or "httpx"),
        "-l",
        str(input_file),
        "-status-code",
        "-title",
        "-tech-detect",
        "-follow-redirects",
        "-json",
        "-o",
        str(raw_output),
        "-rate-limit",
        str(config.scan.rate_limit),
        "-timeout",
        str(max(5, config.timeouts.httpx // 10)),
        "-silent",
    ]

    logger.info("Starting httpx HTTP probe against %d target(s)...", len(valid_in_scope_targets))
    result = runner.run(cmd, timeout=config.timeouts.httpx)

    if result.timed_out:
        msg = f"httpx timed out after {config.timeouts.httpx}s."
        logger.warning(msg)
        return msg, []

    if not raw_output.is_file() or raw_output.stat().st_size == 0:
        if result.returncode != 0:
            msg = f"httpx exited with code {result.returncode}: {result.stderr.strip()}"
            logger.warning(msg)
            return msg, []
        msg = "httpx found no active HTTP services."
        logger.info(msg)
        return msg, []

    parsed_services = parse_httpx_jsonl(raw_output)
    in_scope_services = [s for s in parsed_services if scope.is_in_scope(s.host)]
    logger.info(
        "httpx probed %d services (%d in-scope live services).",
        len(parsed_services),
        len(in_scope_services),
    )
    return f"completed ({len(in_scope_services)} live HTTP services probed)", in_scope_services
