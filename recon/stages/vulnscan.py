"""Stage 4: Template-based exposure checks using ProjectDiscovery Nuclei."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Tuple

from recon.config import ReconConfig
from recon.parsers.nuclei_parser import NucleiFinding, parse_nuclei_jsonl
from recon.runner import SafeRunner
from recon.scope import Scope, validate_target

logger = logging.getLogger("recon.stages.vulnscan")


def run_vulnscan_stage(
    config: ReconConfig,
    scope: Scope,
    runner: SafeRunner,
    raw_dir: Path,
    target_urls: List[str],
) -> Tuple[str, List[NucleiFinding]]:
    """Execute Nuclei with strictly non-intrusive settings.

    Restrictions enforced:
    - Excludes 'intrusive', 'dos', 'fuzz' tags.
    - Limits to configured severities.
    - Low rate limit and strict timeouts.
    - All targets verified against scope before execution.

    Returns:
        Tuple of (status_message, list_of_unverified_findings)
    """
    if "nuclei" in config.skipped_stages:
        logger.info("Stage 'nuclei' skipped via configuration.")
        return "skipped (user request)", []

    raw_output = raw_dir / "nuclei.jsonl"

    if config.resume and raw_output.is_file() and raw_output.stat().st_size > 0:
        logger.info("Resuming vulnscan stage from existing file: %s", raw_output)
        findings = parse_nuclei_jsonl(raw_output)
        in_scope_findings = [f for f in findings if scope.is_in_scope(f.host)]
        return f"resumed ({len(in_scope_findings)} unverified findings)", in_scope_findings

    tool_info = runner.check_tool("nuclei")
    if not tool_info.installed:
        msg = f"Skipping nuclei: {tool_info.error_message or 'nuclei not installed.'}"
        logger.warning(msg)
        return msg, []

    # Validate URLs and ensure their hostnames are in scope
    valid_urls: List[str] = []
    for raw_url in target_urls:
        if not raw_url or not isinstance(raw_url, str):
            continue
        cleaned = raw_url.strip()
        # Extract host part for scope checking
        host_candidate = cleaned
        if "://" in cleaned:
            host_candidate = cleaned.split("://")[1].split("/")[0].split(":")[0]

        try:
            validated_host = validate_target(host_candidate)
            if scope.is_in_scope(validated_host):
                valid_urls.append(cleaned)
            else:
                logger.debug("Target URL out of scope, skipped for nuclei: %s", cleaned)
        except ValueError:
            continue

    if not valid_urls:
        msg = "No live in-scope HTTP targets available for template checks."
        logger.info(msg)
        return msg, []

    input_file = raw_dir / "nuclei_targets.txt"
    input_file.write_text("\n".join(valid_urls) + "\n", encoding="utf-8")

    severities_str = ",".join(config.scan.nuclei_severities)
    exclude_tags_str = ",".join(config.scan.nuclei_exclude_tags)

    cmd = [
        str(tool_info.path or "nuclei"),
        "-l",
        str(input_file),
        "-severity",
        severities_str,
        "-exclude-tags",
        exclude_tags_str,
        "-jsonl",
        "-o",
        str(raw_output),
        "-rate-limit",
        str(config.scan.rate_limit),
        "-timeout",
        str(max(5, config.timeouts.nuclei // 20)),
        "-silent",
    ]

    logger.info(
        "Starting Nuclei non-intrusive scan against %d URL(s) (severities: %s, excluding tags: %s)...",
        len(valid_urls),
        severities_str,
        exclude_tags_str,
    )
    result = runner.run(cmd, timeout=config.timeouts.nuclei)

    if result.timed_out:
        msg = f"Nuclei timed out after {config.timeouts.nuclei}s."
        logger.warning(msg)
        return msg, []

    if not raw_output.is_file() or raw_output.stat().st_size == 0:
        if result.returncode != 0:
            msg = f"Nuclei exited with code {result.returncode}: {result.stderr.strip()}"
            logger.warning(msg)
            return msg, []
        msg = "Nuclei completed with 0 template matches."
        logger.info(msg)
        return msg, []

    all_findings = parse_nuclei_jsonl(raw_output)
    in_scope_findings = [f for f in all_findings if scope.is_in_scope(f.host)]

    logger.info("Nuclei reported %d finding(s) (%d in-scope).", len(all_findings), len(in_scope_findings))
    return f"completed ({len(in_scope_findings)} tool-reported, unverified findings)", in_scope_findings
