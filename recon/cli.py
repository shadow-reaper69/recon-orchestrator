"""Command-line interface entry point for the Reconnaissance Orchestrator."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from recon.config import ReconConfig, ScanDefaults, ToolTimeouts
from recon.logging_setup import setup_logger
from recon.report import AUTHORISATION_BANNER, ReportGenerator
from recon.runner import SafeRunner, ToolCheckResult
from recon.scope import Scope, validate_target
from recon.stages.portscan import run_portscan_stage
from recon.stages.probe import run_probe_stage
from recon.stages.subdomains import run_subdomains_stage
from recon.stages.vulnscan import run_vulnscan_stage
from recon.ui import (
    print_banner,
    print_step,
    print_summary_card,
    print_tool_table,
)


def build_parser() -> argparse.ArgumentParser:
    """Build command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="recon",
        description=(
            "Automated Reconnaissance Orchestrator (Educational Defensive Prototype).\n"
            "Coordinates Subfinder, httpx, Nmap, and Nuclei on AUTHORISED targets only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--scope",
        "-s",
        type=Path,
        required=True,
        help="Path to scope file containing one domain or CIDR per line.",
    )
    parser.add_argument(
        "--i-have-authorization",
        action="store_true",
        default=False,
        dest="authorized",
        help="Mandatory acknowledgement that you own or have explicit written authorisation to scan targets.",
    )
    parser.add_argument(
        "--output-dir",
        "-o",
        type=Path,
        default=Path("runs"),
        help="Base directory for run artifacts (default: ./runs).",
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help="Specific run directory to resume from or write into (bypasses timestamp folder creation).",
    )
    parser.add_argument(
        "--skip",
        action="append",
        choices=["subfinder", "httpx", "nmap", "nuclei"],
        default=[],
        help="Skip one or more stages (can be specified multiple times, e.g. --skip nmap --skip nuclei).",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        default=False,
        help="Resume execution using existing raw outputs if found in run directory.",
    )
    parser.add_argument(
        "--rate-limit",
        type=int,
        default=25,
        help="Maximum requests per second (conservative default: 25).",
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        default=100,
        help="Number of top ports for Nmap to scan (default: 100).",
    )
    parser.add_argument(
        "--nmap-timing",
        choices=["-T0", "-T1", "-T2", "-T3"],
        default="-T3",
        help="Nmap timing template (default: -T3. Higher than -T3 is prohibited for safety).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose debug logging.",
    )

    return parser


def create_run_directory(base_dir: Path, scope_identifier: str) -> Path:
    """Create timestamped run directory structure."""
    utc_stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    clean_id = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in scope_identifier)
    run_dir = base_dir / f"{clean_id}_{utc_stamp}"

    (run_dir / "raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "parsed").mkdir(parents=True, exist_ok=True)
    (run_dir / "report").mkdir(parents=True, exist_ok=True)

    return run_dir


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # 1. Mandatory Authorization Check
    if not args.authorized:
        sys.stderr.write(
            "\n[!] SAFETY ERROR: Execution halted.\n"
            "    You must explicitly supply the '--i-have-authorization' flag to confirm\n"
            "    that you possess written permission or own all targets in the scope file.\n\n"
        )
        return 1

    # 2. Scope File Validation
    scope_path = Path(args.scope)
    if not scope_path.is_file():
        sys.stderr.write(f"\n[!] ERROR: Scope file not found at '{scope_path}'.\n\n")
        return 1

    try:
        scope = Scope.from_file(scope_path)
    except Exception as exc:
        sys.stderr.write(f"\n[!] ERROR: Failed to parse scope file: {exc}\n\n")
        return 1

    # Print Authorisation & Aesthetic Terminal Banner
    print_banner()

    # 3. Setup Run Directory & Logging
    first_target = scope.raw_entries[0] if scope.raw_entries else "recon"
    if args.run_dir:
        run_dir = Path(args.run_dir)
        (run_dir / "raw").mkdir(parents=True, exist_ok=True)
        (run_dir / "parsed").mkdir(parents=True, exist_ok=True)
        (run_dir / "report").mkdir(parents=True, exist_ok=True)
    else:
        run_dir = create_run_directory(args.output_dir, first_target)
    raw_dir = run_dir / "raw"
    parsed_dir = run_dir / "parsed"
    report_dir = run_dir / "report"
    log_file = run_dir / "run.log"

    logger = setup_logger("recon", log_file=log_file, verbose=args.verbose)
    logger.info("Initializing reconnaissance run in %s", run_dir)
    logger.info("Scope loaded with %d entry/entries: %s", len(scope.raw_entries), ", ".join(scope.raw_entries))

    # 4. Initialize Configuration & Safe Runner
    config = ReconConfig(
        scope_file=scope_path,
        authorized=True,
        output_dir=run_dir,
        skipped_stages=args.skip,
        resume=args.resume,
        verbose=args.verbose,
        timeouts=ToolTimeouts(),
        scan=ScanDefaults(
            rate_limit=args.rate_limit,
            nmap_timing=args.nmap_timing,
            nmap_top_ports=args.top_ports,
        ),
    )
    runner = SafeRunner()

    # Pre-check tool availability
    tool_status: Dict[str, ToolCheckResult] = {}
    for tool_name in ["subfinder", "httpx", "nmap", "nuclei"]:
        status = runner.check_tool(tool_name)
        tool_status[tool_name] = status

    print_tool_table(tool_status)

    stage_status: Dict[str, str] = {}
    discovered_subdomains: List[str] = []
    live_http_services = []
    host_ports = []
    findings = []

    start_time = datetime.now(timezone.utc)

    try:
        # Stage 1: Subdomain discovery (Subfinder)
        print_step(1, "Subdomain Inventory", "Subfinder passive OSINT")
        s1_status, discovered_subdomains = run_subdomains_stage(config, scope, runner, raw_dir)
        stage_status["subfinder"] = s1_status
        (parsed_dir / "subdomains.json").write_text(
            json.dumps(discovered_subdomains, indent=2), encoding="utf-8"
        )

        # Stage 2: HTTP probing (httpx)
        print_step(2, "HTTP Service Probing", "httpx status, title & tech stack")
        # Candidate hosts: discovered subdomains + scope hosts
        all_hosts = list(set(discovered_subdomains + scope.raw_entries))
        s2_status, live_http_services = run_probe_stage(config, scope, runner, raw_dir, all_hosts)
        stage_status["httpx"] = s2_status
        (parsed_dir / "http_services.json").write_text(
            json.dumps([s.to_dict() for s in live_http_services], indent=2), encoding="utf-8"
        )

        # Stage 3: Port and service scan (Nmap)
        print_step(3, "Port & Service Fingerprinting", "Nmap conservative -sV -T3")
        # Targets: live HTTP hosts if any, or general discovered hosts/scope
        nmap_targets = [s.host for s in live_http_services] if live_http_services else all_hosts
        s3_status, host_ports = run_portscan_stage(config, scope, runner, raw_dir, nmap_targets)
        stage_status["nmap"] = s3_status
        (parsed_dir / "host_ports.json").write_text(
            json.dumps([h.to_dict() for h in host_ports], indent=2), encoding="utf-8"
        )

        # Stage 4: Template-based exposure checks (Nuclei)
        print_step(4, "Template Exposure Checks", "Nuclei non-intrusive severity filter")
        nuclei_targets = [s.url for s in live_http_services]
        if not nuclei_targets:
            # Fallback to in-scope domains as http/https targets if httpx was skipped or found none
            for h in all_hosts:
                if "/" not in h:
                    nuclei_targets.extend([f"http://{h}", f"https://{h}"])
        s4_status, findings = run_vulnscan_stage(config, scope, runner, raw_dir, nuclei_targets)
        stage_status["nuclei"] = s4_status
        (parsed_dir / "findings.json").write_text(
            json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8"
        )

    except KeyboardInterrupt:
        logger.warning("\nExecution interrupted by user (Ctrl+C). Generating partial report...")
    except Exception as err:
        logger.error("Pipeline execution encountered an unexpected error: %s", err, exc_info=True)
    finally:
        end_time = datetime.now(timezone.utc)

        # 5. Generate Reports
        report_gen = ReportGenerator(
            config=config,
            scope=scope,
            tool_status=tool_status,
            stage_status=stage_status,
            subdomains=discovered_subdomains,
            http_services=live_http_services,
            host_ports=host_ports,
            findings=findings,
            start_time=start_time,
            end_time=end_time,
        )

        json_file = report_dir / "report.json"
        md_file = report_dir / "report.md"

        report_gen.generate_json(json_file)
        report_gen.generate_markdown(md_file)

        logger.info("Run finished.")
        logger.info("Structured JSON report: %s", json_file)
        logger.info("Human-readable Markdown report: %s", md_file)

        total_open_ports = sum(len(h.ports) for h in host_ports)
        print_summary_card(
            run_dir=run_dir,
            subdomains_count=len(discovered_subdomains),
            services_count=len(live_http_services),
            hosts_count=len(host_ports),
            ports_count=total_open_ports,
            findings_count=len(findings),
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
