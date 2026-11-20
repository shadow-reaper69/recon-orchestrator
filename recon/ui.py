"""Rich terminal formatting and console user interface."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from rich.box import DOUBLE, ROUNDED
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False

console = Console() if _HAS_RICH else None


def print_banner() -> None:
    """Print an aesthetic terminal banner using Rich formatting."""
    if not _HAS_RICH or console is None:
        print("=== RECON ORCHESTRATOR ===")
        return

    banner_text = Text()
    banner_text.append("RECON ORCHESTRATOR\n", style="bold cyan")
    banner_text.append("Automated Asset Inventory Pipeline\n", style="bold white")
    banner_text.append("Authorised Security Assessments Only\n", style="bold yellow")
    banner_text.append("Tools: Subfinder | httpx | Nmap | Nuclei", style="dim white")

    panel = Panel(
        banner_text,
        box=ROUNDED,
        border_style="cyan",
        expand=False,
    )
    console.print()
    console.print(panel, justify="center")
    console.print()


def print_step(stage_num: int, title: str, desc: str) -> None:
    """Print a stage step indicator."""
    if not _HAS_RICH or console is None:
        print(f"\n[Stage {stage_num}] {title} - {desc}")
        return

    text = Text()
    text.append(f" STAGE {stage_num} ", style="bold black on cyan")
    text.append(f"  {title.upper()} ", style="bold white")
    text.append(f"({desc})", style="dim white")

    console.print()
    console.print(Panel(text, box=ROUNDED, border_style="cyan", padding=(0, 1)))


def print_tool_table(tool_status: Dict[str, Any]) -> None:
    """Display a table of external tool availability."""
    if not _HAS_RICH or console is None:
        return

    table = Table(
        title="[bold cyan]Tool Environment[/bold cyan]",
        box=ROUNDED,
        header_style="bold cyan",
        border_style="bright_black",
    )
    table.add_column("Tool", style="bold white", width=12)
    table.add_column("Status", justify="center", width=14)
    table.add_column("Binary Path / Details", style="dim white")

    for tool_name, info in tool_status.items():
        if info.installed:
            status = "[bold green]AVAILABLE[/bold green]"
            detail = info.version_output or info.path or "Detected"
        else:
            status = "[bold yellow]SKIPPED[/bold yellow]"
            detail = info.error_message or "Not installed in PATH"

        table.add_row(tool_name, status, detail)

    console.print(table)
    console.print()


def print_summary_card(
    run_dir: Path,
    subdomains_count: int,
    services_count: int,
    hosts_count: int,
    ports_count: int,
    findings_count: int,
) -> None:
    """Display an execution completion card."""
    if not _HAS_RICH or console is None:
        print(f"\nExecution finished. Run artifacts saved to: {run_dir}")
        return

    summary_text = Text()
    summary_text.append("Run Summary\n\n", style="bold green")
    summary_text.append(f"  * In-Scope Subdomains:  {subdomains_count}\n", style="cyan")
    summary_text.append(f"  * Live HTTP Services:  {services_count}\n", style="cyan")
    summary_text.append(f"  * Scanned Hosts:       {hosts_count}\n", style="cyan")
    summary_text.append(f"  * Open Ports:          {ports_count}\n", style="cyan")
    summary_text.append(f"  * Findings Reported:   {findings_count}\n\n", style="yellow")
    summary_text.append(f"Output Directory:\n  {run_dir}\n", style="dim white")
    summary_text.append(f"  |- report/report.md\n  `- report/report.json", style="bold cyan")

    panel = Panel(
        summary_text,
        title="[bold cyan]Pipeline Execution Finished[/bold cyan]",
        box=DOUBLE,
        border_style="green",
        padding=(1, 2),
    )
    console.print()
    console.print(panel)
    console.print()
