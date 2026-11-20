"""Parser for Subfinder output."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Set, Union

from recon.scope import validate_target


def parse_subfinder_output(content_or_file: Union[str, Path]) -> List[str]:
    """Parse subfinder output (supports line-separated hostnames or JSON output).

    Returns a deduplicated, sorted list of validated hostnames.
    """
    if isinstance(content_or_file, Path) or (
        isinstance(content_or_file, str) and Path(content_or_file).is_file()
    ):
        raw_text = Path(content_or_file).read_text(encoding="utf-8")
    else:
        raw_text = str(content_or_file)

    discovered: Set[str] = set()

    for raw_line in raw_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        # Handle JSON line format if present
        host = line
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                host = data.get("host", "") or data.get("subdomain", "")
            except Exception:
                continue

        try:
            valid_host = validate_target(host)
            discovered.add(valid_host)
        except ValueError:
            # Skip invalid / garbage entries safely
            continue

    return sorted(discovered)
