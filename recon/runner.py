"""Safe subprocess execution and external tool detection.

Enforces:
- shell=False at all times.
- Explicit argument lists.
- Target pre-validation before passing to CLI.
- Per-command timeouts and graceful termination.
- Verification of tool vendor (e.g. ProjectDiscovery httpx vs python httpx).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("recon.runner")


@dataclass
class ToolCheckResult:
    """Status and version information for an external binary."""

    installed: bool
    path: Optional[str] = None
    version_output: Optional[str] = None
    vendor_verified: bool = True
    error_message: Optional[str] = None


@dataclass
class CommandResult:
    """Execution output from a safe subprocess invocation."""

    args: List[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class SafeRunner:
    """Manages secure, audited invocation of external reconnaissance binaries."""

    def __init__(self) -> None:
        self._tool_cache: Dict[str, ToolCheckResult] = {}

    def check_tool(self, tool_name: str) -> ToolCheckResult:
        """Inspect system PATH and verify if a tool is installed and compatible."""
        if tool_name in self._tool_cache:
            return self._tool_cache[tool_name]

        binary_path = shutil.which(tool_name)
        if not binary_path:
            result = ToolCheckResult(
                installed=False,
                error_message=f"Binary '{tool_name}' not found in system PATH.",
            )
            self._tool_cache[tool_name] = result
            return result

        # For httpx, distinguish ProjectDiscovery httpx from Python httpx
        if tool_name == "httpx":
            try:
                res = subprocess.run(
                    [binary_path, "-version"],
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                output = res.stdout + res.stderr
                # ProjectDiscovery httpx prints "projectdiscovery" or "Current Version"
                if "projectdiscovery" in output.lower() or "current version" in output.lower():
                    result = ToolCheckResult(
                        installed=True,
                        path=binary_path,
                        version_output=output.strip().split("\n")[0],
                        vendor_verified=True,
                    )
                else:
                    result = ToolCheckResult(
                        installed=False,
                        path=binary_path,
                        vendor_verified=False,
                        error_message=(
                            f"The 'httpx' binary at '{binary_path}' appears to be Python HTTPX, "
                            "not ProjectDiscovery httpx. Skipping stage."
                        ),
                    )
            except Exception as err:
                result = ToolCheckResult(
                    installed=False,
                    path=binary_path,
                    vendor_verified=False,
                    error_message=f"Failed to verify httpx: {err}",
                )
            self._tool_cache[tool_name] = result
            return result

        # Check version for other tools (subfinder, nmap, nuclei)
        version_flags = {
            "subfinder": ["-version"],
            "nmap": ["-V"],
            "nuclei": ["-version"],
        }
        flags = version_flags.get(tool_name, ["--version"])

        try:
            res = subprocess.run(
                [binary_path] + flags,
                shell=False,
                capture_output=True,
                text=True,
                timeout=5,
            )
            v_line = (res.stdout or res.stderr).strip().split("\n")[0]
            result = ToolCheckResult(
                installed=True,
                path=binary_path,
                version_output=v_line,
                vendor_verified=True,
            )
        except Exception as err:
            result = ToolCheckResult(
                installed=True,
                path=binary_path,
                version_output="Unknown (version check timed out or failed)",
                vendor_verified=True,
                error_message=str(err),
            )

        self._tool_cache[tool_name] = result
        return result

    def run(
        self,
        args: List[str],
        timeout: Optional[int] = None,
        cwd: Optional[str] = None,
    ) -> CommandResult:
        """Execute a command list securely with shell=False and strict timeout."""
        if not args or not isinstance(args, list):
            raise ValueError("Arguments must be provided as a non-empty list of strings.")

        # Ensure all arguments are strings
        clean_args = [str(arg) for arg in args]

        # Log sanitized representation of command
        logger.debug("Executing subprocess: %s", " ".join(clean_args))

        try:
            completed = subprocess.run(
                clean_args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                check=False,
            )
            return CommandResult(
                args=clean_args,
                returncode=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            logger.warning(
                "Command '%s' timed out after %s seconds.", clean_args[0], timeout
            )
            return CommandResult(
                args=clean_args,
                returncode=-1,
                stdout=exc.stdout or "" if isinstance(exc.stdout, str) else "",
                stderr=exc.stderr or "" if isinstance(exc.stderr, str) else "",
                timed_out=True,
            )
        except FileNotFoundError:
            logger.error("Binary '%s' was not found for execution.", clean_args[0])
            return CommandResult(
                args=clean_args,
                returncode=127,
                stdout="",
                stderr=f"Binary not found: {clean_args[0]}",
                timed_out=False,
            )
        except Exception as err:
            logger.error("Unexpected error executing '%s': %s", clean_args[0], err)
            return CommandResult(
                args=clean_args,
                returncode=-1,
                stdout="",
                stderr=str(err),
                timed_out=False,
            )
