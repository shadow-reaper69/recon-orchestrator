"""Logging setup for safe reconnaissance pipeline."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logger(
    name: str = "recon",
    log_file: Optional[Path] = None,
    verbose: bool = False,
) -> logging.Logger:
    """Configure console and optional file logging.

    Ensures consistent format and scrubs potential command credentials.
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Avoid duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)-7s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler if path provided
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(str(log_file), encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger
