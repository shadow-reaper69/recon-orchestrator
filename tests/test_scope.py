"""Unit tests for scope parsing and containment logic."""

import pytest
from pathlib import Path
from recon.scope import Scope, validate_target


def test_scope_domain_and_subdomain(tmp_path: Path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        "# Authorized scope\n"
        "example.com\n"
        "lab.internal\n",
        encoding="utf-8",
    )

    scope = Scope.from_file(scope_file)
    assert "example.com" in scope.domains
    assert "lab.internal" in scope.domains

    # Exact matches
    assert scope.is_in_scope("example.com") is True
    assert scope.is_in_scope("lab.internal") is True

    # Valid subdomains
    assert scope.is_in_scope("sub.example.com") is True
    assert scope.is_in_scope("api.dev.example.com") is True
    assert scope.is_in_scope("test.lab.internal") is True

    # Out of scope targets
    assert scope.is_in_scope("badexample.com") is False
    assert scope.is_in_scope("example.org") is False
    assert scope.is_in_scope("notexample.com") is False


def test_scope_cidr_and_single_ip(tmp_path: Path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text(
        "192.168.10.0/24\n"
        "10.0.0.5\n",
        encoding="utf-8",
    )

    scope = Scope.from_file(scope_file)

    # CIDR containment
    assert scope.is_in_scope("192.168.10.1") is True
    assert scope.is_in_scope("192.168.10.254") is True
    assert scope.is_in_scope("192.168.11.1") is False

    # Single IP containment
    assert scope.is_in_scope("10.0.0.5") is True
    assert scope.is_in_scope("10.0.0.6") is False


def test_empty_scope_raises(tmp_path: Path):
    scope_file = tmp_path / "empty.txt"
    scope_file.write_text("# Only comments\n\n", encoding="utf-8")

    with pytest.raises(ValueError, match="contains no valid domains"):
        Scope.from_file(scope_file)
