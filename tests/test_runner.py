"""Unit tests for the SafeRunner subprocess wrapper."""

from unittest.mock import MagicMock, patch
import subprocess
from recon.runner import SafeRunner


def test_safe_runner_executes_list_safely():
    runner = SafeRunner()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="sample output\n",
            stderr="",
        )

        result = runner.run(["echo", "hello"], timeout=10)
        assert result.returncode == 0
        assert result.stdout == "sample output\n"
        assert result.timed_out is False

        # Verify shell=False was strictly enforced
        args, kwargs = mock_run.call_args
        assert kwargs.get("shell") is False
        assert args[0] == ["echo", "hello"]


def test_safe_runner_handles_timeout():
    runner = SafeRunner()

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["test"], timeout=2)):
        result = runner.run(["test"], timeout=2)
        assert result.timed_out is True
        assert result.returncode == -1
