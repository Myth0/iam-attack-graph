"""Tests for engine.cli"""

import subprocess
import sys
from pathlib import Path

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "sample_iam_export.json"


def _run_cli(*args):
    """Run the CLI as a subprocess, the way a real user would invoke it."""
    return subprocess.run(
        [sys.executable, "-m", "engine.cli", *args],
        capture_output=True,
        text=True,
    )


def test_cli_succeeds_on_valid_fixture():
    result = _run_cli(str(FIXTURE_PATH))
    assert result.returncode == 0
    assert "test-user" in result.stdout
    assert "CRITICAL" in result.stdout


def test_cli_fails_gracefully_on_missing_file():
    result = _run_cli("nonexistent_file.json")
    assert result.returncode == 1
    assert "not found" in result.stderr


def test_cli_fails_gracefully_on_invalid_json(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{ this is not valid json")
    result = _run_cli(str(bad_file))
    assert result.returncode == 1
    assert "invalid JSON" in result.stderr
