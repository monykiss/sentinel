"""Tests for the sentinel-cli tool."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from sentinel_cli.cli import cmd_init, main


def _init(tmp_path: Path, api_key: str | None = "dummy-key") -> Path:
    config_path = tmp_path / "sentinel" / "config.json"
    args = SimpleNamespace(api_key=api_key, gateway="http://localhost:8000")
    with patch("sentinel_cli.cli.CONFIG_FILE", config_path), patch("requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        cmd_init(args)
    return config_path


def test_init_writes_config_file(tmp_path: Path) -> None:
    config = json.loads(_init(tmp_path).read_text())
    assert config == {"api_key": "dummy-key", "gateway_url": "http://localhost:8000"}


def test_the_config_holding_the_key_is_owner_only(tmp_path: Path) -> None:
    path = _init(tmp_path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_an_existing_world_readable_config_is_tightened(tmp_path: Path) -> None:
    path = tmp_path / "sentinel" / "config.json"
    path.parent.mkdir()
    path.write_text("{}")
    path.chmod(0o644)
    _init(tmp_path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_the_key_can_come_from_the_environment(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_API_KEY", "from-env")
    config = json.loads(_init(tmp_path, api_key=None).read_text())
    assert config["api_key"] == "from-env"


def test_no_key_anywhere_exits_without_writing(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    with pytest.raises(SystemExit):
        _init(tmp_path, api_key=None)
    assert not (tmp_path / "sentinel" / "config.json").exists()


def test_cli_module_importable() -> None:
    import sentinel_cli

    assert sentinel_cli.__version__ == "1.0.0"


def test_cli_main_no_args_exits_cleanly() -> None:
    """Running sentinel with no args should print help, not crash."""
    with patch.object(sys, "argv", ["sentinel"]):
        main()
