import json
from unittest.mock import Mock

import pytest

from nvd_exporter.cli import main
from nvd_exporter.config import load_config, write_template


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for key in ("NVD_CONFIG", "NVD_OUTPUT", "NVD_FORMAT", "NVD_DATABASE_URL", "NVD_API_KEY"):
        monkeypatch.delenv(key, raising=False)


def test_template_exclusive_and_relative_paths(tmp_path):
    path = tmp_path / "nvd.toml"
    write_template(path)
    settings = load_config(path)
    assert settings["sync"] is True
    assert settings["output"] == str(tmp_path / "data/nvd.sqlite3")
    with pytest.raises(FileExistsError):
        write_template(path)


@pytest.mark.parametrize(
    "contents",
    [
        '[export]\nsync = "yes"',
        "[export]\npage_size = true",
        '[export]\ntimeout = "60"',
        "[export]\nfilter = [123]",
        '[export]\nunknown = "value"',
        "[other]\nsync = true",
        '[export]\npassword = "SECRET"',
        '[export]\napi_key = "SECRET',
    ],
)
def test_invalid_config_does_not_echo_values(tmp_path, contents):
    path = tmp_path / "invalid.toml"
    path.write_text(contents)
    with pytest.raises(ValueError) as error:
        load_config(path)
    assert "SECRET" not in str(error.value)


def test_precedence_and_filter_replacement(tmp_path, monkeypatch, cve):
    path = tmp_path / "nvd.toml"
    path.write_text('[export]\nformat = "csv"\noutput = "config.csv"\nfilter = ["cve_id=NEVER"]\n')
    monkeypatch.setenv("NVD_CONFIG", str(path))
    monkeypatch.setenv("NVD_OUTPUT", str(tmp_path / "env.json"))
    monkeypatch.setenv("NVD_FORMAT", "json")
    api = Mock()
    api.iter_cves.side_effect = lambda _: iter([cve])
    monkeypatch.setattr("nvd_exporter.cli.NvdClient", Mock(return_value=api))
    assert main(["--filter", "cve_id=CVE"]) == 0
    assert json.loads((tmp_path / "env.json").read_text())[0]["cve_id"] == cve["id"]
    cli_path = tmp_path / "cli.jsonl"
    assert main(["--format", "jsonl", "--output", str(cli_path), "--filter", "cve_id=CVE"]) == 0
    assert json.loads(cli_path.read_text())["cve_id"] == cve["id"]
    assert not (tmp_path / "config.csv").exists()


def test_init_config_never_downloads(tmp_path, monkeypatch):
    api = Mock()
    monkeypatch.setattr("nvd_exporter.cli.NvdClient", api)
    path = tmp_path / "nvd.toml"
    assert main(["--init-config", str(path)]) == 0
    assert main(["--init-config", str(path)]) == 1
    api.assert_not_called()


def test_sync_config_and_no_sync_override(tmp_path, monkeypatch, cve):
    path = tmp_path / "nvd.toml"
    write_template(path)
    api = Mock()
    api.iter_cves.return_value = iter([cve])
    monkeypatch.setattr("nvd_exporter.cli.NvdClient", Mock(return_value=api))
    sync = Mock(return_value=0)
    monkeypatch.setattr("nvd_exporter.cli.sync_database", sync)
    assert main(["--config", str(path)]) == 0
    assert sync.call_count == 1
    assert sync.call_args.args[1].database == str(tmp_path / "data/nvd.sqlite3")
    assert main(["--config", str(path), "--no-sync", "--limit", "1"]) == 0
    assert sync.call_count == 1


def test_sqlite_url_relative_to_config(tmp_path):
    path = tmp_path / "settings.toml"
    path.write_text('[export]\nformat="database"\ndatabase_url="sqlite:///data/db.sqlite3"')
    assert load_config(path)["database_url"] == f"sqlite:///{tmp_path}/data/db.sqlite3"
