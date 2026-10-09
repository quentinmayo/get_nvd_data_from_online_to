import json
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine, text

from nvd_exporter.cli import main, parse_date, parser, queries


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    for name in ("NVD_FORMAT", "NVD_OUTPUT", "NVD_DATABASE_URL", "NVD_API_KEY"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def api(monkeypatch, cve):
    instance = Mock()
    instance.iter_cves.return_value = iter([cve, {**cve, "id": "CVE-2024-99999"}])
    constructor = Mock(return_value=instance)
    monkeypatch.setattr("nvd_exporter.cli.NvdClient", constructor)
    return constructor, instance


def test_export_env_filter_limit(tmp_path, monkeypatch, api):
    path = tmp_path / "export.jsonl"
    monkeypatch.setenv("NVD_OUTPUT", str(path))
    monkeypatch.setenv("NVD_FORMAT", "jsonl")
    monkeypatch.setenv("NVD_API_KEY", "secret")
    assert main(["--filter", "cve_id=99999$", "--limit", "1", "--fields", "cve_id"]) == 0
    assert json.loads(path.read_text()) == {"cve_id": "CVE-2024-99999"}
    assert api[0].call_args.kwargs["api_key"] == "secret"
    api[1].close.assert_called_once()


def test_legacy_output_alias(tmp_path, api):
    path = tmp_path / "legacy.csv"
    assert main(["-cve_information_path", str(path), "--limit", "1"]) == 0
    assert path.read_text().count("CVE-2024-") == 1


def test_sqlite_cli(tmp_path, api):
    path = tmp_path / "nested" / "db.sqlite3"
    assert main(["--format", "sqlite", "-o", str(path), "--table", "custom_cves"]) == 0
    engine = create_engine(f"sqlite:///{path}")
    try:
        with engine.connect() as conn:
            assert conn.execute(text("SELECT count(*) FROM custom_cves")).scalar() == 2
    finally:
        engine.dispose()


@pytest.mark.parametrize(
    "args",
    [
        ["--limit", "0"],
        ["--page-size", "2001"],
        ["--timeout", "nan"],
        ["--retries", "-1"],
        ["--published-start", "2024-01-01"],
        ["--published-start", "2024-02-01", "--published-end", "2024-01-01"],
        ["--fields", "not_a_field"],
        ["--filter", "cve_id=["],
        ["--filter", "missing=pattern"],
        ["--format", "database"],
        ["--format", "sqlite", "--fields", "cve_id"],
        ["--database-url", "sqlite://"],
        ["--cve-id", "bad"],
    ],
)
def test_invalid_arguments_before_network(args, api):
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2
    api[0].assert_not_called()


def test_query_dates():
    args = parser().parse_args(["--modified-start", "2024-01-01", "--modified-end", "2024-12-31"])
    result = queries(args)
    assert len(result) == 4
    assert result[0]["lastModStartDate"] == "2024-01-01T00:00:00.000+00:00"
    assert result[-1]["lastModEndDate"] == "2024-12-31T23:59:59.999+00:00"
    assert parse_date("2024-01-01T02:00:00+02:00").hour == 0


def test_invalid_database_hides_secret(api, capsys):
    url = "not-a-url-with-secret"
    assert main(["--format", "database", "--database-url", url]) == 1
    assert url not in capsys.readouterr().err


def test_help_does_not_reveal_credentials(monkeypatch, capsys):
    monkeypatch.setenv("NVD_API_KEY", "private-api-key")
    monkeypatch.setenv("NVD_DATABASE_URL", "postgresql://user:private-password@localhost/nvd")
    with pytest.raises(SystemExit) as error:
        main(["--help"])
    assert error.value.code == 0
    output = capsys.readouterr().out
    assert "private-api-key" not in output
    assert "private-password" not in output
