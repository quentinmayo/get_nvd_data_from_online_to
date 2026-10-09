import csv
import json
import os
import uuid

import pytest
from sqlalchemy import MetaData, create_engine, select
from sqlalchemy.engine import URL

from nvd_exporter.records import normalize
from nvd_exporter.storage import cve_table, database_url, write_database, write_file


@pytest.mark.parametrize("format", ["csv", "json", "jsonl"])
def test_file_roundtrip(tmp_path, cve, format):
    path = tmp_path / "new folder" / f"data.{format}"
    record = normalize(cve)
    assert write_file([record], path, format) == 1
    if format == "csv":
        with path.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream))
        assert rows[0]["description"] == record["description"]
        assert json.loads(rows[0]["cpes"]) == record["cpes"]
        assert "raw" not in rows[0]
    else:
        result = json.loads(path.read_text())
        assert (result[0] if format == "json" else result) == record


@pytest.mark.parametrize("format", ["csv", "json", "jsonl"])
def test_failure_preserves_existing_file(tmp_path, cve, format):
    path = tmp_path / "previous"
    path.write_text("keep me")

    def failing():
        yield normalize(cve)
        raise RuntimeError("download failed")

    with pytest.raises(RuntimeError):
        write_file(failing(), path, format)
    assert path.read_text() == "keep me"
    assert list(tmp_path.iterdir()) == [path]


def test_empty_and_custom_fields(tmp_path, cve):
    path = tmp_path / "result.json"
    write_file([], path, "json")
    assert json.loads(path.read_text()) == []
    write_file([normalize(cve)], path, "json", ["cve_id", "cvss_score"])
    assert json.loads(path.read_text()) == [{"cve_id": cve["id"], "cvss_score": 9.8}]


def check_upsert(url, cve):
    table_name = f"test_nvd_{uuid.uuid4().hex}"
    engine = create_engine(database_url(url))
    table = cve_table(table_name, MetaData())
    try:
        record = normalize(cve)
        assert write_database([record, record], url, table_name, batch_size=1) == 2
        updated = normalize({**cve, "descriptions": [{"lang": "en", "value": "updated"}]})
        assert write_database([updated], url, table_name) == 1
        with engine.connect() as conn:
            rows = conn.execute(select(table)).mappings().all()
        assert len(rows) == 1
        assert rows[0]["description"] == "updated"
        assert rows[0]["raw"] == updated["raw"]
        assert rows[0]["cvss_score"] == 9.8
    finally:
        table.drop(engine, checkfirst=True)
        engine.dispose()


def test_sqlite_upsert(tmp_path, cve):
    path = tmp_path / "new folder" / "cves.sqlite3"
    check_upsert(URL.create("sqlite", database=str(path)), cve)
    assert path.is_file()


def test_database_retains_only_committed_batches(tmp_path, cve):
    url = URL.create("sqlite", database=str(tmp_path / "partial.sqlite3"))

    def failing():
        yield normalize(cve)
        yield normalize({**cve, "id": "CVE-2024-99999"})
        raise RuntimeError("network interrupted")

    with pytest.raises(RuntimeError):
        write_database(failing(), url, batch_size=1)
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            rows = conn.execute(select(cve_table("nvd_cves", MetaData()))).all()
            assert len(rows) == 2
    finally:
        engine.dispose()


@pytest.mark.integration
@pytest.mark.parametrize("variable", ["TEST_POSTGRES_URL", "TEST_MYSQL_URL"])
def test_server_database(variable, cve):
    url = os.getenv(variable)
    if not url:
        pytest.skip(f"Set {variable} to a disposable test database")
    check_upsert(url, cve)


@pytest.mark.parametrize("name", ["bad; DROP TABLE users", "schema.table", "1abc", "x" * 64])
def test_invalid_table_name(name):
    with pytest.raises(ValueError):
        cve_table(name, MetaData())


def test_failed_batch_rolls_back_updates(tmp_path, cve):
    from sqlalchemy.exc import IntegrityError

    url = URL.create("sqlite", database=str(tmp_path / "rollback.sqlite3"))
    record = normalize(cve)
    write_database([record], url)
    changed = {**record, "description": "must be rolled back"}
    invalid = {**record, "cve_id": None}
    with pytest.raises(IntegrityError):
        write_database([changed, invalid], url, batch_size=2)
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            rows = conn.execute(select(cve_table("nvd_cves", MetaData()))).mappings().all()
        assert len(rows) == 1
        assert rows[0]["description"] == record["description"]
    finally:
        engine.dispose()
