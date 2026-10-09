"""Streaming file exports and batched SQL upserts."""

from __future__ import annotations

import csv
import json
import os
import re
import tempfile
from collections.abc import Iterable, Sequence
from itertools import islice
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, Column, Float, MetaData, String, Table, Text, create_engine
from sqlalchemy.dialects.mysql import LONGTEXT
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.postgresql import insert as postgres_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import URL, make_url

from .records import CSV_FIELDS, FIELDS


def cell(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return value


def write_file(
    records: Iterable[dict[str, Any]], path: Path, format: str, fields: Sequence[str] | None = None
) -> int:
    """Publish a new file only after the entire export completes successfully."""
    if format not in {"csv", "json", "jsonl"}:
        raise ValueError("File format must be csv, json, or jsonl")
    selected = tuple(fields) if fields else (CSV_FIELDS if format == "csv" else FIELDS)
    if not set(selected) <= set(FIELDS):
        raise ValueError("Unknown output field")
    path = path.expanduser().absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    count = 0
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            if format == "csv":
                writer = csv.DictWriter(stream, fieldnames=selected)
                writer.writeheader()
            elif format == "json":
                stream.write("[\n")
            for record in records:
                row = {key: record[key] for key in selected}
                if format == "csv":
                    writer.writerow({key: cell(value) for key, value in row.items()})
                else:
                    if format == "json" and count:
                        stream.write(",\n")
                    stream.write(json.dumps(row, ensure_ascii=False))
                    if format == "jsonl":
                        stream.write("\n")
                count += 1
            if format == "json":
                stream.write("\n]\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return count


def database_url(value: str | URL) -> URL:
    url = make_url(value)
    backend = url.get_backend_name()
    if backend not in {"sqlite", "postgresql", "mysql"}:
        raise ValueError("Supported database URL schemes: sqlite, postgresql, mysql")
    if url.drivername == "postgresql":
        url = url.set(drivername="postgresql+psycopg")
    elif url.drivername == "mysql":
        url = url.set(drivername="mysql+pymysql")
    if backend == "sqlite" and url.database not in {None, "", ":memory:"}:
        path = Path(url.database).expanduser().absolute()
        path.parent.mkdir(parents=True, exist_ok=True)
        url = url.set(database=str(path))
    return url


def cve_table(name: str, metadata: MetaData) -> Table:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", name):
        raise ValueError(
            "Table name must be 1–63 letters, digits, or underscores; "
            "start with a letter/underscore"
        )
    return Table(
        name,
        metadata,
        Column("cve_id", String(64), primary_key=True),
        Column("source_identifier", Text),
        Column("published", String(40)),
        Column("last_modified", String(40)),
        Column("status", String(64)),
        Column("description", Text().with_variant(LONGTEXT(), "mysql")),
        Column("cvss_version", String(10)),
        Column("cvss_score", Float),
        Column("cvss_severity", String(20)),
        Column("cvss_vector", Text),
        Column("weaknesses", JSON),
        Column("references", JSON),
        Column("cpes", JSON),
        Column("raw", JSON, nullable=False),
    )


def upsert_statement(table: Table, dialect: str):
    if dialect in {"sqlite", "postgresql"}:
        statement = (sqlite_insert if dialect == "sqlite" else postgres_insert)(table)
        return statement.on_conflict_do_update(
            index_elements=[table.c.cve_id],
            set_={
                col.name: statement.excluded[col.name] for col in table.c if col.name != "cve_id"
            },
        )
    if dialect == "mysql":
        statement = mysql_insert(table)
        return statement.on_duplicate_key_update(
            **{col.name: statement.inserted[col.name] for col in table.c if col.name != "cve_id"}
        )
    raise ValueError("Unsupported database dialect")


def write_database(
    records: Iterable[dict[str, Any]],
    url: str | URL,
    table_name: str = "nvd_cves",
    batch_size: int = 500,
) -> int:
    if batch_size < 1:
        raise ValueError("Batch size must be positive")
    table = cve_table(table_name, MetaData())
    engine = create_engine(database_url(url), pool_pre_ping=True, hide_parameters=True)
    count = 0
    try:
        table.metadata.create_all(engine)
        statement = upsert_statement(table, engine.dialect.name)
        iterator = iter(records)
        while batch := list(islice(iterator, batch_size)):
            with engine.begin() as connection:
                connection.execute(statement, batch)
            count += len(batch)
    finally:
        engine.dispose()
    return count
