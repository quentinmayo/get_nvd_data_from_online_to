"""Durable database synchronization with atomic page writes and fenced leases."""

from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import JSON, Column, Float, MetaData, String, Table, create_engine, inspect, select
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError

from .client import NvdClient, date_windows
from .records import normalize
from .storage import STATE_TABLE, cve_table, database_url, upsert_statement

LOG = logging.getLogger(__name__)
LEASE_SECONDS = 900


class SyncError(RuntimeError):
    """Synchronization could not safely advance."""


def utcnow() -> datetime:
    now = datetime.now(timezone.utc)
    return now.replace(microsecond=now.microsecond // 1000 * 1000)


def timestamp(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds")


def state_table(metadata: MetaData) -> Table:
    return Table(
        STATE_TABLE,
        metadata,
        Column("target_table", String(63), primary_key=True),
        Column("progress", JSON, nullable=False),
        Column("owner", String(32)),
        Column("lease_until", Float, nullable=False),
    )


def initial_state() -> dict[str, Any]:
    return {
        "version": 1,
        "phase": "bootstrap",
        "next_index": 0,
        "watermark": timestamp(utcnow()),
        "pending": None,
    }


def validate_state(state: Any) -> None:
    try:
        valid = (
            type(state["version"]) is int
            and state["version"] == 1
            and state["phase"] in {"bootstrap", "incremental"}
            and type(state["next_index"]) is int
            and state["next_index"] >= 0
            and datetime.fromisoformat(state["watermark"]).tzinfo is not None
        )
        if state["pending"] is not None:
            begin = datetime.fromisoformat(state["pending"]["start"])
            end = datetime.fromisoformat(state["pending"]["end"])
            valid = valid and (
                begin.tzinfo is not None
                and end.tzinfo is not None
                and timedelta(0) <= end - begin <= timedelta(days=120)
            )
        if not valid:
            raise ValueError("Invalid checkpoint")
    except (KeyError, TypeError, ValueError):
        raise SyncError(
            "Invalid sync checkpoint; use --reset-sync to start a full import"
        ) from None


def sync_database(
    client: NvdClient,
    url: str | URL,
    table_name: str = "nvd_cves",
    *,
    batch_size: int = 500,
    overlap: int = 300,
    reset: bool = False,
) -> int:
    if batch_size < 1 or not 1 <= overlap <= 86400:
        raise ValueError("Sync requires a positive batch size and 1–86400 seconds of overlap")
    if table_name.lower() == STATE_TABLE:
        raise ValueError("This table name is reserved for sync checkpoints")
    url = database_url(url)
    if url.get_backend_name() == "sqlite" and (
        url.database in {None, "", ":memory:"} or url.query.get("mode") == "memory"
    ):
        raise ValueError("Sync requires a persistent database, not an in-memory SQLite database")
    metadata = MetaData()
    table = cve_table(table_name, metadata)
    checkpoints = state_table(metadata)
    engine = create_engine(url, pool_pre_ping=True, hide_parameters=True)
    owner = uuid.uuid4().hex
    acquired = False
    count = 0
    try:
        target_missing = not inspect(engine).has_table(table_name)
        metadata.create_all(engine)
        # Savepoints let concurrent first runs race on a unique key without aborting
        # the outer PostgreSQL transaction. Acquiring the lease remains an atomic UPDATE.
        with engine.begin() as conn:
            try:
                with conn.begin_nested():
                    conn.execute(
                        checkpoints.insert().values(
                            target_table=table_name,
                            progress=initial_state(),
                            owner=None,
                            lease_until=0,
                        )
                    )
            except IntegrityError:
                pass
            acquired = (
                conn.execute(
                    checkpoints.update()
                    .where(
                        checkpoints.c.target_table == table_name,
                        checkpoints.c.lease_until <= time.time(),
                    )
                    .values(owner=owner, lease_until=time.time() + LEASE_SECONDS)
                ).rowcount
                == 1
            )
            if not acquired:
                raise SyncError(
                    "Another sync owns this table; retry after it finishes or its "
                    "15-minute lease expires"
                )
            state = conn.execute(
                select(checkpoints.c.progress).where(checkpoints.c.target_table == table_name)
            ).scalar_one()
            if reset or target_missing:
                state = initial_state()
                conn.execute(
                    checkpoints.update()
                    .where(checkpoints.c.target_table == table_name)
                    .values(progress=state)
                )
        validate_state(state)
        statement = upsert_statement(table, engine.dialect.name)

        def commit_page(cves: list[dict[str, Any]], progress: dict[str, Any]) -> None:
            nonlocal count
            records = [normalize(cve) for cve in cves]
            with engine.begin() as conn:
                # Check ownership inside the SAME transaction as both data and cursor.
                # An expired/replaced worker must never publish stale rows or progress.
                changed = conn.execute(
                    checkpoints.update()
                    .where(
                        checkpoints.c.target_table == table_name,
                        checkpoints.c.owner == owner,
                        checkpoints.c.lease_until > time.time(),
                    )
                    .values(progress=progress, lease_until=time.time() + LEASE_SECONDS)
                ).rowcount
                if changed != 1:
                    raise SyncError("Sync lease expired or ownership changed; rerun to recover")
                for offset in range(0, len(records), batch_size):
                    conn.execute(statement, records[offset : offset + batch_size])
            count += len(records)

        if state["phase"] == "bootstrap":
            LOG.info("Full import: resuming at record %d", state["next_index"])
            for cves, next_index, complete in client.iter_pages(start_index=state["next_index"]):
                state = {
                    **state,
                    "next_index": next_index,
                    "phase": "incremental" if complete else "bootstrap",
                }
                commit_page(cves, state)
        stop_at = utcnow()
        if datetime.fromisoformat(state["watermark"]) > stop_at:
            raise SyncError("Sync checkpoint is in the future; check the system clock")

        def update_window(begin: datetime, end: datetime) -> None:
            nonlocal state
            LOG.info("Syncing modified CVEs: %s to %s", timestamp(begin), timestamp(end))
            state = {**state, "pending": {"start": timestamp(begin), "end": timestamp(end)}}
            commit_page([], state)
            params = {"lastModStartDate": timestamp(begin), "lastModEndDate": timestamp(end)}
            # A modified-date result set can shrink while we are offline. Replaying
            # the unfinished window is safer than resuming at its saved row offset.
            for cves, _, complete in client.iter_pages(params):
                if complete:
                    state = {**state, "watermark": timestamp(end), "pending": None, "next_index": 0}
                commit_page(cves, state)

        if state["pending"]:
            pending = state["pending"]
            if datetime.fromisoformat(pending["end"]) > stop_at:
                raise SyncError("Pending sync window is in the future; check the system clock")
            update_window(
                datetime.fromisoformat(pending["start"]), datetime.fromisoformat(pending["end"])
            )
        start = datetime.fromisoformat(state["watermark"]) - timedelta(seconds=overlap)
        for begin, end in date_windows(start, stop_at):
            update_window(begin, end)
        LOG.info("Sync complete through %s", state["watermark"])
        return count
    finally:
        try:
            if acquired:
                with engine.begin() as conn:
                    conn.execute(
                        checkpoints.update()
                        .where(
                            checkpoints.c.target_table == table_name,
                            checkpoints.c.owner == owner,
                        )
                        .values(owner=None, lease_until=0)
                    )
        finally:
            engine.dispose()
