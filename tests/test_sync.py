import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import MetaData, create_engine, inspect, select
from sqlalchemy.engine import URL
from sqlalchemy.exc import IntegrityError

from nvd_exporter.client import NvdError
from nvd_exporter.records import normalize
from nvd_exporter.storage import cve_table, database_url
from nvd_exporter.sync import SyncError, state_table, sync_database


class ScriptedClient:
    def __init__(self, *scripts):
        self.scripts = list(scripts)
        self.calls = []

    def iter_pages(self, params=None, *, start_index=0):
        self.calls.append((params, start_index))
        for item in self.scripts.pop(0):
            if isinstance(item, Exception):
                raise item
            yield item


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param("TEST_POSTGRES_URL", marks=pytest.mark.integration),
        pytest.param("TEST_MYSQL_URL", marks=pytest.mark.integration),
    ]
)
def destination(request, tmp_path):
    if request.param == "sqlite":
        url = URL.create("sqlite", database=str(tmp_path / "sync.sqlite3"))
    else:
        url = os.getenv(request.param)
        if not url:
            pytest.skip(f"Set {request.param}")
    name = f"sync_test_{uuid.uuid4().hex}"
    engine = create_engine(database_url(url))
    yield url, name, engine
    checkpoints = state_table(MetaData())
    if inspect(engine).has_table(checkpoints.name):
        with engine.begin() as conn:
            conn.execute(checkpoints.delete().where(checkpoints.c.target_table == name))
    cve_table(name, MetaData()).drop(engine, checkfirst=True)
    engine.dispose()


@pytest.fixture
def clock(monkeypatch):
    values = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    monkeypatch.setattr("nvd_exporter.sync.utcnow", lambda: values[0])
    return values


def progress(destination):
    _, name, engine = destination
    checkpoints = state_table(MetaData())
    with engine.connect() as conn:
        return (
            conn.execute(select(checkpoints).where(checkpoints.c.target_table == name))
            .mappings()
            .one()
        )


def rows(destination):
    _, name, engine = destination
    with engine.connect() as conn:
        return conn.execute(select(cve_table(name, MetaData()))).mappings().all()


def test_bootstrap_then_incremental(destination, clock, cve):
    url, name, _ = destination
    other = {**cve, "id": "CVE-2024-99999"}
    api = ScriptedClient([([cve], 1, False), ([other], 2, True)], [([], 0, True)])
    assert sync_database(api, url, name, batch_size=1) == 2
    assert len(rows(destination)) == 2
    assert progress(destination)["progress"]["phase"] == "incremental"
    assert api.calls[0] == (None, 0)
    assert api.calls[1][0]["lastModStartDate"] == "2025-12-31T23:55:00.000+00:00"
    assert progress(destination)["owner"] is None
    clock[0] += timedelta(hours=3)
    changed = {**cve, "vulnStatus": "Rejected"}
    updates = ScriptedClient([([changed], 1, True)])
    assert sync_database(updates, url, name) == 1
    assert len(updates.calls) == 1
    assert updates.calls[0][0]["lastModEndDate"] == "2026-01-01T03:00:00.000+00:00"
    assert len(rows(destination)) == 2
    assert (
        next(row for row in rows(destination) if row["cve_id"] == cve["id"])["status"] == "Rejected"
    )


def test_resume_bootstrap(destination, clock, cve):
    url, name, _ = destination
    api = ScriptedClient([([cve], 1, False), NvdError("offline")])
    with pytest.raises(NvdError):
        sync_database(api, url, name)
    assert progress(destination)["progress"]["next_index"] == 1
    assert len(rows(destination)) == 1
    assert progress(destination)["owner"] is None
    clock[0] += timedelta(days=1)
    resumed = ScriptedClient([([{**cve, "id": "CVE-2024-99999"}], 2, True)], [([], 0, True)])
    sync_database(resumed, url, name)
    assert resumed.calls[0] == (None, 1)
    assert resumed.calls[1][0]["lastModStartDate"] == "2025-12-31T23:55:00.000+00:00"
    assert len(rows(destination)) == 2


def test_replay_interrupted_update_window(destination, clock, cve):
    url, name, _ = destination
    sync_database(ScriptedClient([([], 0, True)], [([], 0, True)]), url, name)
    before = progress(destination)["progress"]["watermark"]
    clock[0] += timedelta(days=1)
    failed = ScriptedClient([([cve], 1, False), NvdError("offline")])
    with pytest.raises(NvdError):
        sync_database(failed, url, name)
    state = progress(destination)["progress"]
    assert state["watermark"] == before
    assert state["pending"] is not None
    clock[0] += timedelta(days=1)
    resumed = ScriptedClient([([cve], 1, True)], [([], 0, True)])
    sync_database(resumed, url, name)
    assert resumed.calls[0] == failed.calls[0]  # same fixed window, offset zero
    assert len(rows(destination)) == 1
    assert progress(destination)["progress"]["pending"] is None
    assert progress(destination)["progress"]["watermark"] == "2026-01-03T00:00:00.000+00:00"


def test_empty_windows_and_long_gap(destination, clock):
    url, name, _ = destination
    sync_database(ScriptedClient([([], 0, True)], [([], 0, True)]), url, name)
    clock[0] += timedelta(days=365)
    api = ScriptedClient(*[[([], 0, True)]] * 4)
    assert sync_database(api, url, name) == 0
    assert len(api.calls) == 4
    for params, index in api.calls:
        assert index == 0
        assert (
            datetime.fromisoformat(params["lastModEndDate"])
            - datetime.fromisoformat(params["lastModStartDate"])
        ) < timedelta(days=120)
    assert progress(destination)["progress"]["watermark"] == "2027-01-01T00:00:00.000+00:00"


def test_page_rows_and_checkpoint_rollback_together(destination, clock, cve, monkeypatch):
    url, name, _ = destination
    real_normalize = normalize

    def broken_record(value):
        result = real_normalize(value)
        if value["id"] == "CVE-2024-99999":
            result["cve_id"] = None  # inject a database constraint failure in the second SQL batch
        return result

    monkeypatch.setattr("nvd_exporter.sync.normalize", broken_record)
    api = ScriptedClient([([cve, {**cve, "id": "CVE-2024-99999"}], 2, True)])
    with pytest.raises(IntegrityError):
        sync_database(api, url, name, batch_size=1)
    assert rows(destination) == []
    assert progress(destination)["progress"]["next_index"] == 0
    assert progress(destination)["progress"]["phase"] == "bootstrap"


def test_live_lease_blocks_and_expired_lease_recovers(destination, clock):
    url, name, engine = destination
    sync_database(ScriptedClient([([], 0, True)], [([], 0, True)]), url, name)
    checkpoints = state_table(MetaData())
    with engine.begin() as conn:
        conn.execute(
            checkpoints.update()
            .where(checkpoints.c.target_table == name)
            .values(owner="another-worker", lease_until=time.time() + 900)
        )
    api = ScriptedClient()
    with pytest.raises(SyncError, match="Another sync"):
        sync_database(api, url, name)
    assert api.calls == []
    assert progress(destination)["owner"] == "another-worker"
    with engine.begin() as conn:
        conn.execute(
            checkpoints.update().where(checkpoints.c.target_table == name).values(lease_until=0)
        )
    sync_database(ScriptedClient([([], 0, True)]), url, name)
    assert progress(destination)["owner"] is None


def test_stale_worker_cannot_commit(destination, clock, cve):
    url, name, engine = destination
    checkpoints = state_table(MetaData())

    class StolenLease:
        def iter_pages(self, **kwargs):
            with engine.begin() as conn:
                conn.execute(
                    checkpoints.update()
                    .where(checkpoints.c.target_table == name)
                    .values(owner="replacement", lease_until=time.time() + 900)
                )
            yield [cve], 1, True

    with pytest.raises(SyncError, match="ownership changed"):
        sync_database(StolenLease(), url, name)
    assert rows(destination) == []
    assert progress(destination)["progress"]["next_index"] == 0
    assert progress(destination)["owner"] == "replacement"


def test_reset_preserves_data(destination, clock, cve):
    url, name, _ = destination
    sync_database(ScriptedClient([([cve], 1, True)], [([], 0, True)]), url, name)
    api = ScriptedClient([([], 0, True)], [([], 0, True)])
    sync_database(api, url, name, reset=True)
    assert api.calls[0] == (None, 0)
    assert len(rows(destination)) == 1


def test_memory_database_rejected():
    with pytest.raises(ValueError, match="persistent"):
        sync_database(ScriptedClient(), "sqlite://")


def test_dropped_destination_restarts_full_import(destination, clock, cve):
    url, name, engine = destination
    sync_database(ScriptedClient([([cve], 1, True)], [([], 0, True)]), url, name)
    cve_table(name, MetaData()).drop(engine)
    api = ScriptedClient([([cve], 1, True)], [([], 0, True)])
    sync_database(api, url, name)
    assert api.calls[0] == (None, 0)
    assert len(rows(destination)) == 1


def test_invalid_checkpoint_requires_reset(destination, clock):
    url, name, engine = destination
    sync_database(ScriptedClient([([], 0, True)], [([], 0, True)]), url, name)
    checkpoints = state_table(MetaData())
    with engine.begin() as conn:
        conn.execute(
            checkpoints.update()
            .where(checkpoints.c.target_table == name)
            .values(progress={"version": 99})
        )
    with pytest.raises(SyncError, match="Invalid sync checkpoint"):
        sync_database(ScriptedClient(), url, name)
    assert progress(destination)["owner"] is None
    sync_database(ScriptedClient([([], 0, True)], [([], 0, True)]), url, name, reset=True)
    assert progress(destination)["progress"]["version"] == 1
