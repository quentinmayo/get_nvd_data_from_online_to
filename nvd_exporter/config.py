"""Explicit TOML configuration; command-line arguments always take precedence."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

TEMPLATE = """# Run: nvd-export --config nvd.toml
# Relative output paths are resolved beside this configuration file.
[export]
format = "sqlite"
output = "data/nvd.sqlite3"
table = "nvd_cves"
sync = true
page_size = 2000
batch_size = 500
sync_overlap = 300  # seconds replayed at the start of each update

# For a server database, remove output and set format = "database".
# Supply the connection via NVD_DATABASE_URL and the API key via NVD_API_KEY.
# sync = false enables ordinary exports with keyword, filter, fields, or limit.
"""
STRINGS = {
    "format",
    "output",
    "database_url",
    "table",
    "api_key",
    "cve_id",
    "keyword",
    "fields",
    "published_start",
    "published_end",
    "modified_start",
    "modified_end",
}
INTEGERS = {"limit", "page_size", "batch_size", "retries", "sync_overlap"}
BOOLEANS = {"sync", "quiet"}
ENVIRONMENT = {
    "NVD_FORMAT": "format",
    "NVD_OUTPUT": "output",
    "NVD_DATABASE_URL": "database_url",
    "NVD_API_KEY": "api_key",
}


def write_template(path: Path) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation preserves existing settings; limit access to future credentials.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(TEMPLATE)


def load_config(path: Path) -> dict[str, Any]:
    path = path.expanduser().resolve()
    try:
        with path.open("rb") as stream:
            document = tomllib.load(stream)
    except (OSError, ValueError):
        raise ValueError(
            "Cannot read configuration; check file permissions and TOML syntax"
        ) from None
    if set(document) != {"export"} or not isinstance(document["export"], dict):
        raise ValueError("Configuration must contain exactly one [export] section")
    settings = document["export"]
    for key, value in settings.items():
        valid = (
            (key in STRINGS and isinstance(value, str))
            or (key in INTEGERS and type(value) is int)
            or (key in BOOLEANS and type(value) is bool)
            or (key == "timeout" and type(value) in {int, float})
            or (
                key == "filter"
                and isinstance(value, list)
                and all(isinstance(item, str) for item in value)
            )
        )
        if not valid:
            raise ValueError(f"Unknown configuration option or invalid type: {key}")
    if settings.get("output"):
        output = Path(settings["output"]).expanduser()
        settings["output"] = str(output if output.is_absolute() else path.parent / output)
    if settings.get("database_url"):
        try:
            url = make_url(settings["database_url"])
        except ArgumentError:
            raise ValueError("Invalid database_url in configuration") from None
        if url.get_backend_name() == "sqlite" and url.database not in {None, "", ":memory:"}:
            output = Path(url.database).expanduser()
            if not output.is_absolute():
                output = path.parent / output
            settings["database_url"] = url.set(database=str(output)).render_as_string(
                hide_password=False
            )
    return settings
