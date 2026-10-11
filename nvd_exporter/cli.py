"""Command line interface for selecting the source query and destination."""

from __future__ import annotations

import argparse
import logging
import math
import os
import re
import sys
from collections.abc import Iterator, Sequence
from datetime import datetime, time, timezone
from itertools import islice
from pathlib import Path
from typing import Any

from sqlalchemy.engine import URL
from sqlalchemy.exc import SQLAlchemyError

from . import __version__
from .client import NvdClient, NvdError, date_windows
from .config import ENVIRONMENT, load_config, write_template
from .records import FIELDS, normalize
from .storage import cell, write_database, write_file
from .sync import SyncError, sync_database

LOG = logging.getLogger(__name__)
FORMATS = ("csv", "json", "jsonl", "sqlite", "database")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Export NVD API 2.0 CVEs to a file or database.",
    )
    result.add_argument(
        "--config", default=os.getenv("NVD_CONFIG"), help="Read an [export] TOML file"
    )
    result.add_argument(
        "--init-config", metavar="PATH", help="Create a starter configuration and exit"
    )
    result.add_argument(
        "--sync",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Maintain a complete CVE database with durable incremental updates",
    )
    result.add_argument(
        "--reset-sync",
        action="store_true",
        help="Restart the full sync without deleting existing CVEs",
    )
    result.add_argument(
        "--sync-overlap",
        type=int,
        default=300,
        help="Seconds to replay between updates (1–86400; default 300)",
    )
    result.add_argument("--version", action="version", version=__version__)
    result.add_argument("--format", choices=FORMATS, default=os.getenv("NVD_FORMAT", "csv"))
    result.add_argument(
        "--output",
        "-o",
        "-cve_information_path",
        default=os.getenv("NVD_OUTPUT"),
        help="Destination file path (CSV/JSON/JSONL/SQLite); creates parent folders",
    )
    result.add_argument(
        "--database-url",
        default=os.getenv("NVD_DATABASE_URL"),
        help="SQLAlchemy connection URL; use NVD_DATABASE_URL for credentials",
    )
    result.add_argument("--table", default="nvd_cves", help="Database table name")
    result.add_argument(
        "--api-key", default=os.getenv("NVD_API_KEY"), help="NVD API key; prefer NVD_API_KEY"
    )
    result.add_argument("--cve-id", help="Retrieve one CVE, e.g. CVE-2021-44228")
    result.add_argument("--keyword", help="Search NVD descriptions")
    for kind in ("published", "modified"):
        result.add_argument(f"--{kind}-start", help="Inclusive UTC date or ISO-8601 timestamp")
        result.add_argument(f"--{kind}-end", help="Inclusive UTC date or ISO-8601 timestamp")
    result.add_argument("--fields", help="Comma-separated output fields (file exports only)")
    result.add_argument(
        "--filter",
        action="append",
        default=[],
        metavar="FIELD=REGEX",
        help="Local regex search on a normalized field; repeat to require all matches",
    )
    result.add_argument("--limit", type=int, help="Maximum matching records to store")
    result.add_argument("--page-size", type=int, default=2000, help="NVD page size (1–2000)")
    result.add_argument("--batch-size", type=int, default=500, help="Database rows per transaction")
    result.add_argument("--timeout", type=float, default=60, help="HTTP timeout in seconds")
    result.add_argument(
        "--retries", type=int, default=5, help="Retries for network/429/5xx failures"
    )
    result.add_argument(
        "--quiet", action=argparse.BooleanOptionalAction, default=False, help="Only print errors"
    )
    return result


def parse_date(value: str, *, end: bool = False) -> datetime:
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        parsed = datetime.combine(
            datetime.fromisoformat(value).date(), time(23, 59, 59, 999000) if end else time.min
        )
    else:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    parsed = parsed.astimezone(timezone.utc)
    if parsed.microsecond % 1000:
        raise ValueError("Dates support at most millisecond precision")
    return parsed


def queries(args: argparse.Namespace) -> list[dict[str, Any]]:
    base: dict[str, Any] = {}
    if args.cve_id:
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", args.cve_id):
            raise ValueError("CVE ID must look like CVE-2021-44228")
        base["cveId"] = args.cve_id
    if args.keyword:
        base["keywordSearch"] = args.keyword
    active = []
    for kind, prefix in (("published", "pub"), ("modified", "lastMod")):
        start, end = getattr(args, f"{kind}_start"), getattr(args, f"{kind}_end")
        if bool(start) != bool(end):
            raise ValueError(f"--{kind}-start and --{kind}-end must be provided together")
        if start:
            active.append((prefix, parse_date(start), parse_date(end, end=True)))
    if len(active) > 1:
        raise ValueError("Choose either a published or modified date range per export")
    if not active:
        return [base]
    prefix, start, end = active[0]
    return [
        {
            **base,
            f"{prefix}StartDate": begin.isoformat(timespec="milliseconds"),
            f"{prefix}EndDate": stop.isoformat(timespec="milliseconds"),
        }
        for begin, stop in date_windows(start, end)
    ]


def filters(values: Sequence[str]) -> list[tuple[str, re.Pattern[str]]]:
    result = []
    for value in values:
        key, separator, pattern = value.partition("=")
        if not separator or key not in FIELDS:
            raise ValueError(f"Filter must be FIELD=REGEX; fields: {', '.join(FIELDS)}")
        try:
            result.append((key, re.compile(pattern)))
        except re.error as error:
            raise ValueError(f"Invalid regex for {key}: {error}") from None
    return result


def main(argv: Sequence[str] | None = None) -> int:
    argument_parser = parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    preliminary = argparse.ArgumentParser(add_help=False)
    preliminary.add_argument("--config", default=os.getenv("NVD_CONFIG"))
    preliminary.add_argument("--init-config")
    known, _ = preliminary.parse_known_args(arguments)
    try:
        if known.config and not known.init_config:
            argument_parser.set_defaults(**load_config(Path(known.config)))
        argument_parser.set_defaults(
            **{field: os.environ[name] for name, field in ENVIRONMENT.items() if name in os.environ}
        )
        if any(arg == "--filter" or arg.startswith("--filter=") for arg in arguments):
            argument_parser.set_defaults(filter=[])
    except ValueError as error:
        argument_parser.error(str(error))
    args = argument_parser.parse_args(arguments)
    if args.init_config:
        try:
            write_template(Path(args.init_config))
        except OSError:
            print(
                "Error: cannot create configuration; file may already exist or be unwritable",
                file=sys.stderr,
            )
            return 1
        print(f"Created {args.init_config}. Run: nvd-export --config {args.init_config}")
        return 0
    try:
        if args.format not in FORMATS:
            raise ValueError("NVD_FORMAT must be csv, json, jsonl, sqlite, or database")
        if not 1 <= args.page_size <= 2000:
            raise ValueError("--page-size must be between 1 and 2000")
        if args.limit is not None and args.limit < 1:
            raise ValueError("--limit must be positive")
        if args.batch_size < 1 or args.retries < 0:
            raise ValueError("--batch-size must be positive and --retries must be nonnegative")
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ValueError("--timeout must be a positive finite number")
        if not 1 <= args.sync_overlap <= 86400:
            raise ValueError("--sync-overlap must be between 1 and 86400 seconds")
        if args.reset_sync and not args.sync:
            raise ValueError("--reset-sync requires --sync")
        if args.sync:
            if args.format not in {"sqlite", "database"}:
                raise ValueError("--sync requires --format sqlite or database")
            if any(
                (
                    args.cve_id,
                    args.keyword,
                    args.filter,
                    args.fields,
                    args.limit,
                    args.published_start,
                    args.published_end,
                    args.modified_start,
                    args.modified_end,
                )
            ):
                raise ValueError(
                    "--sync maintains a complete database; filters, fields, limits, "
                    "and manual date ranges require --no-sync"
                )
        query_list = queries(args)
        local_filters = filters(args.filter)
        fields = [field.strip() for field in args.fields.split(",")] if args.fields else None
        if fields and (not set(fields) <= set(FIELDS) or len(fields) != len(set(fields))):
            raise ValueError(f"--fields must contain unique names from: {', '.join(FIELDS)}")
        if args.format in {"database", "sqlite"} and fields:
            raise ValueError("--fields applies only to CSV/JSON/JSONL exports")
        if args.format == "database":
            if not args.database_url or args.output:
                raise ValueError(
                    "--format database requires --database-url and does not accept --output"
                )
        elif args.database_url:
            raise ValueError("Set --format database to use --database-url / NVD_DATABASE_URL")
    except ValueError as error:
        argument_parser.error(str(error))

    logging.basicConfig(
        level=logging.ERROR if args.quiet else logging.INFO, format="%(levelname)s: %(message)s"
    )
    client = NvdClient(
        api_key=args.api_key,
        page_size=min(args.page_size, args.limit or args.page_size),
        timeout=args.timeout,
        retries=args.retries,
    )

    def records() -> Iterator[dict[str, Any]]:
        for query in query_list:
            for cve in client.iter_cves(query):
                record = normalize(cve)
                if all(
                    regex.search(str(cell(record[key]) if record[key] is not None else ""))
                    for key, regex in local_filters
                ):
                    yield record

    try:
        selected = islice(records(), args.limit) if args.limit else records()
        if args.sync:
            url = (
                args.database_url
                if args.format == "database"
                else URL.create(
                    "sqlite",
                    database=str(
                        Path(args.output or "cve_information.sqlite3").expanduser().absolute()
                    ),
                )
            )
            count = sync_database(
                client,
                url,
                args.table,
                batch_size=args.batch_size,
                overlap=args.sync_overlap,
                reset=args.reset_sync,
            )
        elif args.format == "database":
            count = write_database(selected, args.database_url, args.table, args.batch_size)
        else:
            suffix = "sqlite3" if args.format == "sqlite" else args.format
            path = Path(args.output or f"cve_information.{suffix}").expanduser()
            if args.format == "sqlite":
                url = URL.create("sqlite", database=str(path.absolute()))
                count = write_database(selected, url, args.table, args.batch_size)
            else:
                count = write_file(selected, path, args.format, fields)
        LOG.info("Stored %d CVE records", count)
        return 0
    except (SQLAlchemyError, ImportError):
        # Driver errors may contain credentials, URLs, SQL, or source CVE data.
        print(
            "Error: database operation failed; check the connection, permissions, table schema, "
            "and installed driver extras. Earlier committed batches are retained.",
            file=sys.stderr,
        )
        return 1
    except (NvdError, SyncError, ValueError, OSError) as error:
        # Never echo connection URLs or API keys supplied by the caller.
        message = str(error)
        for secret in (args.api_key, args.database_url):
            if secret:
                message = message.replace(secret, "[redacted]")
        print(f"Error: {message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(
            "Interrupted. Existing file exports and committed database batches are retained.",
            file=sys.stderr,
        )
        return 130
    finally:
        client.close()
