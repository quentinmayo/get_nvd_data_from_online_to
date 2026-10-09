# get_nvd_data_from_online_to

Download National Vulnerability Database (NVD) CVEs and store them where you choose: **CSV, JSON, JSONL, SQLite, PostgreSQL, or MySQL**.

Version 2 replaces the original XML-to-CSV script with the [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities), a packaged Python CLI, streamed exports, and repeatable database imports. The former repository name was `get_nvd_data_from_online_to_csv`.

## Install

Requires **Python 3.10 or newer**. SQLite needs no separate database server.

```sh
git clone https://github.com/quentinmayo/get_nvd_data_from_online_to.git
cd get_nvd_data_from_online_to
python -m venv .venv
source .venv/bin/activate
python -m pip install .
```

On Windows PowerShell, activate with `.\.venv\Scripts\Activate.ps1` instead.

```sh
nvd-export --help
nvd-export --cve-id CVE-2021-44228 --output ./data/example.csv
```

You can also use `python -m nvd_exporter` or the original `python get_nvd_data_from_online.py` entry point after installing dependencies.

## Choose where data is stored

Relative paths resolve from your current directory. Absolute paths, mounted drives, network-mounted folders, spaces, and `~` are supported. Missing parent folders are created automatically. `--output` names a **file**, not a directory.

| Destination | Command | Default file |
| --- | --- | --- |
| CSV | `nvd-export --format csv --output ./data/cves.csv` | `cve_information.csv` |
| JSON array | `nvd-export --format json --output ./data/cves.json` | `cve_information.json` |
| JSON Lines | `nvd-export --format jsonl --output ./data/cves.jsonl` | `cve_information.jsonl` |
| SQLite | `nvd-export --format sqlite --output ./data/nvd.sqlite3` | `cve_information.sqlite3` |
| PostgreSQL / MySQL | `nvd-export --format database --database-url '…'` | No default; URL required |

Without filters, these commands fetch the **entire NVD CVE collection**. Use `--cve-id`, a date range, or `--limit 100` for a smaller first run. The format is explicit; it is not inferred from the filename.

For example, write to an external drive:

```sh
nvd-export --format sqlite --output '/Volumes/Security Data/nvd.sqlite3'
```

### PostgreSQL

Install the optional driver and create an empty database on your PostgreSQL server:

```sh
python -m pip install '.[postgres]'
export NVD_DATABASE_URL='postgresql+psycopg://nvd_user:password@localhost:5432/nvd'
nvd-export --format database --cve-id CVE-2021-44228
```

### MySQL

Use MySQL 8 or newer and a database configured for `utf8mb4`:

```sh
python -m pip install '.[mysql]'
export NVD_DATABASE_URL='mysql+pymysql://nvd_user:password@localhost:3306/nvd?charset=utf8mb4'
nvd-export --format database --cve-id CVE-2021-44228
```

Plain `postgresql://` and `mysql://` URLs select the same drivers automatically. URL-encode special characters in credentials. The server and database must already exist; the exporter creates the table. Connection/TLS parameters can be included in the [SQLAlchemy connection URL](https://docs.sqlalchemy.org/en/20/core/engines.html#database-urls).

The default table is `nvd_cves`; change it with `--table vulnerability_archive`. Table names may contain 1–63 letters, digits, or underscores and must begin with a letter or underscore. The database user needs table creation and insert/update permissions. Other database engines and cloud object stores are not implemented.

### Environment variables

| Variable | Purpose |
| --- | --- |
| `NVD_API_KEY` | Optional NVD API key |
| `NVD_FORMAT` | Default output format; otherwise `csv` |
| `NVD_OUTPUT` | Default destination file path |
| `NVD_DATABASE_URL` | Database connection string; requires `--format database` |

Explicit command-line options override the corresponding environment variables. `.env` files are **not** loaded automatically. Unset `NVD_OUTPUT` when switching to database mode, and unset `NVD_DATABASE_URL` when switching to a file destination. Conflicting destination settings are rejected rather than silently ignored.

PowerShell example:

```powershell
$env:NVD_API_KEY = 'your-api-key'
nvd-export --format sqlite --output 'D:\Security Data\nvd.sqlite3'
```

## Select records and fields

Search descriptions with NVD's keyword filter:

```sh
nvd-export --keyword 'apache' --limit 100 --output ./data/apache.csv
```

Export CVEs published during a year:

```sh
nvd-export --published-start 2025-01-01 --published-end 2025-12-31 \
  --format jsonl --output ./data/published-2025.jsonl
```

Refresh an existing database with recently modified records:

```sh
nvd-export --modified-start 2026-10-01 --modified-end 2026-10-09 \
  --format sqlite --output ./data/nvd.sqlite3
```

Start and end must be supplied together. Choose either publication or modification dates per run. Date-only values include the entire UTC day; ISO-8601 timestamps accept explicit timezone offsets and up to millisecond precision. Long ranges are automatically split into requests covering at most 120 days. Publication dates are NVD publication dates, which can differ from the year in a CVE identifier.

Choose file columns and apply local regular-expression filters:

```sh
nvd-export --keyword apache --filter 'cvss_severity=^(HIGH|CRITICAL)$' \
  --fields cve_id,published,cvss_score,description --output ./data/critical.csv
```

Repeat `--filter FIELD=REGEX` to require multiple matches. Filters use Python's case-sensitive `re.search`; use `(?i)` for case-insensitive matching. `--limit` counts records **after** local filtering. Local filters may require downloading more records than the limit; prefer API filters when possible. `--fields` is available for CSV, JSON, and JSONL, while databases always retain the full schema.

## Data schema

Each record contains these normalized fields:

| Fields | Meaning |
| --- | --- |
| `cve_id` | CVE identifier; database primary key |
| `source_identifier`, `status` | Source and NVD vulnerability status |
| `published`, `last_modified` | NVD UTC timestamps, stored as ISO strings |
| `description` | English description, falling back to the first available language |
| `cvss_version`, `cvss_score`, `cvss_severity`, `cvss_vector` | Preferred available CVSS metric: 4.0, then 3.1, 3.0, 2.0; prefer a Primary metric within that version |
| `weaknesses`, `references`, `cpes` | Lists of weakness identifiers, reference URLs, and vulnerable CPE match criteria |
| `raw` | Complete source CVE JSON, including all metrics, applicability logic, and version ranges |

Missing optional values become JSON/SQL nulls, empty lists, or an empty description. CSV uses empty cells for nulls and JSON text for lists. CSV omits `raw` by default; request it with `--fields` when needed. JSON, JSONL, and databases include it by default.

The flattened `cpes` list is a convenience summary. Use `raw.configurations` to interpret affected versions, AND/OR logic, negation, and non-vulnerable environmental requirements. CVSS summaries are not a replacement for reviewing all source metrics.

## Reliability and repeat imports

- Downloads are paginated and processed incrementally, without loading the whole collection into memory.
- CSV/JSON/JSONL exports replace the destination only after a successful complete run. Failed or interrupted runs remove their temporary file and preserve any previous export. A successful empty export replaces the file with an empty result. Force-killing a process may leave a hidden `.tmp` file beside the destination.
- Databases upsert by `cve_id`: importing a CVE again replaces that row with the downloaded record. Rows outside the selected query remain. Rerunning a failed query is safe from duplicate rows; no automatic resume cursor is maintained.
- Database writes commit in batches of 500 rows (`--batch-size`). Earlier batches remain if a later download or write fails; the current transaction rolls back on a write error. Existing tables must have this schema; automatic schema migrations are not provided.
- HTTPS certificate verification stays enabled. Network failures, HTTP 429, and HTTP 5xx receive up to five retries with backoff and `Retry-After` support. Other HTTP errors fail with a nonzero exit status.
- Requests are spaced at least 6.1 seconds apart without a key, or 0.65 seconds with one. Multiple processes sharing an API key/IP must coordinate their request rate. See [NVD API guidance](https://nvd.nist.gov/developers/start-here) and [request an API key](https://nvd.nist.gov/developers/request-an-api-key).
- Tune `--timeout` (default 60 seconds), `--retries` (5), and `--page-size` (2000). `--quiet` hides progress. Exit codes: `0` success, `1` export failure, `2` invalid command arguments, `130` interrupted.

For recurring updates, track your own last successful modified-date window and overlap it slightly on the next run. The NVD is a live dataset, so a long export is not a transactional snapshot; run a modified-date refresh after a full import. Rejected CVEs are retained with their NVD status.

## Migrating from version 1

Python 2/3.7, XML feeds, BeautifulSoup, and the old XML mapping API have been removed. This is a major-version change with a new output schema.

| Old usage | Version 2 |
| --- | --- |
| `python get_nvd_data_from_online.py` | Still supported; installed `nvd-export` is preferred |
| `-cve_information_path file.csv` | Still accepted as an alias for `--output file.csv` |
| `-date_range_string '2025\|2025'` | `--published-start 2025-01-01 --published-end 2025-12-31` (publication dates, not CVE-ID year) |
| `-data_map_string ...` | `--fields cve_id,description,...` using normalized field names |
| `-custom_filter_string 'CVE[\|]2025'` | `--filter 'cve_id=2025'` (regex search; use `^` to anchor) |
| Importing the old `get_nvd_data_from_online(...)` function | Compose `NvdClient.iter_cves`, `normalize`, and a storage writer |

After the repository rename, update an existing clone:

```sh
git remote set-url origin https://github.com/quentinmayo/get_nvd_data_from_online_to.git
git fetch origin
git switch main
```

## Development

```sh
python -m pip install -e '.[dev,postgres,mysql]'
ruff check .
ruff format --check .
pytest
python -m build
```

Unit tests use local fixtures and mocked HTTP. Server integration tests skip unless `TEST_POSTGRES_URL` and/or `TEST_MYSQL_URL` point to disposable test databases; they create and remove uniquely named tables. CI runs Python 3.10, 3.12, and 3.14 tests plus PostgreSQL 17 and MySQL 8.4 integration tests.

To add another destination, implement an iterator-consuming writer in `nvd_exporter/storage.py`, expose its options in the CLI, and add persistence/failure tests. Do not assume all SQLAlchemy dialects support the same upsert syntax.

## Data attribution

This product uses data from the NVD API but is not endorsed or certified by the NVD. See [NVD terms of use](https://nvd.nist.gov/developers/terms-of-use).
