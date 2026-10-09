"""A stable, queryable summary alongside the complete source CVE."""

from typing import Any

FIELDS = (
    "cve_id",
    "source_identifier",
    "published",
    "last_modified",
    "status",
    "description",
    "cvss_version",
    "cvss_score",
    "cvss_severity",
    "cvss_vector",
    "weaknesses",
    "references",
    "cpes",
    "raw",
)
CSV_FIELDS = FIELDS[:-1]


def normalize(cve: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(cve.get("id"), str) or not cve["id"]:
        raise ValueError("NVD record is missing its CVE ID")
    metric: dict[str, Any] = {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        candidates = cve.get("metrics", {}).get(key, [])
        if candidates:
            metric = next(
                (item for item in candidates if item.get("type") == "Primary"), candidates[0]
            )
            break
    cvss = metric.get("cvssData", {})
    descriptions = cve.get("descriptions", [])
    description = next(
        (item["value"] for item in descriptions if item.get("lang") == "en"),
        descriptions[0].get("value", "") if descriptions else "",
    )
    cpes: set[str] = set()

    def visit(node: dict[str, Any]) -> None:
        for match in node.get("cpeMatch", []):
            if match.get("vulnerable") and match.get("criteria"):
                cpes.add(match["criteria"])
        for child in node.get("nodes", []) + node.get("children", []):
            visit(child)

    for configuration in cve.get("configurations", []):
        visit(configuration)
    return {
        "cve_id": cve["id"],
        "source_identifier": cve.get("sourceIdentifier"),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description": description,
        "cvss_version": cvss.get("version"),
        "cvss_score": cvss.get("baseScore"),
        "cvss_severity": cvss.get("baseSeverity", metric.get("baseSeverity")),
        "cvss_vector": cvss.get("vectorString"),
        "weaknesses": sorted(
            {
                d["value"]
                for w in cve.get("weaknesses", [])
                for d in w.get("description", [])
                if d.get("lang") == "en"
            }
        ),
        "references": sorted({r["url"] for r in cve.get("references", []) if r.get("url")}),
        "cpes": sorted(cpes),
        "raw": cve,
    }
