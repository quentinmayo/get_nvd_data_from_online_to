from nvd_exporter.records import normalize


def test_full_record(cve):
    record = normalize(cve)
    assert record["description"].endswith("café")
    assert record["cvss_score"] == 9.8
    assert record["weaknesses"] == ["CWE-79"]
    assert len(record["cpes"]) == 1
    assert record["raw"] == cve


def test_missing_optional_data():
    record = normalize({"id": "CVE-2024-12345"})
    assert record["cvss_score"] is None
    assert record["description"] == ""
    assert record["cpes"] == []


def test_cvss_preference(cve):
    cve["metrics"]["cvssMetricV40"] = [
        {"type": "Secondary", "cvssData": {"version": "4.0", "baseScore": 5}},
        {"type": "Primary", "cvssData": {"version": "4.0", "baseScore": 8}},
    ]
    assert normalize(cve)["cvss_score"] == 8
    assert normalize(cve)["cvss_version"] == "4.0"


def test_cvss_v2_severity(cve):
    cve["metrics"] = {
        "cvssMetricV2": [{"baseSeverity": "HIGH", "cvssData": {"version": "2.0", "baseScore": 10}}]
    }
    assert normalize(cve)["cvss_severity"] == "HIGH"
