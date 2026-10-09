import pytest


@pytest.fixture
def cve():
    return {
        "id": "CVE-2024-12345",
        "sourceIdentifier": "security@example.com",
        "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-02-01T00:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {"lang": "es", "value": "otro"},
            {"lang": "en", "value": "Example, with a newline\nand Unicode: café"},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    },
                }
            ]
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
        "references": [{"url": "https://example.com/advisory"}],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*",
                            },
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:o:example:os:*:*:*:*:*:*:*:*",
                            },
                        ]
                    }
                ]
            }
        ],
    }
