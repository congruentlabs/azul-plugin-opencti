import json

import pytest

from azul_plugin_opencti.opencti import OpenCTIClient, OpenCTIError


def test_search_hashes_queries_opencti_for_each_available_hash(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://opencti.example/graphql",
        json={
            "data": {
                "stixCyberObservables": {
                    "edges": [
                        {
                            "node": {
                                "id": "observable--sha256",
                                "entity_type": "File",
                                "observable_value": "abc",
                                "x_opencti_score": 80,
                                "objectLabel": {"edges": [{"node": {"value": "malware"}}]},
                            }
                        }
                    ]
                },
                "indicators": {"edges": []},
            }
        },
    )
    httpx_mock.add_response(
        method="POST",
        url="https://opencti.example/graphql",
        json={
            "data": {
                "stixCyberObservables": {"edges": []},
                "indicators": {
                    "edges": [
                        {
                            "node": {
                                "id": "indicator--sha1",
                                "name": "Known malware hash",
                                "pattern": "[file:hashes.'SHA-1' = 'def']",
                                "x_opencti_score": 90,
                                "confidence": 75,
                                "revoked": False,
                                "valid_from": "2026-01-01T00:00:00.000Z",
                                "valid_until": None,
                                "objectLabel": {"edges": [{"node": {"value": "apt"}}]},
                                "externalReferences": {
                                    "edges": [
                                        {
                                            "node": {
                                                "source_name": "report",
                                                "url": "https://example.test/report",
                                            }
                                        }
                                    ]
                                },
                            }
                        }
                    ]
                },
            }
        },
    )

    client = OpenCTIClient(
        base_url="https://opencti.example",
        token="secret-token",
        timeout=5,
        retry_count=0,
        result_limit=10,
    )

    result = client.search_hashes({"SHA-256": "abc", "SHA-1": "def", "MD5": ""})

    requests = httpx_mock.get_requests()
    assert len(requests) == 2
    assert requests[0].headers["Authorization"] == "Bearer secret-token"
    assert requests[0].headers["Content-Type"] == "application/json"
    first_payload = json.loads(requests[0].content)
    second_payload = json.loads(requests[1].content)

    assert first_payload["variables"]["observableFilters"]["filters"][0] == {
        "key": "hashes.SHA-256",
        "values": ["abc"],
        "operator": "eq",
        "mode": "or",
    }
    assert second_payload["variables"]["observableFilters"]["filters"][0]["key"] == "hashes.SHA-1"

    assert result.matched_hashes == {"SHA-256": "abc", "SHA-1": "def"}
    assert result.observables[0].id == "observable--sha256"
    assert result.observables[0].labels == ["malware"]
    assert result.indicators[0].id == "indicator--sha1"
    assert result.indicators[0].external_references == ["report: https://example.test/report"]


def test_search_hashes_raises_on_graphql_errors(httpx_mock):
    httpx_mock.add_response(
        method="POST",
        url="https://opencti.example/graphql",
        json={"errors": [{"message": "Field does not exist"}]},
    )

    client = OpenCTIClient(
        base_url="https://opencti.example",
        token="secret-token",
        timeout=5,
        retry_count=0,
        result_limit=10,
    )

    with pytest.raises(OpenCTIError, match="Field does not exist"):
        client.search_hashes({"SHA-256": "abc"})
