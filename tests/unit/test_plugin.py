import pytest

azul_runner = pytest.importorskip("azul_runner", exc_type=ImportError)
DATA_HASH = azul_runner.DATA_HASH
FV = azul_runner.FV
Event = azul_runner.Event
JobResult = azul_runner.JobResult
State = azul_runner.State

from .common import BaseOpenCTITest, make_fake_binary


def _opencti_response(observable_edges=None, indicator_edges=None):
    return {
        "data": {
            "stixCyberObservables": {"edges": observable_edges or []},
            "indicators": {"edges": indicator_edges or []},
        }
    }


class TestOpenCTIPlugin(BaseOpenCTITest):
    def test_plugin_adds_opencti_indicator_features(self):
        data = make_fake_binary()
        file_hash = DATA_HASH(data).hexdigest()

        self.httpx_mock.add_response(
            method="POST",
            url="https://opencti.example/graphql",
            json=_opencti_response(
                indicator_edges=[
                    {
                        "node": {
                            "id": "indicator--1",
                            "name": "Known malware",
                            "pattern": f"[file:hashes.'SHA-256' = '{file_hash}']",
                            "x_opencti_score": 90,
                            "confidence": 75,
                            "revoked": False,
                            "valid_from": "2026-01-01T00:00:00.000Z",
                            "valid_until": None,
                            "objectLabel": {"edges": [{"node": {"value": "malware"}}]},
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
            ),
        )
        self.httpx_mock.add_response(method="POST", url="https://opencti.example/graphql", json=_opencti_response())
        self.httpx_mock.add_response(method="POST", url="https://opencti.example/graphql", json=_opencti_response())

        result = self.do_execution(
            data_in=[("content", data)],
            config=self.PLUGIN_TO_TEST_CONFIG,
            no_multiprocessing=True,
        )

        expected_features = {
            "cti_confidence": [FV(75)],
            "cti_external_reference": [FV("report: https://example.test/report")],
            "cti_indicator_id": [FV("indicator--1")],
            "cti_indicator_name": [FV("Known malware")],
            "cti_indicator_pattern": [FV(f"[file:hashes.'SHA-256' = '{file_hash}']")],
            "cti_known_ioc": [FV("true")],
            "cti_label": [FV("malware")],
            "cti_match_count": [FV(1)],
            "cti_matched_hash": [FV(f"SHA-256: {file_hash}")],
            "cti_score": [FV(90)],
        }

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[Event(sha256=file_hash, features=expected_features)],
            ),
        )

    def test_plugin_records_negative_lookup(self):
        data = make_fake_binary()
        file_hash = DATA_HASH(data).hexdigest()

        for _ in range(3):
            self.httpx_mock.add_response(
                method="POST",
                url="https://opencti.example/graphql",
                json=_opencti_response(),
            )

        result = self.do_execution(
            data_in=[("content", data)],
            config=self.PLUGIN_TO_TEST_CONFIG,
            no_multiprocessing=True,
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256=file_hash,
                        features={
                            "cti_known_ioc": [FV("false")],
                            "cti_match_count": [FV(0)],
                        },
                    )
                ],
            ),
        )

    def test_plugin_requires_opencti_url(self):
        with self.assertRaises(RuntimeError):
            self.do_execution(
                data_in=[("content", make_fake_binary())],
                config={**self.PLUGIN_TO_TEST_CONFIG, "opencti_url": ""},
                no_multiprocessing=True,
            )

    def test_plugin_requires_opencti_token(self):
        with self.assertRaises(RuntimeError):
            self.do_execution(
                data_in=[("content", make_fake_binary())],
                config={**self.PLUGIN_TO_TEST_CONFIG, "opencti_token": ""},
                no_multiprocessing=True,
            )
