import pytest

azul_runner = pytest.importorskip("azul_runner", exc_type=ImportError)
TestPlugin = pytest.importorskip("azul_runner.test_utils", exc_type=ImportError).TestPlugin

from azul_plugin_opencti.main import AzulPluginOpenCTI


def make_fake_binary() -> bytes:
    """Return a tiny binary sample for plugin test execution."""
    return b"MZ\x90\x00opencti-test-binary"


class BaseOpenCTITest(TestPlugin):
    PLUGIN_TO_TEST = AzulPluginOpenCTI
    PLUGIN_TO_TEST_CONFIG = {
        "opencti_url": "https://opencti.example",
        "opencti_token": "test-token",
        "request_timeout": 5,
        "api_retry_count": 0,
        "result_limit": 10,
        "assume_streams_available": False,
        "filter_data_types": {},
    }

    @pytest.fixture(autouse=True)
    def _httpx_mock_fixture(self, httpx_mock):
        self.httpx_mock = httpx_mock
        return httpx_mock
