"""Search OpenCTI for binary hash indicators and add the results as Azul features."""

import logging
import traceback
from typing import Any, cast

import httpx
from azul_runner import BinaryPlugin, Feature, FeatureType, Job, State, add_settings, cmdline_run

from .opencti import OpenCTIClient, OpenCTIError, OpenCTIHashSearchResult

ftInt, ftStr = (FeatureType.Integer, FeatureType.String)
logger = logging.getLogger(__name__)


class AzulPluginOpenCTI(BinaryPlugin):
    """Search OpenCTI for binary hash indicators and add the results as Azul features."""

    VERSION = "2026.05.21"
    SETTINGS = add_settings(
        assume_streams_available=False,
        filter_data_types={},
        request_timeout=30,
        opencti_url=(str, ""),
        opencti_token=(str, ""),
        result_limit=(int, 25),
        api_retry_count=(int, 3),
    )
    FEATURES = [
        Feature("cti_known_ioc", desc="Whether OpenCTI has a matching observable or indicator", type=ftStr),
        Feature("cti_match_count", desc="Number of unique OpenCTI observables and indicators matched", type=ftInt),
        Feature("cti_matched_hash", desc="Hash values that matched in OpenCTI", type=ftStr),
        Feature("cti_observable_id", desc="OpenCTI observable IDs that matched the binary", type=ftStr),
        Feature("cti_observable_value", desc="OpenCTI observable values that matched the binary", type=ftStr),
        Feature("cti_indicator_id", desc="OpenCTI indicator IDs that matched the binary", type=ftStr),
        Feature("cti_indicator_name", desc="OpenCTI indicator names that matched the binary", type=ftStr),
        Feature("cti_indicator_pattern", desc="OpenCTI indicator patterns that matched the binary", type=ftStr),
        Feature("cti_score", desc="OpenCTI score values from matching objects", type=ftInt),
        Feature("cti_confidence", desc="OpenCTI confidence values from matching indicators", type=ftInt),
        Feature("cti_label", desc="OpenCTI labels attached to matching objects", type=ftStr),
        Feature("cti_external_reference", desc="External references attached to matching indicators", type=ftStr),
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        cfg = cast(Any, self.cfg)
        opencti_url = cfg.opencti_url
        opencti_token = cfg.opencti_token
        if not opencti_url:
            raise RuntimeError("OpenCTI URL must be set")
        if not httpx.URL(opencti_url).is_absolute_url:
            raise RuntimeError(f"Unable to use OpenCTI with URL '{opencti_url}'")
        if not opencti_token:
            raise RuntimeError("OpenCTI API token must be set")

        for cfg_var in ("request_timeout", "result_limit", "api_retry_count"):
            try:
                setattr(self.cfg, cfg_var, int(getattr(self.cfg, cfg_var)))
            except ValueError as e:
                raise ValueError(f"Config setting {cfg_var} must be an int value") from e

    def execute(self, job: Job):
        """Run the plugin."""
        try:
            return self.execute_body(job)
        except httpx.HTTPError as exc:
            return State(State.Label.ERROR_NETWORK, exc.args[0], "".join(traceback.format_exc()))
        except OpenCTIError as exc:
            return State(State.Label.ERROR_EXCEPTION, exc.args[0], "".join(traceback.format_exc()))

    def execute_body(self, job: Job):
        """Search OpenCTI and add normalized match details to the binary record."""
        hashes = self._job_hashes(job)
        if not any(hashes.values()):
            return State(State.Label.OPT_OUT, message="No supported binary hashes were available for OpenCTI lookup")

        with OpenCTIClient(
            base_url=cast(Any, self.cfg).opencti_url,
            token=cast(Any, self.cfg).opencti_token,
            timeout=self.cfg.request_timeout,
            retry_count=cast(Any, self.cfg).api_retry_count,
            result_limit=cast(Any, self.cfg).result_limit,
        ) as client:
            result = client.search_hashes(hashes)

        self._add_result_features(result)
        return State(State.Label.COMPLETED)

    @staticmethod
    def _job_hashes(job: Job) -> dict[str, str | None]:
        entity = job.event.entity
        return {
            "SHA-256": getattr(entity, "sha256", None),
            "SHA-1": getattr(entity, "sha1", None),
            "MD5": getattr(entity, "md5", None),
        }

    def _add_result_features(self, result: OpenCTIHashSearchResult) -> None:
        self.add_feature_values("cti_known_ioc", ["true" if result.has_matches else "false"])
        self.add_feature_values("cti_match_count", [len(result.observables) + len(result.indicators)])

        if not result.has_matches:
            return

        self.add_feature_values(
            "cti_matched_hash",
            [f"{algorithm}: {value}" for algorithm, value in result.matched_hashes.items()],
        )
        if observable_ids := [item.id for item in result.observables if item.id]:
            self.add_feature_values("cti_observable_id", observable_ids)
        if observable_values := [item.observable_value for item in result.observables if item.observable_value]:
            self.add_feature_values("cti_observable_value", observable_values)
        if indicator_ids := [item.id for item in result.indicators if item.id]:
            self.add_feature_values("cti_indicator_id", indicator_ids)
        if indicator_names := [item.name for item in result.indicators if item.name]:
            self.add_feature_values("cti_indicator_name", indicator_names)
        if indicator_patterns := [item.pattern for item in result.indicators if item.pattern]:
            self.add_feature_values("cti_indicator_pattern", indicator_patterns)

        if scores := [item.score for item in [*result.observables, *result.indicators] if item.score is not None]:
            self.add_feature_values("cti_score", scores)
        if confidences := [item.confidence for item in result.indicators if item.confidence is not None]:
            self.add_feature_values("cti_confidence", confidences)
        if labels := sorted({label for item in [*result.observables, *result.indicators] for label in item.labels}):
            self.add_feature_values("cti_label", labels)
        if references := sorted({ref for item in result.indicators for ref in item.external_references}):
            self.add_feature_values("cti_external_reference", references)


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginOpenCTI)


if __name__ == "__main__":
    main()
