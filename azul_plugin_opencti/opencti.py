"""OpenCTI GraphQL client helpers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

OPENCTI_HASH_KEYS = {
    "SHA-256": "hashes.SHA-256",
    "SHA-1": "hashes.SHA-1",
    "MD5": "hashes.MD5",
}


class OpenCTIError(RuntimeError):
    """Raised when OpenCTI returns a GraphQL-level error."""


@dataclass(frozen=True)
class OpenCTIObservable:
    """A matching OpenCTI observable."""

    id: str
    entity_type: str
    observable_value: str
    score: int | None = None
    labels: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class OpenCTIIndicator:
    """A matching OpenCTI indicator."""

    id: str
    name: str
    pattern: str
    score: int | None = None
    confidence: int | None = None
    revoked: bool | None = None
    valid_from: str | None = None
    valid_until: str | None = None
    labels: list[str] = field(default_factory=list)
    external_references: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class OpenCTIHashSearchResult:
    """Normalized result for one or more hash searches."""

    matched_hashes: dict[str, str] = field(default_factory=dict)
    observables: list[OpenCTIObservable] = field(default_factory=list)
    indicators: list[OpenCTIIndicator] = field(default_factory=list)

    @property
    def has_matches(self) -> bool:
        """Return whether OpenCTI had any observable or indicator matches."""
        return bool(self.observables or self.indicators)


class OpenCTIClient:
    """Small GraphQL client for exact binary hash lookups in OpenCTI."""

    HASH_LOOKUP_QUERY = """
    query AzulOpenCTIHashLookup(
      $observableFilters: FilterGroup
      $indicatorSearch: String
      $first: Int
    ) {
      stixCyberObservables(first: $first, filters: $observableFilters) {
        edges {
          node {
            id
            entity_type
            observable_value
            x_opencti_score
            objectLabel {
              edges {
                node {
                  value
                }
              }
            }
          }
        }
      }
      indicators(first: $first, search: $indicatorSearch) {
        edges {
          node {
            id
            name
            pattern
            x_opencti_score
            confidence
            revoked
            valid_from
            valid_until
            objectLabel {
              edges {
                node {
                  value
                }
              }
            }
            externalReferences {
              edges {
                node {
                  source_name
                  url
                }
              }
            }
          }
        }
      }
    }
    """

    def __init__(
        self,
        *,
        base_url: str,
        token: str,
        timeout: int | float,
        retry_count: int,
        result_limit: int,
    ) -> None:
        self.base_url = str(httpx.URL(base_url)).rstrip("/")
        self.result_limit = int(result_limit)
        self.client = httpx.Client(
            base_url=self.base_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            transport=httpx.HTTPTransport(retries=int(retry_count)),
            timeout=timeout,
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self.client.close()

    def __enter__(self) -> "OpenCTIClient":
        """Return the client for context manager use."""
        return self

    def __exit__(self, *args: object) -> None:
        """Close the underlying HTTP client on context manager exit."""
        self.close()

    def search_hashes(self, hashes: dict[str, str | None]) -> OpenCTIHashSearchResult:
        """Search OpenCTI for supported hash values."""
        matched_hashes: dict[str, str] = {}
        observables: dict[str, OpenCTIObservable] = {}
        indicators: dict[str, OpenCTIIndicator] = {}

        for algorithm, value in hashes.items():
            if not value or algorithm not in OPENCTI_HASH_KEYS:
                continue

            response = self.client.post(
                "/graphql",
                json={
                    "query": self.HASH_LOOKUP_QUERY,
                    "variables": {
                        "observableFilters": self._hash_filter(algorithm, value),
                        "indicatorSearch": value,
                        "first": self.result_limit,
                    },
                },
            )
            response.raise_for_status()
            payload = response.json()
            if errors := payload.get("errors"):
                messages = ", ".join(str(error.get("message", error)) for error in errors)
                raise OpenCTIError(messages)

            data = payload.get("data") or {}
            current_observables = self._parse_observables(data.get("stixCyberObservables"))
            current_indicators = self._parse_indicators(data.get("indicators"))

            if current_observables or current_indicators:
                matched_hashes[algorithm] = value
            for observable in current_observables:
                observables[observable.id] = observable
            for indicator in current_indicators:
                indicators[indicator.id] = indicator

        return OpenCTIHashSearchResult(
            matched_hashes=matched_hashes,
            observables=list(observables.values()),
            indicators=list(indicators.values()),
        )

    @staticmethod
    def _hash_filter(algorithm: str, value: str) -> dict[str, Any]:
        return {
            "mode": "and",
            "filters": [
                {
                    "key": OPENCTI_HASH_KEYS[algorithm],
                    "values": [value],
                    "operator": "eq",
                    "mode": "or",
                }
            ],
            "filterGroups": [],
        }

    @staticmethod
    def _edge_nodes(connection: dict[str, Any] | None) -> list[dict[str, Any]]:
        if not connection:
            return []
        return [edge.get("node") or {} for edge in connection.get("edges") or []]

    @classmethod
    def _labels(cls, node: dict[str, Any]) -> list[str]:
        return sorted(
            label.get("value", "") for label in cls._edge_nodes(node.get("objectLabel")) if label.get("value")
        )

    @classmethod
    def _parse_observables(cls, connection: dict[str, Any] | None) -> list[OpenCTIObservable]:
        observables = []
        for node in cls._edge_nodes(connection):
            observables.append(
                OpenCTIObservable(
                    id=node.get("id", ""),
                    entity_type=node.get("entity_type", ""),
                    observable_value=node.get("observable_value", ""),
                    score=node.get("x_opencti_score"),
                    labels=cls._labels(node),
                )
            )
        return observables

    @classmethod
    def _parse_indicators(cls, connection: dict[str, Any] | None) -> list[OpenCTIIndicator]:
        indicators = []
        for node in cls._edge_nodes(connection):
            indicators.append(
                OpenCTIIndicator(
                    id=node.get("id", ""),
                    name=node.get("name", ""),
                    pattern=node.get("pattern", ""),
                    score=node.get("x_opencti_score"),
                    confidence=node.get("confidence"),
                    revoked=node.get("revoked"),
                    valid_from=node.get("valid_from"),
                    valid_until=node.get("valid_until"),
                    labels=cls._labels(node),
                    external_references=cls._external_references(node),
                )
            )
        return indicators

    @classmethod
    def _external_references(cls, node: dict[str, Any]) -> list[str]:
        refs = []
        for ref in cls._edge_nodes(node.get("externalReferences")):
            source = ref.get("source_name")
            url = ref.get("url")
            if source and url:
                refs.append(f"{source}: {url}")
            elif source:
                refs.append(source)
            elif url:
                refs.append(url)
        return sorted(refs)
