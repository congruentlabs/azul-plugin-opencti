# OpenCTI Plugin

Azul plugin for checking whether a binary is known to an OpenCTI instance as a file observable or indicator.

The plugin performs exact hash lookups against OpenCTI using direct GraphQL requests over `httpx`. It does not depend on
`pycti`, keeping the runtime dependency surface small.

## Features

- Searches OpenCTI by SHA-256, SHA-1, and MD5 when those hashes are available on the Azul binary record
- Adds a positive or negative `cti_known_ioc` feature
- Adds matched OpenCTI observable IDs, indicator IDs, indicator names, indicator patterns, labels, scores, confidence
  values, and external references
- Processes binary records without downloading or uploading the file body to OpenCTI

## Configuration

Required configuration:

- `opencti_url`: OpenCTI base URL, for example `https://opencti.example`
- `opencti_token`: OpenCTI API token

Optional configuration:

- `request_timeout`: HTTP request timeout in seconds. Default: `30`
- `api_retry_count`: Number of HTTP transport retries. Default: `3`
- `result_limit`: Maximum observables and indicators returned for each hash query. Default: `25`

## Output Features

- `cti_known_ioc`
- `cti_match_count`
- `cti_matched_hash`
- `cti_observable_id`
- `cti_observable_value`
- `cti_indicator_id`
- `cti_indicator_name`
- `cti_indicator_pattern`
- `cti_score`
- `cti_confidence`
- `cti_label`
- `cti_external_reference`
