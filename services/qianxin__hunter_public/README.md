# QiAnXin Hunter Public API

This read-only service exposes Hunter account information, asset search, and batch-search APIs through OctoBus.

Import the service root from the repository distribution package:

```bash
octobus service import qianxin-hunter-public ./services/qianxin__hunter_public
```

Configure a non-secret API endpoint if needed:

```json
{"api_base":"https://hunter.qianxin.com/openApi","timeout_ms":15000}
```

Set the Hunter credential only in the instance secret:

```json
{"api_key":"REDACTED"}
```

The service never accepts a credential from an RPC request and never logs the key, the authenticated request URL, or the upstream response body. Hunter's public API requires the credential in its `api-key` query parameter; the implementation limits that unavoidable exposure to the upstream request and redacts credentials from returned data and errors. It supports `skip_tls_verify` only through a per-request undici dispatcher; it does not alter global Node TLS state.

Methods:

- `hunter.v1.HunterService/GetUserInfo`
- `hunter.v1.HunterService/Search`
- `hunter.v1.HunterService/BatchSearch`

`Search.search` and the non-file `BatchSearch.search` fields use Hunter query syntax and are base64url-encoded for the upstream request. `BatchSearch.file_content` is sent directly as an in-memory multipart blob; no temporary file is created.

The service retries an upstream 429 at most twice, honours a bounded `Retry-After` value, and maps the final rate limit to `UNAVAILABLE`.
