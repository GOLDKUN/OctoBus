# QiAnXin SecGate3600 Security Policy

OctoBus service package for managing security policies on the QiAnXin (网神) SecGate3600 firewall.

## Import

```bash
octobus service import --id qianxin-fw-secgate3600-policy ./services/qianxin__fw-secgate3600-policy
```

## Configuration

Set `host` to the firewall base URL. `timeoutMs` defaults to 5000. Responses are
limited to 1 MiB by default (and never more than 5 MiB), redirects are rejected,
and TLS verification remains enabled unless `skipTlsVerify` is explicitly set.

```json
{
  "host": "https://secgate3600.example.com:8443",
  "timeoutMs": 5000,
  "maxResponseBytes": 1048576
}
```

Secret: `username` and `password` for session-based authentication.

```json
{
  "username": "admin",
  "password": "secret"
}
```

## Behavior

Session management uses `POST /v1.0/login` to obtain a `PHPSESSID` cookie and
token. Sessions are isolated per OctoBus instance, expire after 30 minutes, and
use bounded LRU caches (128 instances × 8 endpoints). Cookies, tokens,
authorization headers, and raw login bodies are never reflected in RPC results.
`POST /v1.0/out` is called on logout.

- `Login` establishes a session explicitly; other methods require an active session.
- `ListSecPolicy` calls `POST /v1.0/rest/` with `module=sec_policy&func=get_sec_policy`. Returns the policy list as Struct.
- `SetSecPolicy` calls `POST /v1.0/rest/` with `module=sec_policy&func=set_sec_policy`. Requires `action` and policy fields.
- `MoveSecPolicyPriority` calls `POST /v1.0/rest/` with `module=sec_policy&func=set_move_sec_policy_pri`. Requires `id` and `direct` (`top`, `end`, `before`, `after`).
- `Logout` clears the session cache and calls `POST /v1.0/out`.
- Missing host or credentials returns `INVALID_ARGUMENT`. Network errors and 5xx map to `UNAVAILABLE`; malformed upstream responses map to `UNKNOWN`; over-limit responses map to `RESOURCE_EXHAUSTED`.

## Evidence boundary

This package contains no screenshots, device exports, archives, credentials, or
captured traffic. The committed evidence is deterministic mock-based validation
only; live-device compatibility must be confirmed separately with sanitized
operator evidence before production use.

## Local Checks

```bash
cd services
npm run validate -- --service-dir qianxin__fw-secgate3600-policy
npm test -- --service-dir qianxin__fw-secgate3600-policy --coverage
npm run pack:check
```
