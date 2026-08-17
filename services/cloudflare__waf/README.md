# Cloudflare WAF

OctoBus service package for Cloudflare WAF firewall operations via Cloudflare API v4.

## Import

```bash
octobus service import --id cloudflare-waf ./services/cloudflare__waf
```

## Configuration

Set `endpoint` (default `https://api.cloudflare.com/client/v4`), `zoneId`, and `accountId` as needed. `timeoutMs` (default 1500), `maxResponseBytes` (default 4 MiB; maximum 10 MiB), and `skipTlsVerify` are optional. Timeouts use `AbortSignal.timeout`; TLS bypass uses an isolated undici dispatcher and is intended only for private/proxied test gateways.

```json
{
  "zoneId": "<zone-id>",
  "timeoutMs": 3000
}
```

Secret: `apiToken` (Bearer, recommended) or `authEmail` + `authKey` (legacy global key).

```json
{
  "apiToken": "<scoped-api-token>"
}
```

## Behavior

- `BlockIP` calls `POST /…/firewall/access_rules/rules`. Duplicate targets in one request are processed once, and concurrent creation of the same scope, target, and mode is serialized within the service process before rechecking upstream. If a later create fails, the gRPC error includes `partial_created_ids` for reconciliation or safe whole-request retry.
- `UnblockIP` calls `DELETE /…/firewall/access_rules/rules/{id}`. Duplicate targets are processed once and no matching rule returns `deleted_count=0`. If a later delete fails, the gRPC error includes `partial_deleted_ids` so callers can reconcile or safely retry the whole request.
- `ListAccessRules` calls `GET /…/firewall/access_rules/rules` with optional `value`, `mode`, `page`, and `per_page` filters.
- `GetSecurityLevel` calls `GET /zones/{zone}/settings/security_level`.
- `SetSecurityLevel` calls `PATCH /zones/{zone}/settings/security_level`. Idempotent.
- Each request carries `x-engine-instance` and `x-request-id` audit headers.
- Redirects are rejected, response bodies are bounded, and credential values are redacted from propagated transport errors.
- Missing scope or credentials returns `INVALID_ARGUMENT`. HTTP 401/403 or Cloudflare error codes 9109/10000 map to `PERMISSION_DENIED`; HTTP 429 maps to `RESOURCE_EXHAUSTED`. Other `success:false` responses map to `FAILED_PRECONDITION`. Network errors and 5xx map to `UNAVAILABLE`.

## Local Checks

```bash
cd services
npm run validate -- --service-dir cloudflare__waf
npm test -- --service-dir cloudflare__waf --coverage
npm run pack:check
```

The automated checks use a local mock upstream. No Cloudflare API credentials or live Zone were used for this package's verification.
