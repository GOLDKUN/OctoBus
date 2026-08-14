# OpenInfra OpenStack Yoga (2022.1)

OctoBus service package for read-only Keystone v3 (Identity), Nova v2.1 (Compute),
Neutron v2.0 (Network) and Cinder v3 (Block Storage) queries against an OpenInfra
OpenStack Yoga (2022.1) cloud.

## Import

```bash
octobus service import --id openstack-yoga-2022-1 ./services/openinfra__openstack-yoga_2022-1
```

## Package Layout

- `service.json`: OctoBus service package manifest.
- `proto/openstack_yoga_2022_1.proto`: Legacy-compatible gRPC API.
- `src/openstack-yoga-2022-1.js`: Runtime handlers, Keystone auth flow, HTTP request
  building, response parsing, and error mapping.
- `config.schema.json`: Non-secret binding schema (auth URL, region, project info).
- `secret.schema.json`: Username + password schema.
- `test/`: Node test coverage and mock upstream that responds to both
  `/v3/auth/tokens` and the various API endpoints.

## Bindings

Configuration:

- `auth_url` (or `authUrl`, `identityEndpoint`): Keystone v3 base URL, for example
  `https://identity.example.com:5000` or `http://controller:5000`.
- `region`: OpenStack region used to select a public service-catalog endpoint.
- `project_name`: required canonical Keystone project name used to scope the
  token. `projectName` is retained only for compatibility with legacy callers
  that also provide the canonical field.
- `project_domain_name` (or `projectDomainName`): Keystone project domain name
  (defaults to `Default` upstream if missing).
- `user_domain_name` (or `userDomainName`): Keystone user domain name (defaults to
  `Default` upstream if missing).
- `timeoutMs`: HTTP timeout in milliseconds for both Keystone auth and upstream
  calls, default `15000`.
- `allowInsecureHttp` (or `allow_insecure_http`): allow `http://` auth URLs.
  Defaults to `false` (only `https://` is accepted).
- `skipTlsVerify`, `tlsInsecureSkipVerify`, `insecureSkipVerify`: skip TLS
  certificate verification.

Secrets:

- `username`: OpenStack user name.
- `password`: OpenStack user password.

## Authentication

A two-step Keystone token flow is used:

1. `POST {auth_url}/v3/auth/tokens` with the standard password-method body, e.g.:

   ```json
   {
     "auth": {
       "identity": {
         "methods": ["password"],
         "password": {
           "user": {
             "name": "USERNAME",
             "domain": { "name": "USER_DOMAIN_NAME" },
             "password": "PASSWORD"
           }
         }
       },
       "scope": {
         "project": {
           "name": "PROJECT_NAME",
           "domain": { "name": "PROJECT_DOMAIN_NAME" }
         }
       }
     }
   }
   ```

2. The response's `X-Subject-Token` header is captured and reused for subsequent
   calls via the `X-Auth-Token` header. The scoped `project.id` is also extracted
   from the response body and used as the `{project_id}` path segment for Compute
   and Block Storage endpoints.

> NOTE: For the scaffold, every handler re-fetches a token (no caching). A future improvement is to add a per-(username, project, lifetime) token cache once upstream token expiry (`token.expires_at`) is consumed.
> marks the spot where a per-(username, project, lifetime) token cache should be
> inserted when the upstream supports token expiry.

## RPC Methods

- `OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListProjects`
- `OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListServers`
- `OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/GetServer`
- `OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListNetworks`
- `OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListVolumes`
- `OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListFlavors`

List methods request up to 1,000 records from the upstream API. They currently
return one upstream page; deployments with more than 1,000 matching resources
should narrow the request filters or query OpenStack directly for exhaustive
pagination.

## Behavior

- All list/get RPCs use `HTTP GET` against the configured `auth_url` base.
- The Keystone project id is auto-discovered from the auth response body, but
  callers may override the scoped project in `project_id` fields where present.
- All response mapping is sourced directly from the OpenStack Yoga 2022.1
  official API reference (docs.openstack.org/api-ref). Field names follow the
  upstream JSON structure. Nested objects/arrays (e.g. `attachments`,
  `extra_specs`, `subnets`) are exposed as serialized `*_json` fields so
  callers retain full fidelity.
- HTTP `401` / `403` map to `PERMISSION_DENIED`, `404` maps to `NOT_FOUND`,
  other `4xx` map to `FAILED_PRECONDITION`, `5xx` and network errors map to
  `UNAVAILABLE`.

## Validation

```bash
cd services
npm run validate -- --service-dir openinfra__openstack-yoga_2022-1
npm test -- --service-dir openinfra__openstack-yoga_2022-1 --coverage
npm run pack:check
```
