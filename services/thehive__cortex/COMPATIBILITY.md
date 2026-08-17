# Cortex 3.1 compatibility evidence

This adapter was verified against a real Cortex 3.1.7 deployment on
2026-08-17. This is not mock-upstream evidence.

## Reproducible upstream

- Official Cortex image: `thehiveproject/cortex:3.1.7`
- Image digest: `sha256:f4bc64fb8844f4624274395e42b2f37db600bcd81d6b3edbf64695e7dccb8ae9`
- Cortex application version reported by `/api/status`: `3.1.7-1`
- Official application JAR SHA-256:
  `2d8672ccb5d530c544e8da0658c1b642014bbf4d2eae5000e7cc310c311b0491`
- `/api/status` also reported Elastic4Play 1.13.6, Play 2.8.16,
  Elastic4s 7.17.2, and Elasticsearch client 7.17.1.
- Elasticsearch 7.8.1 was used, matching the compose file in the Cortex
  `3.1.7` source tag.

The validation host was ARM64 while the Cortex image is amd64-only. A
temporary `tonistiigi/binfmt:qemu-v10.0.4` registration first established
that the official image contents were executable. To avoid making the full
JVM run depend on slow emulation, the unmodified application files from the
official image were then run with ARM64 Temurin 8. The JAR hash above ties
that process to the official image. All temporary containers, volumes,
network, credentials, and binfmt registration were removed after validation.

The database was initialized through `POST /api/maintenance/migrate`. A
temporary tenant, org-admin service account, and API key were created. The
official analyzer definition list from
`https://download.thehive-project.org/analyzers.json` was loaded, and the
official `ValidateObservable_1_0` analyzer was enabled. Cortex pulled and ran:

- `ghcr.io/thehive-project/validateobservable:1`
- digest `sha256:6c593b2c68104984a2c47aaf5d4ed52b0d8a75969fa19a9983de02cf53e9099e`
- architecture `arm64`

## Real RPC results

All five adapter methods were called against that live API:

| RPC | Auditable result |
| --- | --- |
| `ListAnalyzers` | Returned two real tenant analyzers and preserved the Cortex instance IDs and definition IDs. |
| `AnalyzeObservable` | Submitted `openai.com` as `domain` to `ValidateObservable_1_0`; Cortex created job `m2sTD6AB0XWvYClaSjin`. |
| `GetJobStatus` | Observed `Waiting` to `InProgress` to `Success`; batch lookup also returned `NotFound` for a deliberately absent ID. |
| `GetJobReport` | Returned `success=true`, taxonomy `ValidateObs/domain=valid`, and full result `{status: valid, type: Domain, value: openai.com}`. |
| `ListJobs` | Returned the successful job using `dataTypeFilter=domain`, `analyzerFilter=OctoBus Validate Observable`, and `range=0-100`. |

The request included a non-secret parameter marker
`{"validation":"adapter-preserved"}`. It appeared unchanged in the created
job and the later ListJobs response, demonstrating that analyzer parameters
are not dropped or stringified.

The same live report was then exercised through a real OctoBus daemon and
service instance:

- Connect RPC returned the two live analyzers.
- gRPC `GetJobStatus`, with `x-octobus-capset=cortex-validation` and
  `x-octobus-instance=cortex-real`, returned `Success`.
- MCP tool `cortex__cortex-real__get_job_report` returned the successful live
  report and taxonomy.

This protocol run also exposed and fixed an adapter issue: successful
responses previously populated `google.protobuf.Value` fields with an unset
oneof, which caused MCP conversion to fail. Successful responses now omit
empty `err` and `msg` values.

## Compatibility limits discovered by the live run

- Cortex 3.1.7 local username/password login creates a browser session and
  does not accept HTTP Basic authentication for these REST endpoints. The
  unsupported Basic fallback and its schema/proto fields were removed; use a
  Cortex API key as a Bearer token.
- Cortex 3.1.7 accepted `dataTypeFilter` and `analyzerFilter`, but its own
  `dataFilter` search returned `SearchError: all shards failed` even when
  called directly. The adapter still forwards the documented parameter; the
  successful compatibility evidence does not claim that this upstream defect
  is fixed.

The mock suite remains useful for deterministic errors and edge cases, but it
is supplemental to the live evidence above.
