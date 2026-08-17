## Real Kibana 7.10.0 integration evidence

Validated on 2026-08-17 against clean, temporary containers made from the
official Elastic images. This was a real Kibana process backed by a real
Elasticsearch process, not `test/mock_upstream.js`.

- Kibana image: `docker.elastic.co/kibana/kibana:7.10.0`
- Kibana digest: `sha256:30b0dd20e532d45c42fc4703c21bfc54c2076b0436e6405019abb1b9cb44d3fa`
- Kibana image revision: `1796b5ec8fa1e60ccea63f2e5c25ccc665b92fdc`
- Elasticsearch image: `docker.elastic.co/elasticsearch/elasticsearch:7.10.0`
- Elasticsearch image revision: `51e9d6f22758d0374a0f3f5c6e8f3a7997850f96`
- Network exposure: loopback only (`127.0.0.1`)
- Authentication: Elasticsearch security was disabled in this disposable
  environment; the wrapper still exercised its Basic Authorization header.

A temporary dashboard named `OctoBus real Kibana 7.10 evidence` was created
through Kibana's saved objects API. All seven wrapper methods then completed
successfully against the real instance:

| Wrapper method | Real upstream result |
| --- | --- |
| `GetStatus` | `name=octobus-pr379-real`, `version=7.10.0`, overall/core Elasticsearch/core saved objects all `green` |
| `ListSpaces` | returned the reserved `default` space |
| `GetSpace` | returned the `default` space |
| `FindSavedObjects` | found exactly the temporary dashboard; repeated `fields` parameters were accepted |
| `GetSavedObject` | returned the dashboard and version token `WzgsMV0=` |
| `BulkGetSavedObjects` | accepted the Kibana 7.10 bare-array request and returned the same version token |
| `ExportSavedObjects` | returned one object plus the NDJSON summary; `total_count=1`, `exported_count=1` |

Representative redacted upstream response:

```json
{
  "name": "octobus-pr379-real",
  "version": { "number": "7.10.0" },
  "status": {
    "overall": { "state": "green" },
    "statuses": [
      { "id": "core:elasticsearch@7.10.0", "state": "green" },
      { "id": "core:savedObjects@7.10.0", "state": "green" }
    ]
  }
}
```

The repository L2 smoke separately exercises `GetStatus` through OctoBus
Connect, gRPC, and MCP transports and requires one upstream request per
protocol. Together, the real-instance run and transport smoke cover both the
Kibana 7.10 contract and the OctoBus transport path.

## Mock regression evidence: GetStatus

This transcript was produced by `test/mock_upstream.js`. It verifies the
handler's HTTP request/response mapping only; it is not evidence from a real
Kibana deployment and does not establish Kibana 7.10.0 compatibility.

# Request
```
http://127.0.0.1:<ephemeral-port>/api/status
Basic elastic:REDACTED
```

# Response   HTTP/1.1 200 OK
```json
{
  "name": "mock-kibana",
  "uuid": "kibana-uuid-001",
  "version": {
    "number": "7.10.0",
    "build_hash": "abc123",
    "build_number": 1
  },
  "status": {
    "overall": {
      "state": "green",
      "level": "available"
    },
    "statuses": [
      {
        "id": "core:elasticsearch@7.10.0",
        "state": "green",
        "message": "Ready",
        "level": "available"
      },
      {
        "id": "core:savedObjects@7.10.0",
        "state": "green",
        "message": "Ready",
        "level": "available"
      }
    ]
  }
}
```
