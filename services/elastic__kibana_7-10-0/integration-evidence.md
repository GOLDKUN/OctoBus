## Mock integration evidence: GetStatus

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
