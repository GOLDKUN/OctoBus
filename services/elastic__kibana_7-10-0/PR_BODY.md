## Mock 联调记录：GetStatus

以下内容来自 `test/mock_upstream.js`，仅验证 handler 的 HTTP 映射；它不是
真实 Kibana 实例证据，也不能单独证明 Kibana 7.10.0 兼容性。

# Request
GET http://127.0.0.1:<ephemeral-port>/api/status
Basic elastic:REDACTED




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
