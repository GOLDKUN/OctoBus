## 联调证据：GetStatus 跑通

# Request
GET https://10.0.0.4:5601/api/status
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
