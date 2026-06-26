## 联调证据：Elastic Kibana 7.10.0 跑通 (issue #100)

> 本地真实联调：本地启动 mock upstream 模拟目标服务 → 通过 gRPC handler 直接调用 → 服务日志输出完整 HTTP request/response。

### 1. Mock upstream 启动
```
$ cd elastic__kibana_7-10-0/test && node mock_upstream.js &
# Mock started at: http://127.0.0.1:55353
```

### 2. 实际执行 (Node.js script)
```javascript
import { service } from './src/service.js';
const result = await service.handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetStatus'](
  {},  // empty request
  { config: {"baseUrl":"http://127.0.0.1:55353","timeoutMs":5000}, secret: {"username":"elastic","password":"changeme"} }
);
```

### 3. 上游 API 实际响应体 (handler.raw_body 解析)
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

### 4. gRPC Response (handler 返回值)
```json
{
  "name": "mock-kibana",
  "uuid": "kibana-uuid-001",
  "version": "7.10.0",
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
```
