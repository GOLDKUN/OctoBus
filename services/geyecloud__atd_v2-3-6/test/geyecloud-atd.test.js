import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { grpcStatus } from "@chaitin-ai/octobus-sdk";

import { buildAuthHeaders, handlers, normalizeBaseUrl } from "../src/geyecloud-atd.js";

const assertGrpcError = async (fn, code, message) => {
  await assert.rejects(fn, (err) => {
    assert.equal(err.code, code);
    if (message) assert.match(err.message, message);
    return true;
  });
};

test("normalizeBaseUrl removes UI hash and trailing slash", () => {
  assert.equal(normalizeBaseUrl("https://192.0.2.10:5443/#/workBench"), "https://192.0.2.10:5443");
});

test("normalizeBaseUrl rejects malformed and unsupported URLs", () => {
  assert.throws(
    () => normalizeBaseUrl("not a url"),
    (err) => {
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.match(err.message, /valid URL/);
      return true;
    },
  );
  assert.throws(
    () => normalizeBaseUrl("ftp://192.0.2.10"),
    (err) => {
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.match(err.message, /http or https/);
      return true;
    },
  );
});

test("normalizeBaseUrl strips embedded credentials, query, and hash", () => {
  assert.equal(
    normalizeBaseUrl("https://user:pass@192.0.2.10:5443/?token=secret#/workBench"),
    "https://192.0.2.10:5443",
  );
});

test("buildAuthHeaders sends api-key and ATD signature headers", () => {
  const headers = buildAuthHeaders("dummy-api-key", 1774249367000, "nonce-value");
  assert.equal(headers["api-key"], "dummy-api-key");
  assert.equal(headers["user-key"], "");
  assert.equal(headers["X-Ca-Timestamp"], "1774249367000");
  assert.equal(headers["X-Ca-Nonce"], "nonce-value");
  assert.equal(headers["X-Ca-Sign"], crypto.createHash("md5").update("1774249367000nonce-value").digest("hex"));
});

test("AggregateThreatEvents accepts lowerCamelCase request fields and maps aggregate response", async () => {
  const handler = handlers["geyecloud.atd.v1.GEYECloudATD/AggregateThreatEvents"];
  const calls = [];
  globalThis.__geyeCloudAtdTestRequest = async (url, options) => {
    calls.push({ url, options });
    return {
      statusCode: 200,
      body: JSON.stringify({
        msg: "success",
        code: 200,
        agg: {
          count: 2,
          totalCount: 12,
          list: [
            { key: "high", value: 10 },
            { key: "low", value: 2 }
          ]
        }
      })
    };
  };
  try {
    const result = await handler({
      request: {
        start: 1773644567000,
        end: 1774249367000,
        page: 1,
        pageSize: 10,
        terms: "severity",
        tableName: "hw"
      },
      config: { baseUrl: "https://atd.example.com/#/workBench", skipTlsVerify: true },
      secret: { apiKey: "dummy-api-key" }
    });
    assert.equal(result.code, 200);
    assert.equal(result.count, 2);
    assert.equal(result.total_count, 12);
    assert.equal(result.items[0].key, "high");
    assert.equal(calls[0].url.pathname, "/workbenchApi/furious/elasticSearch/aggregate");
    assert.equal(calls[0].options.headers["api-key"], "dummy-api-key");
    assert.deepEqual(JSON.parse(calls[0].options.body), {
      start: 1773644567000,
      end: 1774249367000,
      from: 1,
      size: 10,
      terms: "severity",
      tableName: "hw"
    });
  } finally {
    delete globalThis.__geyeCloudAtdTestRequest;
  }
});

test("ListFileDetectionLogs maps file detection pagination", async () => {
  const handler = handlers["geyecloud.atd.v1.GEYECloudATD/ListFileDetectionLogs"];
  const calls = [];
  globalThis.__geyeCloudAtdTestRequest = async (url, options) => {
    calls.push({ url, options });
    return {
      statusCode: 200,
      body: JSON.stringify({
        msg: "success",
        code: 200,
        data: {
          total: 1,
          size: 20,
          current: 1,
          page: 1,
          records: [
            {
              timestamp: 1774249367000,
              uuid: "evt-1",
              file_name: "sample.exe",
              file_md5: "44d88612fea8a8f36de82e1278abb02f",
              file_type: "exe",
              file_size: "12KB",
              src_ip: "192.0.2.20",
              dst_ip: "198.51.100.10",
              severity: 3,
              classtype: "恶意文件",
              category: "特洛伊木马通信",
              engine_type: "sandbox",
              sensor_id: 1001
            }
          ]
        }
      })
    };
  };
  try {
    const result = await handler({
      request: {
        start: 1773644567000,
        end: 1774249367000,
        page: 1,
        pageSize: 20,
        isTranslate: "false",
        fileMd5: "44d88612fea8a8f36de82e1278abb02f"
      },
      config: { baseUrl: "https://atd.example.com", skipTlsVerify: true },
      secret: { apiKey: "dummy-api-key" }
    });
    assert.equal(calls[0].url.pathname, "/workbenchApi/furious/fileDetectionLog/list");
    const requestBody = JSON.parse(calls[0].options.body);
    assert.equal(requestBody.fileMd5, "44d88612fea8a8f36de82e1278abb02f");
    assert.equal(requestBody.isTranslate, false);
    assert.equal(result.total, 1);
    assert.equal(result.items[0].file_name, "sample.exe");
  } finally {
    delete globalThis.__geyeCloudAtdTestRequest;
  }
});

test("GetSituationOverview performs readonly dashboard GET calls", async () => {
  const handler = handlers["geyecloud.atd.v1.GEYECloudATD/GetSituationOverview"];
  const calls = [];
  globalThis.__geyeCloudAtdTestRequest = async (url, options) => {
    calls.push({ url, options });
    return {
      statusCode: 200,
      body: JSON.stringify({ msg: "success", code: 200, data: { value: calls.length } })
    };
  };
  try {
    const result = await handler({
      request: {},
      config: { baseUrl: "https://atd.example.com", skipTlsVerify: true },
      secret: { apiKey: "dummy-api-key" }
    });
    assert.equal(calls[0].options.method, "GET");
    assert.equal(calls[0].url.pathname, "/workbenchApi/furious/situationAwareness/security_pyramid/logs_statistics");
    assert.equal(result.sections.length, 5);
    assert.equal(result.sections[0].name, "logs_statistics");
  } finally {
    delete globalThis.__geyeCloudAtdTestRequest;
  }
});

test("SearchThreatEvents maps advanced search response", async () => {
  const handler = handlers["geyecloud.atd.v1.GEYECloudATD/SearchThreatEvents"];
  const calls = [];
  globalThis.__geyeCloudAtdTestRequest = async (url, options) => {
    calls.push({ url, options });
    return {
      statusCode: 200,
      body: JSON.stringify({
        total: 1,
        size: 10,
        current: 1,
        page: 1,
        records: [
          {
            timestamp: 1774249367000,
            uuid: "evt-2",
            severity: "高危",
            category: "特洛伊木马通信",
            classtype: "恶意文件",
            src_ip: "192.0.2.20",
            dst_ip: "198.51.100.10",
            attack_status: "攻击成功",
            kill_chain: "命令控制",
            app_proto: "https",
            sensor_id: 1001,
            event_source: "atd"
          }
        ]
      })
    };
  };
  try {
    const result = await handler({
      request: {
        start: 1773644567000,
        end: 1774249367000,
        tableName: "hw",
        srcIp: "192.0.2.20",
        page: 1,
        pageSize: 10
      },
      config: { baseUrl: "https://atd.example.com", skipTlsVerify: true },
      secret: { apiKey: "dummy-api-key" }
    });
    assert.equal(calls[0].url.pathname, "/workbenchApi/furious/searchCenter/advanced/searchData");
    assert.equal(JSON.parse(calls[0].options.body).src_ip, "192.0.2.20");
    assert.equal(result.total, 1);
    assert.equal(result.items[0].kill_chain, "命令控制");
    assert.equal(result.items[0].severity_text, "高危");
  } finally {
    delete globalThis.__geyeCloudAtdTestRequest;
  }
});

test("ListSceneMonitors maps unwrapped scene monitor pagination", async () => {
  const handler = handlers["geyecloud.atd.v1.GEYECloudATD/ListSceneMonitors"];
  globalThis.__geyeCloudAtdTestRequest = async () => ({
    statusCode: 200,
    body: JSON.stringify({
      total: 1,
      size: 1,
      current: 1,
      page: 1,
      records: [{ monitorId: 1, monitorName: "test" }]
    })
  });
  try {
    const result = await handler({
      request: { page: 1, pageSize: 1 },
      config: { baseUrl: "https://atd.example.com", skipTlsVerify: true },
      secret: { apiKey: "dummy-api-key" }
    });
    assert.equal(result.total, 1);
    assert.equal(JSON.parse(result.items[0].raw_json).monitorId, 1);
  } finally {
    delete globalThis.__geyeCloudAtdTestRequest;
  }
});

test("GetNetworkLogDetail sends detail id as upstream uuid", async () => {
  const handler = handlers["geyecloud.atd.v1.GEYECloudATD/GetNetworkLogDetail"];
  const calls = [];
  globalThis.__geyeCloudAtdTestRequest = async (url, options) => {
    calls.push({ url, options });
    return {
      statusCode: 200,
      body: JSON.stringify({
        msg: "success",
        code: 200,
        data: {
          uuid: "net-1",
          uid: "net-1",
          timestamp: 1774249367000,
          src_ip: "192.0.2.20",
          dst_ip: "198.51.100.10"
        }
      })
    };
  };
  try {
    const result = await handler({
      request: {
        detailId: "net-1",
        queryTimestamp: 1774249367000,
        start: 1773644567000,
        end: 1774249367000
      },
      config: { baseUrl: "https://atd.example.com", skipTlsVerify: true },
      secret: { apiKey: "dummy-api-key" }
    });
    assert.equal(calls[0].url.pathname, "/workbenchApi/furious/netWorkLog/details");
    assert.equal(JSON.parse(calls[0].options.body).uuid, "net-1");
    assert.equal(JSON.parse(calls[0].options.body).detailId, undefined);
    assert.equal(result.log.uid, "net-1");
  } finally {
    delete globalThis.__geyeCloudAtdTestRequest;
  }
});

test("upstream HTTP errors are mapped to unavailable", async () => {
  const handler = handlers["geyecloud.atd.v1.GEYECloudATD/AggregateThreatEvents"];
  globalThis.__geyeCloudAtdTestRequest = async () => ({
    statusCode: 503,
    body: "service unavailable",
  });
  try {
    await assertGrpcError(
      () =>
        handler({
          request: { start: 1773644567000, end: 1774249367000, terms: "severity" },
          config: { baseUrl: "https://atd.example.com" },
          secret: { apiKey: "dummy-api-key" },
        }),
      grpcStatus.UNAVAILABLE,
      /upstream http 503/,
    );
  } finally {
    delete globalThis.__geyeCloudAtdTestRequest;
  }
});

test("invalid JSON upstream responses are mapped to unknown", async () => {
  const handler = handlers["geyecloud.atd.v1.GEYECloudATD/AggregateThreatEvents"];
  globalThis.__geyeCloudAtdTestRequest = async () => ({
    statusCode: 200,
    body: "<html>not json</html>",
  });
  try {
    await assertGrpcError(
      () =>
        handler({
          request: { start: 1773644567000, end: 1774249367000, terms: "severity" },
          config: { baseUrl: "https://atd.example.com" },
          secret: { apiKey: "dummy-api-key" },
        }),
      grpcStatus.UNKNOWN,
      /not valid JSON/,
    );
  } finally {
    delete globalThis.__geyeCloudAtdTestRequest;
  }
});

test("network exceptions are mapped to unavailable", async () => {
  const handler = handlers["geyecloud.atd.v1.GEYECloudATD/AggregateThreatEvents"];
  globalThis.__geyeCloudAtdTestRequest = async () => {
    throw new Error("request timeout");
  };
  try {
    await assertGrpcError(
      () =>
        handler({
          request: { start: 1773644567000, end: 1774249367000, terms: "severity" },
          config: { baseUrl: "https://atd.example.com" },
          secret: { apiKey: "dummy-api-key" },
        }),
      grpcStatus.UNAVAILABLE,
      /request timeout/,
    );
  } finally {
    delete globalThis.__geyeCloudAtdTestRequest;
  }
});

test("upstream application errors are mapped to grpc statuses", async () => {
  const handler = handlers["geyecloud.atd.v1.GEYECloudATD/AggregateThreatEvents"];
  const cases = [
    [401, grpcStatus.UNAUTHENTICATED],
    [403, grpcStatus.PERMISSION_DENIED],
    [404, grpcStatus.NOT_FOUND],
    [500, grpcStatus.UNAVAILABLE],
  ];

  for (const [upstreamCode, grpcCode] of cases) {
    globalThis.__geyeCloudAtdTestRequest = async () => ({
      statusCode: 200,
      body: JSON.stringify({ code: upstreamCode, msg: `error ${upstreamCode}` }),
    });
    await assertGrpcError(
      () =>
        handler({
          request: { start: 1773644567000, end: 1774249367000, terms: "severity" },
          config: { baseUrl: "https://atd.example.com" },
          secret: { apiKey: "dummy-api-key" },
        }),
      grpcCode,
      new RegExp(`error ${upstreamCode}`),
    );
  }

  delete globalThis.__geyeCloudAtdTestRequest;
});
