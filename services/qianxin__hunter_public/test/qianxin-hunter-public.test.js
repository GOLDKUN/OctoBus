import assert from "node:assert/strict";
import test from "node:test";

import { GrpcError, grpcStatus } from "@chaitin-ai/octobus-sdk";

import { service } from "../src/service.js";
import {
  BATCH_SEARCH_PATH,
  GET_USER_INFO_PATH,
  MAX_RETRIES,
  SEARCH_PATH,
  _test,
  handlers,
} from "../src/qianxin-hunter-public.js";
import { createMockServer } from "./mock_upstream.js";

const originalFetch = globalThis.fetch;
const response = (status, payload = {}, headers = {}) => ({
  status,
  ok: status >= 200 && status < 300,
  headers: { get: (name) => headers[String(name).toLowerCase()] ?? null },
  text: async () => typeof payload === "string" ? payload : JSON.stringify(payload),
});

const context = (overrides = {}) => ({
  request: overrides.request ?? {},
  config: { api_base: "http://127.0.0.1:1/openApi", timeout_ms: 1_000, ...(overrides.config ?? {}) },
  secret: overrides.secret ?? { api_key: "test-key" },
  limits: overrides.limits ?? {},
});

test.afterEach(() => {
  globalThis.fetch = originalFetch;
  _test.resetRateLimit();
});

test("all Hunter RPCs use the single-context SDK ABI, header credential, and correct request shapes", async () => {
  const mock = await createMockServer();
  try {
    const ctx = context({ config: { api_base: mock.host } });
    const account = await handlers[GET_USER_INFO_PATH.slice(1)](ctx);
    const search = await handlers[SEARCH_PATH.slice(1)]({ ...ctx, request: { search: 'ip="203.0.113.9"', page: 2, page_size: 20 } });
    const batch = await handlers[BATCH_SEARCH_PATH.slice(1)]({ ...ctx, request: { file_content: "203.0.113.9\n", assets_limit: 5 } });

    assert.equal(account.data.rest_equity_point, 9);
    assert.equal(search.data.arr[0].ip, "203.0.113.9");
    assert.equal(batch.data.task_id, 7);
    assert.equal(mock.requests.length, 3);
    assert.equal(mock.requests[0].headers["x-api-key"], "test-key");
    assert.equal(mock.requests[0].query["api-key"], undefined);
    assert.equal(mock.requests[1].query.page, "2");
    assert.equal(Buffer.from(mock.requests[1].query.search, "base64url").toString(), 'ip="203.0.113.9"');
    assert.match(mock.requests[2].headers["content-type"], /multipart\/form-data/);
    assert.match(mock.requests[2].body, /203\.0\.113\.9/);
  } finally {
    await mock.close();
  }
});

test("request and secret validation do not accept credentials from an RPC payload", async () => {
  await assert.rejects(
    () => handlers[SEARCH_PATH.slice(1)](context({ secret: {}, request: { search: "x", api_key: "request-key" } })),
    (error) => error instanceof GrpcError && error.legacyCode === "UNAUTHENTICATED",
  );
  await assert.rejects(
    () => handlers[SEARCH_PATH.slice(1)](context({ request: {} })),
    (error) => error.legacyCode === "INVALID_ARGUMENT",
  );
  await assert.rejects(
    () => handlers[BATCH_SEARCH_PATH.slice(1)](context({ request: {} })),
    (error) => error.legacyCode === "INVALID_ARGUMENT",
  );
});

test("maps upstream HTTP, malformed response, and network failures without exposing secrets", async () => {
  const run = () => handlers[SEARCH_PATH.slice(1)](context({ request: { search: "x" } }));
  globalThis.fetch = async () => response(401, { api_key: "leak" });
  await assert.rejects(run, (error) => error.legacyCode === "UNAUTHENTICATED" && !error.message.includes("leak"));
  _test.resetRateLimit();
  globalThis.fetch = async () => response(403, {});
  await assert.rejects(run, (error) => error.legacyCode === "PERMISSION_DENIED");
  _test.resetRateLimit();
  globalThis.fetch = async () => response(400, {});
  await assert.rejects(run, (error) => error.legacyCode === "FAILED_PRECONDITION");
  _test.resetRateLimit();
  globalThis.fetch = async () => response(503, {});
  await assert.rejects(run, (error) => error.legacyCode === "UNAVAILABLE");
  _test.resetRateLimit();
  globalThis.fetch = async () => response(200, "not-json");
  await assert.rejects(run, (error) => error.legacyCode === "UNKNOWN");
  _test.resetRateLimit();
  globalThis.fetch = async () => { throw new Error("api_key=leak"); };
  await assert.rejects(run, (error) => error.legacyCode === "UNAVAILABLE" && !error.message.includes("leak"));
});

test("uses bounded iterative retries for 429 responses", async () => {
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return response(429, {}, { "retry-after": "0.001" });
  };
  await assert.rejects(
    () => handlers[GET_USER_INFO_PATH.slice(1)](context()),
    (error) => error.legacyCode === "UNAVAILABLE",
  );
  assert.equal(calls, MAX_RETRIES + 1);
});

test("timeout, upstream business rejection, TLS option, and safe response redaction are covered", async () => {
  globalThis.fetch = (_url, init) => new Promise((_resolve, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true }));
  await assert.rejects(
    () => handlers[GET_USER_INFO_PATH.slice(1)](context({ limits: { timeoutMs: 1 } })),
    (error) => error.legacyCode === "DEADLINE_EXCEEDED",
  );
  _test.resetRateLimit();
  globalThis.fetch = async () => response(200, { code: 500, api_key: "leak" });
  await assert.rejects(
    () => handlers[GET_USER_INFO_PATH.slice(1)](context({ config: { skip_tls_verify: true } })),
    (error) => error.legacyCode === "FAILED_PRECONDITION" && !error.message.includes("leak"),
  );
  assert.equal(_test.validateUpstreamResult({ code: 200, data: { api_key: "leak" } }).data.api_key, "***");
  assert.equal(_test.normalizeBaseUrl("ftp://example.test"), "");
  assert.equal(_test.normalizeBaseUrl("https://example.test/"), "https://example.test");
  assert.equal(_test.base64urlEncode("中文"), Buffer.from("中文").toString("base64url"));
  assert.equal(_test.booleanValue("yes"), true);
  assert.equal(_test.numberValue({ value: "7" }), 7);
  assert.equal(_test.stringValue({ value: 8 }), "8");
  assert.equal(_test.callContext({ req: { x: 1 } }).request.x, 1);
  assert.equal(_test.responseFor({ code: 0, message: "", data: null }).message, "success");
  assert.equal(_test.retryDelay(response(429, {}, { "retry-after": "99" })), 10_000);
  assert.equal(grpcStatus.UNKNOWN, 2);
});

test("service surface exports every protobuf method", () => {
  for (const path of [GET_USER_INFO_PATH, SEARCH_PATH, BATCH_SEARCH_PATH]) {
    assert.equal(typeof handlers[path.slice(1)], "function");
    assert.equal(typeof service.handlers[path.slice(1)], "function");
  }
});
