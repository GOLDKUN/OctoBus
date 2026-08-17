import assert from "node:assert/strict";
import test from "node:test";

import { JianweiClient, _test as clientTest, isIdempotentMethod } from "../src/jianwei-client.js";
import { handlers } from "../src/jianwei-vuln.js";

const originalFetch = globalThis.fetch;
const prefix = "jianwei.vuln.service";

function context(request) {
    return {
        request,
        config: { baseUrl: "http://127.0.0.1:18080/insight", skipTlsVerify: false },
        secret: { token: "test-token" },
        limits: { timeoutMs: 1_000 },
    };
}

function response(payload, status = 200) {
    return {
        ok: status >= 200 && status < 300,
        status,
        headers: { get: () => null },
        text: async () => JSON.stringify(payload),
    };
}

function installMock(result = {}) {
    const requests = [];
    globalThis.fetch = async (url, options) => {
        requests.push({ url, options, body: JSON.parse(options.body) });
        return response({ jsonrpc: "2.0", id: 1, result });
    };
    return requests;
}

test.afterEach(() => {
    globalThis.fetch = originalFetch;
});

const cases = [
    ["AssetService/ListAssets", "AssetMgrService.IpAssetList", { count: "10", offset: "10", order_by: "name", filter: { status: "active", empty: null } }, { page_size: 10, page: 2, orderBy: "name", status: "active" }, { total: 2, data: [{ id: 1 }] }, { total: 2, data: [{ id: 1 }] }],
    ["AssetService/GetAsset", "AssetMgrService.IpAssetGet", { id: "5", workflow_id: "7" }, { id: 5, workflow_id: 7 }, { data: { id: 5 } }, { data: { id: 5 } }],
    ["AssetService/UpdateAsset", "AssetMgrService.IpAssetSave", { id: "5", data: { name: "a" }, update_empty_col: true }, { id: 5, data: { name: "a" }, update_empty_col: true }, { data: { id: 5 } }, { data: { id: 5 } }],
    ["AssetService/BatchUpdateAssets", "AssetMgrService.IpAssetBatchUpdate", { asset_ids: ["1", "2"], data: { tag: "x" }, cascade_vuln: true, conflict_strategy: "3", update_empty_col: true }, { asset_ids: [1, 2], data: { tag: "x" }, cascade_vuln: true, conflict_strategy: 3, update_empty_col: true }, { duplicated: ["2"] }, { duplicated: [2] }],
    ["VulnerabilityService/ListIpVulnerabilities", "ScanVulnIpService.SearchScanVulnIpList", { count: "5", offset: "0" }, { page_size: 5, page: 1 }, { total: 1, data: [{ id: 1 }] }, { total: 1, data: [{ id: 1 }] }],
    ["VulnerabilityService/ListWebVulnerabilities", "ScanVulnIpService.SearchScanVulnWebList", { count: "5", offset: "5" }, { page_size: 5, page: 2 }, { total: 1, data: [] }, { total: 1, data: [] }],
    ["VulnerabilityService/GetVulnerabilityDetails", "ScanVulnIpService.SearchScanVulnIpDetail", { vuln_id: "4", workflow_id: "wf" }, { id: 4, workflow_id: "wf" }, { data: { id: 4 } }, { data: { id: 4 } }],
    ["VulnerabilityService/UpdateVulnerabilityStatus", "ScanVulnIpService.UpsertScanVulnIp", { vuln_ids: ["1"], vuln_status: "2", vuln_type: "ip", fix_remarks: "fixed", remark: "ok", workflow_id: "wf", skip_end_status: true, exposure_exec_id: "3", exposure_result_id: ["4"] }, { vuln_ids: [1], vuln_status: 2, vuln_type: "ip", fix_remarks: "fixed", remark: "ok", workflow_id: "wf", skip_end_status: true, exposure_exec_id: 3, exposure_result_id: [4] }, {}, {}],
    ["DisposalService/DirectVulnDispose", "ScanVulnIpService.UpsertScanVulnIp", { vuln_ids: ["1"], vuln_status: "3", vuln_type: "ip", fix_remarks: "fixed", remark: "ok", workflow_id: "wf", skip_end_status: false, exposure_exec_id: "3", exposure_result_id: ["4"] }, { vuln_ids: [1], vuln_status: 3, vuln_type: "ip", fix_remarks: "fixed", remark: "ok", workflow_id: "wf", skip_end_status: false, exposure_exec_id: 3, exposure_result_id: [4] }, {}, {}],
    ["DisposalService/VulnDisposeHistory", "ScanVulnIpService.SearchScanVulnIpDetail", { vuln_id: "4", vuln_type: "ip" }, { id: 4, vuln_type: "ip" }, { vuln_dispose_record: [{ id: 1 }] }, { vuln_dispose_record: [{ id: 1 }] }],
    ["DisposalService/SaveVulnWorkflowStatus", "ScanVulnIpService.UpsertScanVulnIp", { vuln_type: "ip", status_map: { fixed: { ids: ["1", "2"] } } }, { vuln_type: "ip", status_map: { fixed: { ids: [1, 2] } } }, {}, {}],
    ["IntelligenceService/GetIPIntelligenceList", "IntelligenceService.GetIPIntelligenceList", { count: "2", offset: "0" }, { page_size: 2, page: 1 }, { total: 1, data: [{ ip: "127.0.0.1" }] }, { total: 1, data: [{ ip: "127.0.0.1" }] }],
    ["IntelligenceService/GetIPIntelligenceDetail", "IntelligenceService.GetIPIntelligenceDetail", { id: "100" }, { id: 100 }, { data: { ip: "127.0.0.1" } }, { data: { ip: "127.0.0.1" } }],
    ["IntelligenceService/GetDomainIntelligenceList", "IntelligenceService.GetDomainIntelligenceList", { count: "2", offset: "2" }, { page_size: 2, page: 2 }, { total: 1, data: [{ domain: "example.test" }] }, { total: 1, data: [{ domain: "example.test" }] }],
    ["IntelligenceService/GetDomainIntelligenceDetail", "IntelligenceService.GetDomainIntelligenceDetail", { id: "101" }, { id: 101 }, { data: { domain: "example.test" } }, { data: { domain: "example.test" } }],
    ["KnowledgeBaseService/SearchStandardVulnList", "KBService.SearchStandardVulnList", { count: "2", offset: "0" }, { page_size: 2, page: 1 }, { total: 1, data: [{ ct_id: "CT-1" }] }, { total: 1, data: [{ ct_id: "CT-1" }] }],
    ["KnowledgeBaseService/GetStandardVulnDetailByCTID", "KBService.GetStandardVulnDetailByCTID", { ct_id: "CT-1" }, { ct_id: "CT-1" }, { detail: { ct_id: "CT-1" } }, { detail: { ct_id: "CT-1" } }],
    ["KnowledgeBaseService/GetStandardVulnDetailByID", "KBService.GetStandardVulnDetailByID", { id: "6" }, { id: 6 }, { detail: { id: 6 } }, { detail: { id: 6 } }],
    ["KnowledgeBaseService/SearchCustomizeTags", "KBService.SearchCustomizeTags", { keyword: "critical" }, { keyword: "critical" }, { data: [{ name: "critical" }] }, { data: [{ name: "critical" }] }],
    ["KnowledgeBaseService/CreateCustomizeTag", "KBService.CreateCustomizeTag", { name: "tag", category: "custom" }, { name: "tag", category: "custom" }, { data: { id: 1 } }, { data: { id: 1 } }],
    ["KnowledgeBaseService/DeleteCustomizeTag", "KBService.DeleteCustomizeTag", { id: "7" }, { id: 7 }, {}, {}],
    ["KnowledgeBaseService/AppendCustomizeTags", "KBService.AppendCustomizeTags", { vuln_id: "7", tag_names: ["a"] }, { vuln_id: 7, tag_names: ["a"] }, {}, {}],
    ["KnowledgeBaseService/ReplaceCustomizeTags", "KBService.ReplaceCustomizeTags", { vuln_id: "7", tag_names: ["a"] }, { vuln_id: 7, tag_names: ["a"] }, {}, {}],
    ["DeviceService/CheckScanDeviceAuth", "ScanDeviceService.CheckScanDeviceAuth", { device_id: "8", env_map: { key: "value" } }, { device_id: 8, env_map: { key: "value" } }, {}, {}],
    ["DeviceService/CreateDevice", "ScanDeviceService.CreateDevice", { name: "scanner", organization_id: "1", owner_id: "2", security_scope_id: "3", logo_file_id: "4" }, { name: "scanner", organization_id: 1, owner_id: 2, security_scope_id: 3, logo_file_id: 4 }, { result: { id: 1 } }, { result: { id: 1 } }],
    ["DeviceService/RemoveScanDevice", "ScanDeviceService.RemoveScanDevice", { device_id: "8" }, { device_id: 8 }, {}, {}],
    ["DeviceService/GetDataAccessMapping", "ScanDeviceService.GetDataAccessMapping", {}, {}, { data: [{ id: 1 }] }, { data: [{ id: 1 }] }],
    ["DeviceService/GetDeviceProductNameList", "ScanDeviceService.GetDeviceProductNameList", {}, {}, { data: [{ name: "xray" }] }, { data: [{ name: "xray" }] }],
    ["VptService/GetVulnVptScore", "ScanVulnIpService.GetVulnVptScore", { vuln_ids: ["1"], vuln_type: "ip" }, { vuln_ids: [1], vuln_type: "ip" }, { list: [{ id: 1 }] }, { list: [{ id: 1 }] }],
    ["VptService/GetVulnVptScoreSetting", "ScanVulnIpService.GetVulnVptScoreSetting", {}, {}, { is_default: true, setting: { mode: "auto" } }, { is_default: true, setting: { mode: "auto" } }],
    ["VptService/SaveVulnVptScoreSetting", "ScanVulnIpService.SaveVulnVptScoreSetting", { setting: { mode: "manual" } }, { setting: { mode: "manual" } }, {}, {}],
    ["VptService/ResetVulnVptScoreSetting", "ScanVulnIpService.ResetVulnVptScoreSetting", {}, {}, {}, {}],
    ["VptService/GetVulnVptScoreState", "ScanVulnIpService.GetVulnVptScoreState", {}, {}, { state: "running", progress: "75" }, { state: "running", progress: 75 }],
];

test("all 33 declared RPC handlers have deterministic OctoBus context mappings", async (t) => {
    assert.equal(cases.length, 33);
    assert.deepEqual(Object.keys(handlers).sort(), cases.map(([path]) => `${prefix}.${path}`).sort());
    for (const [path, rpcMethod, request, params, upstream, expected] of cases) {
        await t.test(path, async () => {
            const requests = installMock(upstream);
            const result = await handlers[`${prefix}.${path}`](context(request));
            assert.deepEqual(result, expected);
            assert.equal(requests.length, 1);
            assert.equal(requests[0].url, "http://127.0.0.1:18080/pedestal/rpc");
            assert.equal(requests[0].body.method, rpcMethod);
            assert.deepEqual(requests[0].body.params, params);
            assert.equal(requests[0].options.headers.Authorization, "Bearer test-token");
        });
    }
});

test("all RPC handlers safely normalize empty requests and empty upstream results", async () => {
    for (const key of Object.keys(handlers)) {
        const requests = installMock({});
        const result = await handlers[key](context({}));
        assert.equal(typeof result, "object", `${key} must return an object`);
        assert.equal(requests.length, 1, `${key} must make one upstream request`);
        assert.deepEqual(requests[0].body.params, {}, `${key} must omit unset request fields`);
    }
});

test("handlers reject malformed or precision-losing integer fields", async () => {
    const invoke = (path, request) => handlers[`${prefix}.${path}`](context(request));
    await assert.rejects(invoke("AssetService/GetAsset", { id: "not-an-id" }), (error) => error.legacyCode === "INVALID_ARGUMENT");
    await assert.rejects(invoke("AssetService/GetAsset", { id: "9007199254740992" }), (error) => error.legacyCode === "INVALID_ARGUMENT");
    await assert.rejects(invoke("AssetService/ListAssets", { count: "0", offset: "0" }), (error) => error.legacyCode === "INVALID_ARGUMENT");
    await assert.rejects(invoke("AssetService/ListAssets", { count: "10", offset: "-1" }), (error) => error.legacyCode === "INVALID_ARGUMENT");
    await assert.rejects(invoke("VulnerabilityService/UpdateVulnerabilityStatus", { vuln_ids: ["1", "bad"] }), (error) => error.legacyCode === "INVALID_ARGUMENT");
});

test("offset-only pagination is explicit and retry classification covers all RPCs", async () => {
    const requests = installMock({ total: 0, data: [] });
    await handlers[`${prefix}.AssetService/ListAssets`](context({ offset: "10" }));
    assert.deepEqual(requests[0].body.params, { page_size: 10, page: 2 });
    const methods = cases.map(([, method]) => method);
    const readMethods = methods.filter((method) => isIdempotentMethod(method));
    const writeMethods = methods.filter((method) => !isIdempotentMethod(method));
    assert.ok(readMethods.length >= 15);
    assert.ok(writeMethods.length >= 10);
    assert.equal(new Set([...readMethods, ...writeMethods]).size, 30);
});

test("client uses secure defaults, bounded requests, and typed errors", async (t) => {
    await t.test("normalizes only safe base URLs", () => {
        assert.equal(clientTest.normalizeBaseUrl("https://jianwei.example.test/insight/"), "https://jianwei.example.test");
        assert.equal(clientTest.normalizeBaseUrl("http://[::1]:8080"), "http://[::1]:8080");
        assert.throws(() => clientTest.normalizeBaseUrl("http://jianwei.example.test"), /HTTPS/);
        assert.throws(() => clientTest.normalizeBaseUrl("https://user:pass@jianwei.example.test"), /credentials/);
    });
    await t.test("uses a request timeout and does not disable TLS by default", async () => {
        const requests = installMock({ value: true });
        const client = new JianweiClient("http://127.0.0.1:18080", "token", { timeoutMs: 250 });
        await client.call("test.method");
        assert.ok(requests[0].options.signal instanceof AbortSignal);
        assert.equal(requests[0].options.dispatcher, undefined);
        assert.equal(requests[0].options.redirect, "error");
    });
    await t.test("enables the insecure dispatcher only when explicitly configured", async () => {
        const requests = installMock({});
        const client = new JianweiClient("http://127.0.0.1:18080", "token", { skipTlsVerify: true });
        await client.call("test.method");
        assert.ok(requests[0].options.dispatcher);
    });
    await t.test("maps HTTP, JSON-RPC, and timeout failures to SDK errors", async () => {
        globalThis.fetch = async () => response({}, 401);
        await assert.rejects(new JianweiClient("http://127.0.0.1:18080", "token", { retryOptions: { maxRetries: 0 } }).call("test.method"), (error) => error.legacyCode === "UNAUTHENTICATED");
        globalThis.fetch = async () => response({ jsonrpc: "2.0", id: 1, error: { code: -32602 } });
        await assert.rejects(new JianweiClient("http://127.0.0.1:18080", "token", { retryOptions: { maxRetries: 0 } }).call("test.method"), (error) => error.legacyCode === "INVALID_ARGUMENT");
        globalThis.fetch = async () => { throw new DOMException("expired", "TimeoutError"); };
        await assert.rejects(new JianweiClient("http://127.0.0.1:18080", "token", { retryOptions: { maxRetries: 0 } }).call("test.method"), (error) => error.legacyCode === "DEADLINE_EXCEEDED");
    });
    await t.test("retries transient transport failures without exceeding its request contract", async () => {
        let calls = 0;
        globalThis.fetch = async () => {
            calls += 1;
            return calls === 1 ? response({}, 503) : response({ jsonrpc: "2.0", id: 2, result: { recovered: true } });
        };
        const result = await new JianweiClient("http://127.0.0.1:18080", "token", {
            retryOptions: { maxRetries: 1, retryDelayMs: 0 },
        }).call("AssetMgrService.IpAssetList");
        assert.deepEqual(result, { recovered: true });
        assert.equal(calls, 2);
        calls = 0;
        globalThis.fetch = async () => { calls += 1; return response({}, 503); };
        await assert.rejects(new JianweiClient("http://127.0.0.1:18080", "token", { retryOptions: { maxRetries: 2, retryDelayMs: 0 } }).call("ScanDeviceService.CreateDevice"));
        assert.equal(calls, 1);
    });
    await t.test("rejects unsafe configuration and malformed successful responses", async () => {
        assert.throws(() => new JianweiClient("http://127.0.0.1:18080", "", {}), (error) => error.legacyCode === "UNAUTHENTICATED");
        assert.throws(() => new JianweiClient("http://127.0.0.1:18080", "token", { timeoutMs: 0 }), (error) => error.legacyCode === "INVALID_ARGUMENT");
        globalThis.fetch = async () => response({ jsonrpc: "2.0" });
        await assert.rejects(new JianweiClient("http://127.0.0.1:18080", "token", { retryOptions: { maxRetries: 0 } }).call("test.method"), (error) => error.legacyCode === "INTERNAL");
        globalThis.fetch = async () => response("invalid");
        await assert.rejects(new JianweiClient("http://127.0.0.1:18080", "token", { retryOptions: { maxRetries: 0 } }).call("test.method"), (error) => error.legacyCode === "INTERNAL");
        globalThis.fetch = async () => response({ jsonrpc: "2.0", id: 99, result: {} });
        await assert.rejects(new JianweiClient("http://127.0.0.1:18080", "token", { retryOptions: { maxRetries: 0 } }).call("test.method"), (error) => error.legacyCode === "INTERNAL");
        globalThis.fetch = async () => ({ ...response({}, 200), text: async () => "not-json" });
        await assert.rejects(new JianweiClient("http://127.0.0.1:18080", "token", { retryOptions: { maxRetries: 0 } }).call("test.method"), (error) => error.legacyCode === "INTERNAL");
    });
});
