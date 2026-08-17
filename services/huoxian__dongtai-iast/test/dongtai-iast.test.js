import { describe, it, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';

import {
  _test,
  handlers,
  METHOD_LIST_VULNS_FULL,
  METHOD_GET_VULN_FULL,
  METHOD_UPDATE_VULN_STATUS_FULL,
  METHOD_GET_VULN_SUMMARY_FULL,
  METHOD_LIST_PROJECTS_FULL,
  METHOD_GET_PROJECT_FULL,
  METHOD_CREATE_PROJECT_FULL,
  METHOD_DELETE_PROJECT_FULL,
  METHOD_LIST_AGENTS_FULL,
  METHOD_GET_SYSTEM_INFO_FULL,
  METHOD_LIST_STRATEGIES_FULL,
  METHOD_GET_SCA_DETAIL_FULL,
} from '../src/dongtai-iast.js';

const {
  errorWithCode,
  firstDefined,
  mergedBindings,
  normalizeBaseUrl,
  parseHeaders,
  toPositiveInt,
  toStruct,
  toValue,
  unwrapString,
} = _test;

// ============ Unit Tests: Utility Functions ============

describe('Utility Functions', () => {
  it('normalizeBaseUrl should handle valid URLs', () => {
    assert.equal(normalizeBaseUrl('http://localhost:9090'), 'http://localhost:9090');
    assert.equal(normalizeBaseUrl('https://dongtai.example.com/'), 'https://dongtai.example.com');
    assert.equal(normalizeBaseUrl('invalid'), null);
    assert.equal(normalizeBaseUrl(''), null);
    assert.equal(normalizeBaseUrl(null), null);
    assert.equal(normalizeBaseUrl('ftp://dongtai.example.com'), null);
    assert.equal(normalizeBaseUrl('https://token@dongtai.example.com'), null);
    assert.equal(normalizeBaseUrl('https://dongtai.example.com/?next=elsewhere'), null);
  });

  it('toPositiveInt should parse numbers correctly', () => {
    assert.equal(toPositiveInt(1), 1);
    assert.equal(toPositiveInt(100), 100);
    assert.equal(toPositiveInt({ value: 42 }), 42);
    assert.equal(toPositiveInt(0), 0);
    assert.equal(toPositiveInt(-1), null);
    assert.equal(toPositiveInt(null), null);
    assert.equal(toPositiveInt(undefined), null);
    assert.equal(toPositiveInt('abc'), null);
    assert.equal(toPositiveInt(1.5), null);
  });

  it('unwrapString should handle various inputs', () => {
    assert.equal(unwrapString('hello'), 'hello');
    assert.equal(unwrapString({ value: 'world' }), 'world');
    assert.equal(unwrapString(null), '');
    assert.equal(unwrapString(undefined), '');
    assert.equal(unwrapString(123), '123');
  });

  it('firstDefined should return the first defined value', () => {
    assert.equal(firstDefined(undefined, null, 'hello'), 'hello');
    assert.equal(firstDefined('first', 'second'), 'first');
    assert.equal(firstDefined(undefined, undefined, 42), 42);
    assert.equal(firstDefined(), undefined);
  });

  it('mergedBindings should merge config and secret', () => {
    const ctx = {
      config: { endpoint: 'http://localhost:9090', timeoutMs: 5000 },
      secret: { apiToken: 'test-token' },
    };
    const result = mergedBindings(ctx);
    assert.equal(result.endpoint, 'http://localhost:9090');
    assert.equal(result.apiToken, 'test-token');
    assert.equal(result.timeoutMs, 5000);
  });

  it('parseHeaders should handle various inputs', () => {
    assert.deepEqual(parseHeaders({ 'X-Custom': 'value' }), { 'X-Custom': 'value' });
    assert.deepEqual(parseHeaders(''), {});
    assert.deepEqual(parseHeaders(null), {});
    assert.deepEqual(parseHeaders('{"X-Auth":"abc"}'), { 'X-Auth': 'abc' });
    assert.deepEqual(parseHeaders('{bad json'), {});
    assert.deepEqual(parseHeaders('[]'), {});
    assert.deepEqual(parseHeaders(['not', 'headers']), {});
  });

  it('toValue should convert values correctly', () => {
    assert.deepEqual(toValue('hello'), { stringValue: 'hello' });
    assert.deepEqual(toValue(42), { numberValue: 42 });
    assert.deepEqual(toValue(true), { boolValue: true });
    assert.deepEqual(toValue(null), undefined);
    assert.deepEqual(toValue(undefined), undefined);
    assert.deepEqual(toValue(['one', null, 2]), {
      listValue: { values: [{ stringValue: 'one' }, { numberValue: 2 }] },
    });
    assert.deepEqual(toValue({ nested: null, enabled: false }), {
      structValue: { fields: { nested: { nullValue: 'NULL_VALUE' }, enabled: { boolValue: false } } },
    });
    assert.deepEqual(toValue(Symbol.for('value')), { stringValue: 'Symbol(value)' });
  });

  it('toStruct should convert objects to struct format', () => {
    const result = toStruct({ name: 'test', count: 5 });
    assert.ok(result.fields);
    assert.equal(result.fields.name.stringValue, 'test');
    assert.equal(result.fields.count.numberValue, 5);
    assert.deepEqual(toStruct(null), { fields: {} });
  });

  it('errorWithCode should create GrpcError with correct code', () => {
    const err = errorWithCode('INVALID_ARGUMENT', 'test error');
    assert.ok(err);
    assert.ok(err.message.includes('INVALID_ARGUMENT'));
    assert.equal(err.legacyCode, 'INVALID_ARGUMENT');
  });
});

// ============ Integration Tests with Mock ============

const MOCK_BASE_URL = 'http://127.0.0.1:19999';
const MOCK_TOKEN = 'test-token-12345';

let mockServer;

function createMockResponse(data, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get: (name) => name === 'content-type' ? 'application/json' : null,
    },
    text: async () => JSON.stringify(data),
  };
}

describe('API Method Tests (Mock)', () => {
  let originalFetch;
  const summaryRequests = [];

  before(() => {
    originalFetch = globalThis.fetch;
    globalThis.fetch = mock.fn(async (url, init) => {
      const urlStr = String(url);
      const method = init?.method || 'GET';

      // ListVulnerabilities
      if (urlStr.includes('/api/v1/vulns') && method === 'GET') {
        return createMockResponse({
          status: 201,
          data: [
            {
              id: 1, vul_name: 'SQL注入', vul_type: 'sql_injection',
              level_id: 1, level_name: '高危', state: 'confirmed',
              url: 'http://test.com/api', project_id: 1, project_name: 'test-project',
              agent_id: 1, language: 'JAVA', first_time: '2024-01-01', latest_time: '2024-01-02', count: 3,
            },
          ],
          page: { alltotal: 1, num_pages: 1, page_size: 20 },
        });
      }
      // GetVulnerability
      if (urlStr.match(/\/api\/v1\/vuln\/\d+$/) && method === 'GET') {
        return createMockResponse({
          status: 201,
          data: {
            id: 1, vul_name: 'SQL注入', vul_type: 'sql_injection',
            level_id: 1, level_name: '高危', state: 'confirmed',
          },
        });
      }
      // UpdateVulnStatus
      if (urlStr.includes('/api/v1/vuln/status') && method === 'POST') {
        assert.deepEqual(JSON.parse(init.body), { vul_id: 1, status_id: 1 });
        return createMockResponse({ status: 201, msg: 'success' });
      }
      // GetVulnSummary
      if (urlStr.includes('/api/v1/vuln/summary_type') && method === 'GET') {
        summaryRequests.push(urlStr);
        return createMockResponse({
          status: 201,
          data: {
            // Exact DongTai 1.14.0 VulSummaryType response keys.
            type: [{ type: 'sql_injection', count: 3 }],
          },
        });
      }
      if (urlStr.includes('/api/v1/vuln/summary_level') && method === 'GET') {
        summaryRequests.push(urlStr);
        return createMockResponse({
          status: 201,
          // Exact DongTai 1.14.0 VulSummaryLevel response keys.
          data: { level: [{ level: '高危', level_id: 1, count: 5 }] },
        });
      }
      // ListProjects
      if (urlStr.includes('/api/v1/projects') && method === 'GET') {
        return createMockResponse({
          status: 201,
          data: [
            { id: 1, name: 'test-project', mode: '插桩模式', agent_count: 1, owner: 'admin', latest_time: '1782468621', agent_language: ['JAVA'], vul_count: [], status: 0 },
          ],
          page: { alltotal: 1, num_pages: 1, page_size: 20 },
        });
      }
      // GetProject
      if (urlStr.match(/\/api\/v1\/project\/\d+$/) && method === 'GET') {
        return createMockResponse({
          status: 201,
          data: { id: 1, name: 'test-project', mode: '插桩模式', versionData: { version_name: 'V1.0' } },
        });
      }
      // CreateProject
      if (urlStr.includes('/api/v1/project/add') && method === 'POST') {
        return createMockResponse({ status: 201, data: { project_id: 2, project_version_id: 3 } });
      }
      // DeleteProject
      if (urlStr.includes('/api/v1/project/delete') && method === 'POST') {
        return createMockResponse({ status: 201, msg: 'success' });
      }
      // ListAgents
      if (urlStr.includes('/api/v1/agents') && method === 'GET') {
        assert.match(urlStr, /[?&]pageSize=20(?:&|$)/);
        assert.doesNotMatch(urlStr, /[?&]page_size=/);
        return createMockResponse({
          status: 201,
          data: [
            { id: 1, token: 'agent-token', alias: 'agent-token', language: 'JAVA', running_status: 'Online', bind_project_id: 1, server: '192.168.1.1', latest_time: '2024-01-01' },
          ],
          page: { alltotal: 1, num_pages: 1, page_size: 20 },
        });
      }
      // GetSystemInfo
      if (urlStr.includes('/api/v1/system/info') && method === 'GET') {
        return createMockResponse({ status: 201, msg: 'success', data: { version: '1.14.0' } });
      }
      // ListStrategies
      if (urlStr.includes('/api/v1/strategys') && method === 'GET') {
        return createMockResponse({
          status: 201,
          data: [
            { id: 41, vul_type: 'FileWrite', vul_name: '文件写入', vul_desc: 'desc', level_id: 3, state: 'enable' },
          ],
        });
      }
      // GetScaDetail
      if (urlStr.match(/\/api\/v1\/sca\/\d+$/) && method === 'GET') {
        return createMockResponse({ status: 201, data: { id: 1, package_name: 'lodash', version: '4.17.0' } });
      }

      return createMockResponse({ status: 404, msg: 'Not Found' }, 404);
    });
  });

  after(() => {
    globalThis.fetch = originalFetch;
  });

  const makeCtx = (req = {}) => ({
    config: { endpoint: MOCK_BASE_URL },
    secret: { apiToken: MOCK_TOKEN },
    req,
    meta: { instance_id: 'test-inst', request_id: 'test-req' },
  });

  it('ListVulnerabilities should return vulns list', async () => {
    const handler = handlers[METHOD_LIST_VULNS_FULL];
    const result = await handler(makeCtx({ page: 1, page_size: 20 }));
    assert.ok(Array.isArray(result.vulns));
    assert.equal(result.vulns.length, 1);
    assert.equal(result.vulns[0].vul_name, 'SQL注入');
    assert.equal(result.total, 1);
  });

  it('ListVulnerabilities should filter by level_id', async () => {
    const handler = handlers[METHOD_LIST_VULNS_FULL];
    const result = await handler(makeCtx({ level_id: 1 }));
    assert.ok(Array.isArray(result.vulns));
  });

  it('GetVulnerability should return vuln detail', async () => {
    const handler = handlers[METHOD_GET_VULN_FULL];
    const result = await handler(makeCtx({ id: 1 }));
    assert.ok(result.vuln);
    assert.equal(result.vuln.id, 1);
    assert.ok(result.raw);
  });

  it('UpdateVulnStatus should update status', async () => {
    const handler = handlers[METHOD_UPDATE_VULN_STATUS_FULL];
    const result = await handler(makeCtx({ id: 1, status_id: 1 }));
    assert.ok(result.raw);
  });

  it('GetVulnSummary should return summary stats', async () => {
    const handler = handlers[METHOD_GET_VULN_SUMMARY_FULL];
    summaryRequests.length = 0;
    const result = await handler(makeCtx({ project_id: 7 }));
    assert.ok(Array.isArray(result.levels));
    assert.ok(Array.isArray(result.types));
    assert.equal(result.levels[0].level, '高危');
    assert.equal(result.types[0].vul_type, 'sql_injection');
    assert.deepEqual(summaryRequests.sort(), [
      `${MOCK_BASE_URL}/api/v1/vuln/summary_level?project_id=7`,
      `${MOCK_BASE_URL}/api/v1/vuln/summary_type?project_id=7`,
    ]);
  });

  it('ListProjects should return projects list', async () => {
    const handler = handlers[METHOD_LIST_PROJECTS_FULL];
    const result = await handler(makeCtx());
    assert.ok(Array.isArray(result.projects));
    assert.equal(result.projects[0].name, 'test-project');
    assert.equal(result.total, 1);
  });

  it('GetProject should return project detail', async () => {
    const handler = handlers[METHOD_GET_PROJECT_FULL];
    const result = await handler(makeCtx({ id: 1 }));
    assert.ok(result.project);
    assert.equal(result.project.name, 'test-project');
  });

  it('CreateProject should create and return project', async () => {
    const handler = handlers[METHOD_CREATE_PROJECT_FULL];
    const result = await handler(makeCtx({ name: 'new-project' }));
    assert.equal(result.id, 2);
    assert.equal(result.name, 'new-project');
  });

  it('DeleteProject should delete project', async () => {
    const handler = handlers[METHOD_DELETE_PROJECT_FULL];
    const result = await handler(makeCtx({ id: 1 }));
    assert.ok(result.raw);
  });

  it('ListAgents should return agents list', async () => {
    const handler = handlers[METHOD_LIST_AGENTS_FULL];
    const result = await handler(makeCtx());
    assert.ok(Array.isArray(result.agents));
    assert.equal(result.agents[0].language, 'JAVA');
    assert.equal(result.agents[0].alias, '');
    assert.equal(Object.hasOwn(result.agents[0], 'token_value'), false);
  });

  it('GetSystemInfo should return system info', async () => {
    const handler = handlers[METHOD_GET_SYSTEM_INFO_FULL];
    const result = await handler(makeCtx());
    assert.ok(result.raw);
  });

  it('ListStrategies should return strategies list', async () => {
    const handler = handlers[METHOD_LIST_STRATEGIES_FULL];
    const result = await handler(makeCtx());
    assert.ok(Array.isArray(result.strategies));
    assert.equal(result.strategies[0].vul_type, 'FileWrite');
  });

  it('GetScaDetail should return SCA detail', async () => {
    const handler = handlers[METHOD_GET_SCA_DETAIL_FULL];
    const result = await handler(makeCtx({ id: 1 }));
    assert.ok(result.raw);
  });
});

// ============ Error Handling Tests ============

describe('Error Handling', () => {
  let originalFetch;

  before(() => {
    originalFetch = globalThis.fetch;
  });

  after(() => {
    globalThis.fetch = originalFetch;
  });

  const makeCtx = (req = {}, overrides = {}) => ({
    config: { endpoint: MOCK_BASE_URL },
    secret: { apiToken: MOCK_TOKEN },
    req,
    ...overrides,
  });

  it('should throw UNAUTHENTICATED for 401', async () => {
    globalThis.fetch = mock.fn(async () => ({
      ok: false, status: 401, headers: { get: () => 'text/plain' },
      text: async () => 'Unauthorized',
    }));
    const handler = handlers[METHOD_LIST_VULNS_FULL];
    await assert.rejects(
      () => handler(makeCtx()),
      (err) => err.message.includes('UNAUTHENTICATED')
    );
  });

  it('should throw PERMISSION_DENIED for 403', async () => {
    globalThis.fetch = mock.fn(async () => ({
      ok: false, status: 403, headers: { get: () => 'text/plain' },
      text: async () => 'Forbidden',
    }));
    const handler = handlers[METHOD_LIST_VULNS_FULL];
    await assert.rejects(
      () => handler(makeCtx()),
      (err) => err.message.includes('PERMISSION_DENIED')
    );
  });

  it('should throw UNAVAILABLE for network error', async () => {
    globalThis.fetch = mock.fn(async () => { throw new Error('ECONNREFUSED'); });
    const handler = handlers[METHOD_LIST_VULNS_FULL];
    await assert.rejects(
      () => handler(makeCtx()),
      (err) => err.message.includes('UNAVAILABLE')
    );
  });

  it('should throw INVALID_ARGUMENT for missing token', async () => {
    const ctxNoToken = {
      config: { endpoint: MOCK_BASE_URL },
      secret: {},
      req: {},
    };
    const handler = handlers[METHOD_LIST_VULNS_FULL];
    await assert.rejects(
      () => handler(ctxNoToken),
      (err) => err.message.includes('INVALID_ARGUMENT') && err.message.includes('token')
    );
  });

  it('should throw INVALID_ARGUMENT for missing endpoint', async () => {
    const ctxNoEndpoint = {
      config: {},
      secret: { apiToken: 'test' },
      req: {},
    };
    const handler = handlers[METHOD_LIST_VULNS_FULL];
    await assert.rejects(
      () => handler(ctxNoEndpoint),
      (err) => err.message.includes('INVALID_ARGUMENT') && err.message.includes('endpoint')
    );
  });

  it('should throw INVALID_ARGUMENT for invalid status_id in UpdateVulnStatus', async () => {
    globalThis.fetch = mock.fn(async () => createMockResponse({ status: 201 }));
    const handler = handlers[METHOD_UPDATE_VULN_STATUS_FULL];
    await assert.rejects(
      () => handler(makeCtx({ id: 1, status_id: 0 })),
      (err) => err.message.includes('INVALID_ARGUMENT') && err.message.includes('positive integer')
    );
  });

  it('rejects negative identifiers and out-of-range pages before making an upstream request', async () => {
    globalThis.fetch = mock.fn(async () => createMockResponse({ status: 201 }));
    await assert.rejects(
      () => handlers[METHOD_GET_PROJECT_FULL](makeCtx({ id: -1 })),
      (err) => err.message.includes('INVALID_ARGUMENT') && err.message.includes('positive integer'),
    );
    await assert.rejects(
      () => handlers[METHOD_LIST_VULNS_FULL](makeCtx({ page: -1 })),
      (err) => err.message.includes('INVALID_ARGUMENT') && err.message.includes('page'),
    );
    await assert.rejects(
      () => handlers[METHOD_LIST_VULNS_FULL](makeCtx({ page_size: 1001 })),
      (err) => err.message.includes('INVALID_ARGUMENT') && err.message.includes('page_size'),
    );
    assert.equal(globalThis.fetch.mock.callCount(), 0);
  });

  it('uses a bounded AbortController timeout and disables redirect following', async () => {
    globalThis.fetch = mock.fn(async (_url, init) => createMockResponse({ status: 201, data: [], page: {} }));
    await handlers[METHOD_LIST_VULNS_FULL](makeCtx());
    const init = globalThis.fetch.mock.calls[0].arguments[1];
    assert.equal(init.redirect, 'error');
    assert.ok(init.signal instanceof AbortSignal);

    globalThis.fetch = mock.fn(async (_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })));
    }));
    await assert.rejects(
      () => handlers[METHOD_LIST_VULNS_FULL](makeCtx({ timeoutMs: undefined, }, { limits: { timeoutMs: 1 } })),
      (err) => err.message.includes('DEADLINE_EXCEEDED'),
    );
  });

  it('keeps the deadline active while reading a slow response body', async () => {
    globalThis.fetch = mock.fn(async (_url, init) => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      text: async () => new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => {
          reject(Object.assign(new Error('body aborted'), { name: 'AbortError' }));
        }, { once: true });
      }),
    }));

    await assert.rejects(
      () => handlers[METHOD_LIST_VULNS_FULL](makeCtx({}, { limits: { timeoutMs: 5 } })),
      (err) => err.message.includes('DEADLINE_EXCEEDED'),
    );
  });

  it('starts both summary endpoint requests concurrently', async () => {
    let started = 0;
    let releaseBarrier;
    const barrier = new Promise((resolve) => { releaseBarrier = resolve; });
    globalThis.fetch = mock.fn(async (url) => {
      const urlStr = String(url);
      started += 1;
      if (started === 2) releaseBarrier();
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        text: async () => {
          await barrier;
          return JSON.stringify(urlStr.includes('/summary_type')
            ? { status: 201, data: { type: [{ type: 'x', count: 1 }] } }
            : { status: 201, data: { level: [{ level: '高危', level_id: 1, count: 1 }] } });
        },
      };
    });

    const result = await handlers[METHOD_GET_VULN_SUMMARY_FULL](makeCtx());
    assert.equal(started, 2);
    assert.equal(result.types[0].vul_type, 'x');
    assert.equal(result.levels[0].level, '高危');
  });

  it('aborts and settles the slow summary sibling while preserving the original error', async () => {
    const requested = [];
    let siblingAborted = false;
    globalThis.fetch = mock.fn(async (url, init) => {
      const urlStr = String(url);
      requested.push(urlStr);
      if (urlStr.includes('/summary_type')) {
        return {
          ok: true,
          status: 200,
          headers: { get: () => null },
          text: async () => new Promise((_resolve, reject) => {
            const rejectCancelled = () => {
              siblingAborted = true;
              reject(Object.assign(new Error('sibling aborted'), { name: 'AbortError' }));
            };
            if (init.signal.aborted) rejectCancelled();
            else init.signal.addEventListener('abort', rejectCancelled, { once: true });
          }),
        };
      }
      return createMockResponse({ status: 500 }, 503);
    });

    await assert.rejects(
      () => handlers[METHOD_GET_VULN_SUMMARY_FULL](makeCtx({ project_id: 9 })),
      (err) => err.message.includes('UNAVAILABLE') && err.message.includes('503'),
    );
    assert.deepEqual(requested, [
      `${MOCK_BASE_URL}/api/v1/vuln/summary_type?project_id=9`,
      `${MOCK_BASE_URL}/api/v1/vuln/summary_level?project_id=9`,
    ]);
    assert.equal(siblingAborted, true);
    const siblingCancellation = errorWithCode('CANCELLED', 'request cancelled');
    assert.equal(siblingCancellation.legacyCode, 'CANCELLED');
    assert.equal(siblingCancellation.code, 1);
  });

  it('uses an undici dispatcher only when TLS verification is explicitly disabled', async () => {
    globalThis.fetch = mock.fn(async () => createMockResponse({ status: 201, data: [], page: {} }));
    await handlers[METHOD_LIST_VULNS_FULL]({
      config: { endpoint: MOCK_BASE_URL, skipTlsVerify: true }, secret: { apiToken: MOCK_TOKEN }, req: {},
    });
    const insecureInit = globalThis.fetch.mock.calls[0].arguments[1];
    assert.ok(insecureInit.dispatcher);
    assert.equal(Object.hasOwn(insecureInit, 'insecureSkipVerify'), false);
    assert.equal(Object.hasOwn(insecureInit, 'tlsInsecureSkipVerify'), false);

    globalThis.fetch = mock.fn(async () => createMockResponse({ status: 201, data: [], page: {} }));
    await handlers[METHOD_LIST_VULNS_FULL]({
      config: { endpoint: MOCK_BASE_URL, skipTlsVerify: 'false' }, secret: { apiToken: MOCK_TOKEN }, req: {},
    });
    assert.equal(Object.hasOwn(globalThis.fetch.mock.calls[0].arguments[1], 'dispatcher'), false);
  });

  it('does not expose or log upstream response bodies', async () => {
    const secret = 'super-secret-upstream-body';
    const originalError = console.error;
    const logs = [];
    console.error = (...args) => logs.push(args.join(' '));
    globalThis.fetch = mock.fn(async () => ({
      ok: false, status: 500, headers: { get: () => 'text/plain' }, text: async () => secret,
    }));
    try {
      await assert.rejects(
        () => handlers[METHOD_LIST_VULNS_FULL](makeCtx()),
        (err) => err.message.includes('UNAVAILABLE') && !err.message.includes(secret),
      );
    } finally {
      console.error = originalError;
    }
    assert.equal(logs.some((entry) => entry.includes(secret)), false);
  });

  it('maps other upstream and malformed response failures without leaking response data', async () => {
    globalThis.fetch = mock.fn(async () => ({
      ok: false, status: 429, headers: { get: () => 'text/plain' }, text: async () => 'rate-limit-secret',
    }));
    await assert.rejects(
      () => handlers[METHOD_LIST_VULNS_FULL](makeCtx()),
      (err) => err.message.includes('FAILED_PRECONDITION') && !err.message.includes('rate-limit-secret'),
    );

    globalThis.fetch = mock.fn(async () => ({
      ok: true, status: 200, headers: { get: () => 'application/json' }, text: async () => '{not-json',
    }));
    await assert.rejects(
      () => handlers[METHOD_LIST_VULNS_FULL](makeCtx()),
      (err) => err.message.includes('UNKNOWN') && err.message.includes('valid JSON'),
    );
  });

  it('accepts a streamed response and rejects bounded response overflows', async () => {
    globalThis.fetch = mock.fn(async () => new Response(JSON.stringify({ status: 201, data: [], page: {} }), {
      status: 200, headers: { 'content-type': 'application/json' },
    }));
    assert.deepEqual((await handlers[METHOD_LIST_VULNS_FULL](makeCtx())).vulns, []);

    globalThis.fetch = mock.fn(async () => ({
      ok: true, status: 200, headers: { get: (name) => name === 'content-length' ? '1048577' : null },
      text: async () => '{}',
    }));
    await assert.rejects(
      () => handlers[METHOD_LIST_VULNS_FULL](makeCtx()),
      (err) => err.message.includes('RESOURCE_EXHAUSTED'),
    );

    globalThis.fetch = mock.fn(async () => ({
      ok: true, status: 200, headers: { get: () => null },
      text: async () => 'x'.repeat(1024 * 1024 + 1),
    }));
    await assert.rejects(
      () => handlers[METHOD_LIST_VULNS_FULL](makeCtx()),
      (err) => err.message.includes('RESOURCE_EXHAUSTED'),
    );

    globalThis.fetch = mock.fn(async () => ({
      ok: true, status: 200, headers: { get: () => null },
      body: new ReadableStream({
        start(controller) { controller.enqueue(new Uint8Array(1024 * 1024 + 1)); },
      }),
    }));
    await assert.rejects(
      () => handlers[METHOD_LIST_VULNS_FULL](makeCtx()),
      (err) => err.message.includes('RESOURCE_EXHAUSTED'),
    );
  });

  it('maps sparse official-style envelopes for every RPC without throwing', async () => {
    globalThis.fetch = mock.fn(async () => createMockResponse({ status: 201, data: [{}], page: {} }));
    const calls = [
      [METHOD_LIST_VULNS_FULL, {}], [METHOD_GET_VULN_FULL, { id: 1 }],
      [METHOD_UPDATE_VULN_STATUS_FULL, { id: 1, status_id: 1 }], [METHOD_GET_VULN_SUMMARY_FULL, {}],
      [METHOD_LIST_PROJECTS_FULL, {}], [METHOD_GET_PROJECT_FULL, { id: 1 }],
      [METHOD_CREATE_PROJECT_FULL, { name: 'sparse' }], [METHOD_DELETE_PROJECT_FULL, { id: 1 }],
      [METHOD_LIST_AGENTS_FULL, {}], [METHOD_GET_SYSTEM_INFO_FULL, {}], [METHOD_LIST_STRATEGIES_FULL, {}],
      [METHOD_GET_SCA_DETAIL_FULL, { id: 1 }],
    ];
    for (const [method, request] of calls) {
      await handlers[method](makeCtx(request));
    }
    // GetVulnSummary makes one request for summary_type and one for
    // summary_level; every other RPC makes a single upstream request.
    assert.equal(globalThis.fetch.mock.callCount(), calls.length + 1);
  });

  it('rejects CRLF token injection and clamps an excessive timeout', async () => {
    await assert.rejects(
      () => handlers[METHOD_LIST_VULNS_FULL]({ config: { endpoint: MOCK_BASE_URL }, secret: { apiToken: 'a\r\nb' }, req: {} }),
      (err) => err.message.includes('INVALID_ARGUMENT') && err.message.includes('line breaks'),
    );
    globalThis.fetch = mock.fn(async (_url, init) => createMockResponse({ status: 201, data: [], page: {} }));
    await handlers[METHOD_LIST_VULNS_FULL]({
      config: { endpoint: MOCK_BASE_URL, timeoutMs: 999999999 }, secret: { apiToken: MOCK_TOKEN }, req: {},
    });
    assert.ok(globalThis.fetch.mock.calls[0].arguments[1].signal);
  });

  it('accepts the SDK single-context ABI with ctx.request', async () => {
    globalThis.fetch = mock.fn(async () => createMockResponse({ status: 201, data: [], page: {} }));
    const result = await handlers[METHOD_LIST_VULNS_FULL]({
      config: { endpoint: MOCK_BASE_URL }, secret: { apiToken: MOCK_TOKEN }, request: { page: 2 },
    });
    assert.deepEqual(result.vulns, []);
    assert.equal(handlers[METHOD_LIST_VULNS_FULL].length, 1);
  });
});

// ============ Config/Secret Binding Tests ============

describe('Config/Secret Binding', () => {
  it('should use endpoint from config', () => {
    const bindings = mergedBindings({ config: { endpoint: 'http://dt.local:9090' }, secret: { apiToken: 'abc' } });
    assert.equal(bindings.endpoint, 'http://dt.local:9090');
    assert.equal(bindings.apiToken, 'abc');
  });

  it('should support legacy baseUrl alias', () => {
    const bindings = mergedBindings({ config: { baseUrl: 'http://dt.local:9090' }, secret: {} });
    assert.equal(bindings.baseUrl, 'http://dt.local:9090');
  });

  it('should prefer endpoint over baseUrl', () => {
    const bindings = mergedBindings({ config: { endpoint: 'http://first:9090', baseUrl: 'http://second:9090' }, secret: {} });
    const url = normalizeBaseUrl(bindings.endpoint || bindings.baseUrl);
    assert.equal(url, 'http://first:9090');
  });
});
