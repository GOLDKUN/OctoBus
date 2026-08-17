import assert from 'node:assert/strict';
import test from 'node:test';

import { GrpcError } from '@chaitin-ai/octobus-sdk';
import { handlers, _test, rpcdef } from '../src/kibana-7-10-0.js';
import { service } from '../src/service.js';
import { DEFAULT_PASSWORD, DEFAULT_USER, createMockServer } from './mock_upstream.js';

const originalFetch = globalThis.fetch;

test.afterEach(() => {
  globalThis.fetch = originalFetch;
});

const buildCtx = (overrides = {}) => ({
  config: { baseUrl: 'https://kibana.example.com:5601', timeoutMs: 4000, ...(overrides.config || {}) },
  secret: { username: DEFAULT_USER, password: DEFAULT_PASSWORD, ...(overrides.secret || {}) },
  bindings: overrides.bindings || {},
  limits: { timeoutMs: 4000, ...(overrides.limits || {}) },
  req: overrides.req || {},
});

const expectGrpcError = async (fn, legacyCode) => {
  try { await fn(); assert.fail('expected rejection'); } catch (err) { assert.ok(err instanceof GrpcError); assert.equal(err.legacyCode, legacyCode); }
};

function mergedBindings(ctx) { return { ...(ctx.config ?? {}), ...(ctx.secret ?? {}), ...(ctx.bindings ?? {}) }; }

test('service exports handlers', () => { assert.equal(typeof service, 'object'); assert.equal(typeof handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetStatus'], 'function'); });

test('validates baseUrl', async () => { await expectGrpcError(() => handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetStatus']({}, buildCtx({ config: { baseUrl: '' } })), 'INVALID_ARGUMENT'); });

test('validates credentials', async () => { await expectGrpcError(() => handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetStatus']({}, buildCtx({ secret: { username: '', password: '' } })), 'INVALID_ARGUMENT'); });

test('GetStatus returns server info', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const result = await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetStatus']({}, buildCtx({ config: { baseUrl } }));
    assert.equal(result.name, 'mock-kibana');
    assert.equal(result.uuid, 'kibana-uuid-001');
    assert.equal(result.version, '7.10.0');
    assert.equal(result.statuses.length, 2);
    assert.equal(result.statuses[0].state, 'green');
  } finally { await mock.close(); }
});

test('ListSpaces returns spaces', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const result = await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ListSpaces']({}, buildCtx({ config: { baseUrl } }));
    assert.equal(result.spaces.length, 2);
    assert.equal(result.spaces[0].id, 'default');
    assert.equal(result.spaces[1].id, 'custom');
  } finally { await mock.close(); }
});

test('GetSpace returns single space', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const result = await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSpace']({ id: 'custom' }, buildCtx({ config: { baseUrl } }));
    assert.equal(result.id, 'custom');
    assert.equal(result.name, 'Space custom');
  } finally { await mock.close(); }
});

test('GetSpace requires id', async () => {
  await expectGrpcError(() => handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSpace']({}, buildCtx()), 'INVALID_ARGUMENT');
});

test('FindSavedObjects requires type', async () => {
  await expectGrpcError(() => handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/FindSavedObjects']({}, buildCtx()), 'INVALID_ARGUMENT');
});

test('FindSavedObjects returns results', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const result = await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/FindSavedObjects']({ type: 'dashboard' }, buildCtx({ config: { baseUrl } }));
    assert.equal(result.total, 2);
    assert.equal(result.saved_objects.length, 2);
    assert.equal(result.saved_objects[0].type, 'index-pattern');
  } finally { await mock.close(); }
});

test('FindSavedObjects with sort fields', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const result = await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/FindSavedObjects'](
      { type: 'dashboard', search: 'test', sort_field: 'title', sort_order: 'asc', fields: ['title', 'type'] },
      buildCtx({ config: { baseUrl } }),
    );
    assert.ok(result.total >= 0);
    assert.deepEqual(mock.requests.at(-1).queryAll.fields, ['title', 'type']);
  } finally { await mock.close(); }
});

test('GetSavedObject requires type and id', async () => {
  await expectGrpcError(() => handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSavedObject']({}, buildCtx()), 'INVALID_ARGUMENT');
  await expectGrpcError(() => handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSavedObject']({ type: 'dashboard' }, buildCtx()), 'INVALID_ARGUMENT');
});

test('GetSavedObject returns object', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const result = await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSavedObject']({ type: 'dashboard', id: 'obj-1' }, buildCtx({ config: { baseUrl } }));
    assert.equal(result.id, 'obj-1');
    assert.equal(result.type, 'dashboard');
    assert.equal(result.version, 'WzEsMV0=');
    assert.ok(result.attributes_json.includes('Test Object'));
  } finally { await mock.close(); }
});

test('BulkGetSavedObjects batch-fetches objects', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const result = await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/BulkGetSavedObjects'](
      { objects: [{ type: 'dashboard', id: 'obj-1' }, { type: 'index-pattern', id: 'obj-2' }] },
      buildCtx({ config: { baseUrl } }),
    );
    assert.equal(result.saved_objects.length, 2);
    assert.equal(result.saved_objects[0].type, 'dashboard');
    assert.equal(result.saved_objects[0].version, 'WzEsMV0=');
    assert.equal(JSON.parse(result.saved_objects[0].raw_body).id, 'obj-1');
  } finally { await mock.close(); }
});

test('BulkGetSavedObjects requires objects', async () => {
  await expectGrpcError(() => handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/BulkGetSavedObjects']({}, buildCtx()), 'INVALID_ARGUMENT');
});

test('ExportSavedObjects requires type', async () => {
  await expectGrpcError(() => handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ExportSavedObjects']({}, buildCtx()), 'INVALID_ARGUMENT');
});

test('ExportSavedObjects creates NDJSON', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const result = await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ExportSavedObjects']({ type: 'dashboard' }, buildCtx({ config: { baseUrl } }));
    assert.ok(result.ndjson.includes('obj-1'));
    assert.ok(result.exported_count > 0);
  } finally { await mock.close(); }
});

test('ExportSavedObjects with object array', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const result = await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ExportSavedObjects'](
      { type: 'dashboard', objects: ['obj-1', 'obj-2'], include_references_deep: true },
      buildCtx({ config: { baseUrl } }),
    );
    assert.ok(result.ndjson.length > 0);
  } finally { await mock.close(); }
});

test('resolveBaseUrl with aliases', () => {
  assert.equal(_test.resolveBaseUrl({ kibana_domain: 'https://kibana.test:5601' }), 'https://kibana.test:5601');
  assert.equal(_test.resolveBaseUrl({ domain: 'https://kb.test:5601' }), 'https://kb.test:5601');
  assert.equal(_test.resolveBaseUrl({ url: 'https://u.test:5601' }), 'https://u.test:5601');
  assert.equal(_test.resolveBaseUrl({}), '');
});

test('resolveUsername and resolvePassword with aliases', () => {
  assert.equal(_test.resolveUsername({ username: 'u1' }), 'u1');
  assert.equal(_test.resolveUsername({ kibana_username: 'u2' }), 'u2');
  assert.equal(_test.resolveUsername({ user: 'u3' }), 'u3');
  assert.equal(_test.resolvePassword({ password: 'p1' }), 'p1');
  assert.equal(_test.resolvePassword({ kibana_password: 'p2' }), 'p2');
  assert.equal(_test.resolvePassword({ passwd: 'p3' }), 'p3');
});

test('buildHeaders authenticates without nonstandard space header', () => {
  const ctx = { bindings: { username: 'elastic', password: 'changeme' }, req: { space: 'custom' } };
  const headers = _test.buildHeaders({ bindings: mergedBindings(ctx), req: ctx.req });
  assert.equal(headers.Authorization, `Basic ${Buffer.from('elastic:changeme').toString('base64')}`);
  assert.equal(headers['kbn-space'], undefined);
});

test('tryParseJson failure and ensureSuccess error mapping', () => {
  assert.equal(_test.tryParseJson('not json').ok, false);
  try { _test.ensureSuccess({ httpStatus: 500, httpBody: 'error' }, 'Test'); assert.fail('expected error'); } catch (e) { assert.equal(e.legacyCode, 'UNAVAILABLE'); }
  try { _test.ensureSuccess({ httpStatus: 401, httpBody: 'denied' }, 'Test'); assert.fail('expected error'); } catch (e) { assert.equal(e.legacyCode, 'PERMISSION_DENIED'); }
});

test('BulkGetSavedObjects uses Kibana 7.10 array body and a URL space prefix', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/BulkGetSavedObjects'](
      { space: 'custom space', objects: [{ type: 'dashboard', id: 'obj-1' }] },
      buildCtx({ config: { baseUrl } }),
    );
    assert.equal(mock.requests.at(-1).path, '/s/custom%20space/api/saved_objects/_bulk_get');
    assert.deepEqual(mock.requests.at(-1).body, [{ type: 'dashboard', id: 'obj-1' }]);
  } finally { await mock.close(); }
});

test('every RPC accepts the SDK single-context ABI', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const ctx = buildCtx({ config: { baseUrl } });
    const cases = [
      ['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetStatus', {}],
      ['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ListSpaces', {}],
      ['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSpace', { id: 'custom' }],
      ['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/FindSavedObjects', { type: 'dashboard' }],
      ['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSavedObject', { type: 'dashboard', id: 'obj-1' }],
      ['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/BulkGetSavedObjects', { objects: [{ type: 'dashboard', id: 'obj-1' }] }],
      ['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ExportSavedObjects', { type: 'dashboard' }],
    ];
    for (const [method, request] of cases) {
      const result = await handlers[method]({ ...ctx, request });
      assert.ok(result, method);
    }
  } finally { await mock.close(); }
});

test('transport uses AbortSignal, refuses redirects, and supports the Undici TLS dispatcher', async () => {
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url: String(url), init };
    return new Response(JSON.stringify({ name: 'mock', version: { number: '7.10.0' }, statuses: [] }), { status: 200 });
  };
  await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetStatus']({}, buildCtx({ bindings: { skipTlsVerify: 'true' } }));
  assert.ok(captured.init.signal instanceof AbortSignal);
  assert.equal(captured.init.redirect, 'error');
  assert.ok(captured.init.dispatcher, 'skipTlsVerify supplies an Undici dispatcher');
  assert.equal(Object.hasOwn(captured.init, 'timeoutMs'), false);
});

test('timeout, oversized responses, and upstream error bodies do not leak secrets', async () => {
  const secret = 'never-log-this-password';
  globalThis.fetch = (_url, init) => new Promise((_resolve, reject) => {
    init.signal.addEventListener('abort', () => reject(Object.assign(new Error(secret), { name: 'AbortError' })), { once: true });
  });
  await expectGrpcError(
    () => handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetStatus']({}, buildCtx({ limits: { timeoutMs: 5 } })),
    'DEADLINE_EXCEEDED',
  );

  globalThis.fetch = async () => new Response('x'.repeat(32), { status: 200 });
  await expectGrpcError(
    () => handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetStatus']({}, buildCtx({ limits: { maxResponseBytes: 16 } })),
    'RESOURCE_EXHAUSTED',
  );

  globalThis.fetch = async () => new Response(`upstream says ${secret}`, { status: 500 });
  try {
    await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetStatus']({}, buildCtx());
    assert.fail('expected rejection');
  } catch (err) {
    assert.equal(err.legacyCode, 'UNAVAILABLE');
    assert.equal(err.message.includes(secret), false);
    assert.equal(err.response.http_body, '');
  }
});

test('base URLs with credentials, queries, or fragments are rejected and log URLs are redacted', async () => {
  assert.equal(_test.resolveBaseUrl('https://user:pass@kibana.example:5601'), '');
  assert.equal(_test.resolveBaseUrl('https://kibana.example:5601/?token=secret'), '');
  assert.equal(_test.redactUrl('https://user:pass@kibana.example:5601/api/status?token=secret'), 'https://kibana.example:5601/api/status');
  assert.equal(_test.redactUrl('not a URL'), '<invalid-url>');
  assert.equal(_test.toBool('off'), false);
  assert.equal(_test.toBool('yes'), true);
  assert.equal(_test.toBool(0), false);
  assert.equal(_test.toBool('unexpected', true), true);
  assert.equal(_test.resolveTimeoutMs({ bindings: { timeoutMs: 0 } }), 5000);
  assert.equal(_test.resolveMaxResponseBytes({ bindings: { maxResponseBytes: -1 } }), 4 * 1024 * 1024);
  assert.equal(_test.resolveMaxResponseBytes({ bindings: { maxResponseBytes: 99 * 1024 * 1024 } }), 16 * 1024 * 1024);
  assert.equal(_test.shouldSkipTlsVerify({ skipTlsVerify: 'false', insecureSkipVerify: true }), true);
  assert.equal(_test.shouldSkipTlsVerify({ skipTlsVerify: false, tlsInsecureSkipVerify: false, insecureSkipVerify: 'off' }), false);
  assert.equal(_test.shouldSkipTlsVerify({ tlsInsecureSkipVerify: true }), true);
  assert.equal(_test.shouldSkipTlsVerify({ insecureSkipVerify: 'on' }), true);
  assert.deepEqual(await _test.buildTlsOptions({ skipTlsVerify: false }), {});
  assert.equal(_test.isRuntimeContext({}), false);
  assert.equal(_test.isRuntimeContext({ config: {} }), true);
  assert.equal(_test.isRuntimeContext({ secret: {} }), true);
  assert.equal(_test.isRuntimeContext({ bindings: {} }), true);
  assert.equal(_test.isRuntimeContext({ request: {} }), true);
  assert.equal(_test.isRuntimeContext({ req: {} }), true);
  const circular = {}; circular.self = circular;
  assert.equal(_test.toJsonString(circular), '');
});

test('JSON parse and body readers cover empty, malformed, declared, and fallback responses', async () => {
  await expectGrpcError(
    () => Promise.resolve().then(() => _test.parseJsonOrThrowUnknown({ httpStatus: 200, httpBody: '' }, 'Test')),
    'UNKNOWN',
  );
  await expectGrpcError(
    () => Promise.resolve().then(() => _test.parseJsonOrThrowUnknown({ httpStatus: 200, httpBody: '{' }, 'Test')),
    'UNKNOWN',
  );
  await expectGrpcError(
    () => _test.readResponseBody({ headers: new Headers({ 'content-length': '32' }), body: null, text: async () => 'ok' }, 16),
    'RESOURCE_EXHAUSTED',
  );
  assert.equal(await _test.readResponseBody({ headers: new Headers(), body: null, text: async () => 'fallback' }, 16), 'fallback');
  try { _test.ensureSuccess({ httpStatus: 404, httpBody: 'missing' }, 'Test'); assert.fail('expected error'); } catch (err) { assert.equal(err.legacyCode, 'FAILED_PRECONDITION'); }
});

test('saved-object references and export metadata map every response branch', async () => {
  globalThis.fetch = async (url) => {
    if (String(url).includes('_export')) {
      return new Response('{"id":"obj-1"}\nnot-json\n{"exportedCount":0,"missingReferences":[{"type":"dashboard","id":"missing"}]}\n', { status: 200 });
    }
    return new Response(JSON.stringify({
      id: 'obj-1', type: 'dashboard', references: [{ name: 'ref', type: 'index-pattern', id: 'pattern-1' }],
    }), { status: 200 });
  };
  const ctx = buildCtx();
  const object = await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSavedObject']({ type: 'dashboard', id: 'obj-1' }, ctx);
  assert.deepEqual(object.references, [{ name: 'ref', type: 'index-pattern', id: 'pattern-1' }]);
  const exported = await handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ExportSavedObjects']({ type: 'dashboard' }, ctx);
  assert.equal(exported.exported_count, 0, 'explicit exportedCount=0 is not replaced with a line-count fallback');
  assert.equal(exported.total_count, 0, 'summary lines are not counted as exported objects');
  assert.deepEqual(exported.missing_refs, ['dashboard:missing']);
});

test('ExportSavedObjects normalizes text booleans and sends either type or objects', async () => {
  const bodies = [];
  globalThis.fetch = async (_url, init) => {
    bodies.push(JSON.parse(init.body));
    return new Response('{"id":"obj-1"}\n', { status: 200 });
  };
  const method = handlers['Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ExportSavedObjects'];
  const byType = await method({ type: 'dashboard', include_references_deep: 'false' }, buildCtx());
  const byObjects = await method({ type: 'dashboard', objects: ['obj-1'], include_references_deep: 'true' }, buildCtx());
  assert.deepEqual(bodies[0], { type: 'dashboard' });
  assert.deepEqual(bodies[1], { objects: [{ type: 'dashboard', id: 'obj-1' }], includeReferencesDeep: true });
  assert.equal(byType.total_count, 1);
  assert.equal(byType.exported_count, 1);
  assert.equal(byObjects.total_count, 1);
});

test('legacy rpcdef exposes all seven deterministic routes', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const routes = rpcdef(buildCtx({ config: { baseUrl } }));
    await routes['/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetStatus']();
    await routes['/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ListSpaces']();
    await routes['/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSpace']({ id: 'custom' });
    await routes['/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/FindSavedObjects']({ type: 'dashboard' });
    await routes['/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/GetSavedObject']({ type: 'dashboard', id: 'obj-1' });
    await routes['/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/BulkGetSavedObjects']({ objects: [{ type: 'dashboard', id: 'obj-1' }] });
    await routes['/Elastic_Kibana_7_10_0.Elastic_Kibana_7_10_0/ExportSavedObjects']({ type: 'dashboard' });
  } finally { await mock.close(); }
});
