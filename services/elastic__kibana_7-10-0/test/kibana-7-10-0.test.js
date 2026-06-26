import assert from 'node:assert/strict';
import test from 'node:test';

import { GrpcError } from '@chaitin-ai/octobus-sdk';
import { handlers, _test } from '../src/kibana-7-10-0.js';
import { service } from '../src/service.js';
import { DEFAULT_PASSWORD, DEFAULT_USER, createMockServer } from './mock_upstream.js';

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

test('buildHeaders with space', () => {
  const ctx = { bindings: { username: 'elastic', password: 'changeme' }, req: { space: 'custom' } };
  const headers = _test.buildHeaders({ bindings: mergedBindings(ctx), req: ctx.req });
  assert.equal(headers['kbn-space'], 'custom');
});

test('tryParseJson failure and ensureSuccess error mapping', () => {
  assert.equal(_test.tryParseJson('not json').ok, false);
  try { _test.ensureSuccess({ httpStatus: 500, httpBody: 'error' }, 'Test'); assert.fail('expected error'); } catch (e) { assert.equal(e.legacyCode, 'UNAVAILABLE'); }
  try { _test.ensureSuccess({ httpStatus: 401, httpBody: 'denied' }, 'Test'); assert.fail('expected error'); } catch (e) { assert.equal(e.legacyCode, 'PERMISSION_DENIED'); }
});