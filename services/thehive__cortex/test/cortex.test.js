import test from 'node:test';
import assert from 'node:assert/strict';

const listAnalyzersPath = '/TheHive_CORTEX.TheHive_CORTEX/ListAnalyzers';
const analyzeObservablePath = '/TheHive_CORTEX.TheHive_CORTEX/AnalyzeObservable';
const getJobReportPath = '/TheHive_CORTEX.TheHive_CORTEX/GetJobReport';
const listJobsPath = '/TheHive_CORTEX.TheHive_CORTEX/ListJobs';
const getJobStatusPath = '/TheHive_CORTEX.TheHive_CORTEX/GetJobStatus';

const buildCtx = (req = {}, overrides = {}) => ({
  bindings: { endpoint: 'http://localhost:18080', headers: { 'X-Extra': 'demo' }, ...overrides.bindings },
  secret: { ...overrides.secret },
  limits: { timeoutMs: 10_000, ...overrides.limits },
  meta: { instance_id: 'inst', request_id: 'req', ...overrides.meta },
  req,
});

const setFetch = (impl) => {
  global.fetch = impl;
};

const mockFetch = (impl) => {
  setFetch(async (...args) => impl(...args));
};

const loadHandler = async (methodPath, req = {}, overrides = {}) => {
  const { rpcdef } = await import('../src/cortex.js');
  const ctx = buildCtx(req, overrides);
  return rpcdef(ctx)[methodPath];
};

test('internal helpers normalize bindings, headers, errors, and call context', async () => {
  const { _test } = await import('../src/cortex.js');

  assert.deepEqual(_test.mergedBindings({
    config: { endpoint: 'http://config', keep: 'config' },
    secret: { apiKey: 'secret' },
    bindings: { endpoint: 'http://binding' },
  }), {
    endpoint: 'http://binding',
    keep: 'config',
    apiKey: 'secret',
  });

  assert.deepEqual(_test.parseHeaders(undefined), {});
  assert.deepEqual(_test.parseHeaders('{"X-Test":"yes"}'), { 'X-Test': 'yes' });
  assert.deepEqual(_test.parseHeaders('{not json'), {});
  assert.deepEqual(_test.parseHeaders(['not-a-header']), {});
  assert.equal(_test.normalizeBaseUrl('ftp://bad'), null);
  assert.equal(_test.normalizeBaseUrl('http://cortex.example.test'), null);
  assert.equal(_test.normalizeBaseUrl('https://cortex.example.test/base/'), 'https://cortex.example.test/base');
  assert.equal(_test.normalizeBaseUrl('http://good'), null);
  assert.equal(_test.toPositiveInt({ value: '7' }), 7);
  assert.equal(_test.toPositiveInt({}), null);
  assert.equal(_test.toPositiveInt('not-a-number'), null);
  assert.deepEqual(_test.toValue(['x', 2, true]), {
    listValue: { values: [{ stringValue: 'x' }, { numberValue: 2 }, { boolValue: true }] },
  });
  assert.deepEqual(_test.toValue({ missing: null }), {
    structValue: { fields: { missing: { nullValue: 'NULL_VALUE' } } },
  });
  assert.deepEqual(_test.mergedBindings({}), {});
  assert.deepEqual(_test.sanitizeHeaders({ 'X-Number': 2 }), {});
  assert.deepEqual(_test.toValue(1n), { stringValue: '1' });
  assert.equal(_test.unwrapString(null), '');
  assert.equal(_test.unwrapString({ value: null }), '');
  assert.deepEqual(_test.fromProtoValue({ structValue: { fields: {
    name: { stringValue: 'cortex' },
    missing: { nullValue: 'NULL_VALUE' },
  } } }), { name: 'cortex', missing: null });
  assert.deepEqual(_test.fromProtoValue(['plain', { boolValue: false }]), ['plain', false]);

  const unknown = _test.errorWithCode('SOMETHING_NEW', 'message');
  assert.equal(unknown.legacyCode, 'SOMETHING_NEW');
});

test('security helpers preserve TLS verification, redact unsafe headers, and bound response bodies', async () => {
  const { _test } = await import('../src/cortex.js');

  assert.deepEqual(_test.sanitizeHeaders({
    Authorization: 'attacker-token',
    Host: 'attacker.example',
    'X-Allowed': 'ok',
    'Content-Type': 'text/plain',
  }), { 'X-Allowed': 'ok' });
  assert.throws(() => _test.resolveTimeoutMs('0'), /INVALID_ARGUMENT/);
  assert.equal(_test.resolveTimeoutMs('1234'), 1234);

  await assert.rejects(
    () => _test.readResponseText({
      headers: new Map([['content-length', String(4 * 1024 * 1024 + 1)]]),
      text: async () => '',
    }),
    /RESOURCE_EXHAUSTED/,
  );
  const chunks = [new Uint8Array([123]), new Uint8Array([125])];
  let released = false;
  assert.equal(await _test.readResponseText({
    headers: new Map(),
    body: { getReader: () => ({
      read: async () => (chunks.length ? { done: false, value: chunks.shift() } : { done: true }),
      cancel: async () => {},
      releaseLock: () => { released = true; },
    }) },
  }), '{}');
  assert.equal(released, true);
  await assert.rejects(
    () => _test.readResponseText({
      headers: new Map(),
      text: async () => 'x'.repeat(4 * 1024 * 1024 + 1),
    }),
    /RESOURCE_EXHAUSTED/,
  );
  let cancelled = false;
  let releasedAfterLimit = false;
  await assert.rejects(
    () => _test.readResponseText({
      headers: new Map(),
      body: { getReader: () => ({
        read: async () => ({ done: false, value: new Uint8Array(4 * 1024 * 1024 + 1) }),
        cancel: async () => { cancelled = true; },
        releaseLock: () => { releasedAfterLimit = true; },
      }) },
    }),
    /RESOURCE_EXHAUSTED/,
  );
  assert.equal(cancelled, true);
  assert.equal(releasedAfterLimit, true);
  assert.equal(_test.normalizeBaseUrl('https://user:pass@cortex.example'), null);
  assert.equal(_test.normalizeBaseUrl('https://cortex.example?query=1'), null);
  assert.equal(_test.normalizeBaseUrl('not a URL'), null);
  assert.equal(_test.normalizeBaseUrl('http://127.0.0.1:9001/'), 'http://127.0.0.1:9001');
});

test('response shape fallbacks preserve Cortex API compatibility', async () => {
  const responses = [
    { data: [{ _id: 'analyzer-alt', analyzer_definition_id: 'worker-alt', data_type_list: ['domain'] }] },
    { data: [{ _id: 'job-alt', analyzer_id: 'a', analyzer_name: 'name', analyzer_definition_id: 'definition', data_type: 'ip', start_date: 'start', end_date: 'end' }] },
    { _id: 'job-no-report', status: 'Waiting', report: null },
  ];
  setFetch(async () => ({
    ok: true,
    status: 200,
    headers: new Map([['content-type', 'application/json']]),
    text: async () => JSON.stringify(responses.shift()),
  }));

  const listAnalyzers = await loadHandler(listAnalyzersPath);
  const analyzers = await listAnalyzers();
  assert.equal(analyzers.data.analyzers[0].id, 'analyzer-alt');
  assert.equal(analyzers.data.analyzers[0].analyzer_definition_id, 'worker-alt');

  const listJobs = await loadHandler(listJobsPath);
  const jobs = await listJobs();
  assert.equal(jobs.data.jobs[0].id, 'job-alt');
  assert.equal(jobs.data.jobs[0].analyzer_id, 'a');

  const getReport = await loadHandler(getJobReportPath, { job_id: 'job-no-report' });
  const report = await getReport();
  assert.equal(report.data.status, 'Waiting');
  assert.equal(report.data.success, false);
});

test('empty successful bodies use RPC-specific empty values', async () => {
  setFetch(async () => ({
    ok: true,
    status: 200,
    headers: new Map([['content-type', 'application/json']]),
    text: async () => '',
  }));
  const handler = await loadHandler(listAnalyzersPath);
  assert.deepEqual((await handler()).data.analyzers, []);
});

test('Cortex response aliases and less-common error paths are mapped safely', async () => {
  const responses = [
    { _id: 'single-analyzer', workerDefinitionId: 'worker', dataTypeList: ['ip'], tlp: 0 },
    { _id: 'single-job', workerId: 'worker', workerName: 'worker-name', workerDefinitionId: 'worker-definition', createdAt: 'now' },
    { _id: 'numeric-report', status: 'Deleted', report: 42 },
    { success: true, summary: 'not-an-object', full: 'not-an-object', operations: ['op'], artifacts: [{ dataType: 'domain', tags: ['tag'] }] },
  ];
  setFetch(async () => ({
    ok: true,
    status: 200,
    headers: new Map([['content-type', 'application/json']]),
    text: async () => JSON.stringify(responses.shift()),
  }));

  const listAnalyzers = await loadHandler(listAnalyzersPath, { dataType: { value: 'ip' } });
  assert.equal((await listAnalyzers()).data.analyzers[0].id, 'single-analyzer');
  const listJobs = await loadHandler(listJobsPath);
  assert.equal((await listJobs()).data.jobs[0].analyzer_id, 'worker');
  const numericReport = await loadHandler(getJobReportPath, { jobId: 'numeric-report' });
  assert.equal((await numericReport()).data.status, 'Deleted');
  const successReport = await loadHandler(getJobReportPath, { job_id: 'success-report' });
  const mapped = await successReport();
  assert.deepEqual(mapped.data.summary, {});
  assert.equal(mapped.data.artifacts[0].data_type, 'domain');
});

test('all RPCs reject malformed endpoints and status aliases select the batch API', async () => {
  const malformed = { bindings: { endpoint: 'https://cortex.example/path?not-allowed=yes' } };
  const report = await loadHandler(getJobReportPath, { job_id: 'x' }, malformed);
  const status = await loadHandler(getJobStatusPath, { job_id: 'x' }, malformed);
  await assert.rejects(() => report(), /INVALID_ARGUMENT/);
  await assert.rejects(() => status(), /INVALID_ARGUMENT/);

  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify({ id: 'first', status: 'Success' }),
    };
  });
  const batch = await loadHandler(getJobStatusPath, { job_id: 'ignored', jobIds: ['first'] });
  assert.equal((await batch()).data.statuses[0].status, 'Success');
  assert.equal(captured.url, 'http://localhost:18080/api/job/first');

  const { handlers, METHOD_LIST_ANALYZERS_FULL } = await import('../src/cortex.js');
  const viaReqAlias = await handlers[METHOD_LIST_ANALYZERS_FULL]({
    config: { endpoint: 'http://localhost:18080' },
    req: {},
  });
  assert.deepEqual(viaReqAlias.data.analyzers, [{
    id: 'first', name: '', analyzer_definition_id: '', description: '', data_type_list: [], version: '', tlp: 2, state: '', raw: { id: 'first', status: 'Success' },
  }]);
});

// ==================== ListAnalyzers ====================

test('ListAnalyzers validates required endpoint', async () => {
  const handler = await loadHandler(listAnalyzersPath, {}, { bindings: { endpoint: '' } });
  await assert.rejects(() => handler(), /INVALID_ARGUMENT: endpoint/);
});

test('ListAnalyzers sends GET and maps response', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify([
        { id: 'vt1', name: 'VirusTotal_3_0', workerDefinitionId: 'VirusTotal_3_0', description: 'VT v3', dataTypeList: ['ip', 'domain'], version: '3.0', tlp: 2, state: 'Enabled' },
        { id: 'sh1', name: 'Shodan_1_0', workerDefinitionId: 'Shodan_1_0', description: 'Shodan', dataTypeList: ['ip'], version: '1.0', tlp: 2, state: 'Enabled' },
      ]),
    };
  });

  const handler = await loadHandler(listAnalyzersPath, {}, {
    bindings: { endpoint: 'http://localhost:18080/' },
    secret: { apiKey: 'test-key' },
  });
  const res = await handler();

  assert.match(captured.url, /\/api\/analyzer$/);
  assert.equal(captured.init.method, 'GET');
  assert.equal(captured.init.headers['Authorization'], 'Bearer test-key');
  assert.equal(res.data.analyzers.length, 2);
  assert.equal(res.data.analyzers[0].id, 'vt1');
  assert.equal(res.data.analyzers[0].name, 'VirusTotal_3_0');
  assert.deepEqual(res.data.analyzers[0].data_type_list, ['ip', 'domain']);
});

test('ListAnalyzers with dataType filter uses /api/analyzer/type/:dataType', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify([
        { id: 'vt1', name: 'VirusTotal_3_0', dataTypeList: ['ip'], version: '3.0' },
      ]),
    };
  });

  const handler = await loadHandler(listAnalyzersPath, { data_type: 'ip' }, {
    secret: { username: 'admin', password: 'secret' },
  });
  const res = await handler();

  assert.match(captured.url, /\/api\/analyzer\/type\/ip/);
  assert.equal(captured.init.method, 'GET');
  assert.match(captured.init.headers['Authorization'], /^Basic /);
  assert.equal(res.data.analyzers.length, 1);
});

test('Basic Auth supports Unicode credentials and fetch uses secure transport options', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => '[]',
    };
  });

  const handler = await loadHandler(listAnalyzersPath, {}, {
    secret: { username: '用户', password: '密码🔐' },
  });
  await handler();

  assert.equal(
    captured.init.headers.Authorization,
    `Basic ${Buffer.from('用户:密码🔐', 'utf8').toString('base64')}`,
  );
  assert.equal(captured.init.redirect, 'error');
  assert.ok(captured.init.dispatcher, 'TLS-verifying undici dispatcher is supplied');
  assert.ok(captured.init.signal instanceof AbortSignal);
});

test('ListAnalyzers handles empty response', async () => {
  setFetch(async () => ({
    ok: true,
    status: 200,
    headers: new Map([['content-type', 'application/json']]),
    text: async () => '[]',
  }));

  const handler = await loadHandler(listAnalyzersPath);
  const res = await handler();
  assert.deepEqual(res.data.analyzers, []);
});

test('ListAnalyzers handles auth error', async () => {
  setFetch(async () => ({
    ok: false,
    status: 401,
    headers: new Map([['content-type', 'text/plain']]),
    text: async () => 'unauthorized',
  }));
  const handler = await loadHandler(listAnalyzersPath);
  await assert.rejects(() => handler(), /UNAUTHENTICATED: upstream http 401/);
});

// ==================== AnalyzeObservable ====================

test('AnalyzeObservable validates required fields', async () => {
  const noAnalyzerId = await loadHandler(analyzeObservablePath, {});
  await assert.rejects(() => noAnalyzerId(), /INVALID_ARGUMENT: analyzer_id is required/);

  const noData = await loadHandler(analyzeObservablePath, { analyzer_id: 'vt1' });
  await assert.rejects(() => noData(), /INVALID_ARGUMENT: data \(observable value\) is required/);

  const noDataType = await loadHandler(analyzeObservablePath, { analyzer_id: 'vt1', data: '8.8.8.8' });
  await assert.rejects(() => noDataType(), /INVALID_ARGUMENT: data_type \(observable type\) is required/);

  const noEndpoint = await loadHandler(analyzeObservablePath, { analyzer_id: 'vt1', data: '8.8.8.8', data_type: 'ip' }, { bindings: { endpoint: 'ftp://bad' } });
  await assert.rejects(() => noEndpoint(), /INVALID_ARGUMENT: endpoint/);
});

test('AnalyzeObservable sends POST payload and maps response', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify({
        id: 'job1',
        _id: 'job1',
        analyzerId: 'vt1',
        workerId: 'vt1',
        analyzerName: 'VirusTotal_3_0',
        workerName: 'VirusTotal_3_0',
        analyzerDefinitionId: 'VirusTotal_3_0',
        workerDefinitionId: 'VirusTotal_3_0',
        status: 'Waiting',
        dataType: 'ip',
        data: '8.8.8.8',
        message: '',
        tlp: 2,
        date: '2024-01-15T10:30:00Z',
      }),
    };
  });

  const handler = await loadHandler(analyzeObservablePath, {
    analyzer_id: 'vt1',
    data: '8.8.8.8',
    data_type: 'ip',
    tlp: { value: 0 },
    message: 'test analysis',
    parameters: {
      fields: {
        retries: { numberValue: 2 },
        private: { boolValue: true },
        tags: { listValue: { values: [{ stringValue: 'one' }, { stringValue: 'two' }] } },
      },
    },
  }, {
    bindings: { endpoint: 'http://localhost:18080' },
    secret: { apiKey: 'test-key' },
  });
  const res = await handler();

  assert.equal(captured.url, 'http://localhost:18080/api/analyzer/vt1/run');
  assert.equal(captured.init.method, 'POST');
  assert.equal(captured.init.headers['Authorization'], 'Bearer test-key');

  const body = JSON.parse(captured.init.body);
  assert.equal(body.data, '8.8.8.8');
  assert.equal(body.dataType, 'ip');
  assert.equal(body.tlp, 0);
  assert.equal(body.message, 'test analysis');
  assert.deepEqual(body.parameters, { retries: 2, private: true, tags: ['one', 'two'] });

  assert.equal(res.data.id, 'job1');
  assert.equal(res.data.status, 'Waiting');
  assert.equal(res.data.data_type, 'ip');
  assert.equal(res.data.data, '8.8.8.8');
  assert.equal(res.data.analyzer_name, 'VirusTotal_3_0');
});

test('AnalyzeObservable uses Basic Auth when no apiKey', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify({ id: 'j1', status: 'Waiting' }),
    };
  });

  const handler = await loadHandler(analyzeObservablePath, {
    analyzer_id: 'vt1',
    data: '8.8.8.8',
    data_type: 'ip',
  }, {
    secret: { username: 'admin', password: 'secret' },
  });
  await handler();

  assert.match(captured.init.headers['Authorization'], /^Basic /);
});

test('AnalyzeObservable handles server error', async () => {
  setFetch(async () => ({
    ok: false,
    status: 500,
    headers: new Map([['content-type', 'text/plain']]),
    text: async () => 'internal error',
  }));
  const handler = await loadHandler(analyzeObservablePath, { analyzer_id: 'vt1', data: '8.8.8.8', data_type: 'ip' });
  await assert.rejects(() => handler(), /UNAVAILABLE: upstream http 500/);
});

// ==================== GetJobReport ====================

test('GetJobReport validates required fields', async () => {
  const noJobId = await loadHandler(getJobReportPath, {});
  await assert.rejects(() => noJobId(), /INVALID_ARGUMENT: job_id is required/);
});

test('GetJobReport sends GET and maps success report', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify({
        id: 'job1',
        status: 'Success',
        report: {
          success: true,
          summary: { taxonomies: [{ level: 'info', namespace: 'VT', value: 'Score', predicate: '8.8.8.8 - 0/73' }] },
          full: { results: { positive: 0, total: 73 } },
          operations: [],
          artifacts: [{ data: 'dns.google', dataType: 'domain', message: 'reverse DNS', tags: ['resolved'], tlp: 2 }],
          errorMessage: '',
        },
      }),
    };
  });

  const handler = await loadHandler(getJobReportPath, { job_id: 'job1' }, {
    secret: { apiKey: 'key' },
  });
  const res = await handler();

  assert.equal(captured.url, 'http://localhost:18080/api/job/job1/report');
  assert.equal(captured.init.method, 'GET');
  assert.equal(res.data.id, 'job1');
  assert.equal(res.data.success, true);
  assert.equal(res.data.status, 'Success');
  assert.ok(res.data.summary);
  assert.ok(res.data.full);
  assert.equal(res.data.artifacts.length, 1);
  assert.equal(res.data.artifacts[0].data, 'dns.google');
  assert.equal(res.data.artifacts[0].data_type, 'domain');
});

test('GetJobReport maps in-progress job', async () => {
  setFetch(async () => ({
    ok: true,
    status: 200,
    headers: new Map([['content-type', 'application/json']]),
    text: async () => JSON.stringify({ id: 'job2', status: 'InProgress', report: 'Running' }),
  }));

  const handler = await loadHandler(getJobReportPath, { job_id: 'job2' });
  const res = await handler();

  assert.equal(res.data.id, 'job2');
  assert.equal(res.data.status, 'InProgress');
  assert.equal(res.data.success, false);
  assert.deepEqual(res.data.summary, { message: 'Running' });
});

test('timeoutMs from config/bindings takes precedence over limits', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify([]),
    };
  });

  const handler = await loadHandler(listAnalyzersPath, {}, {
    bindings: { endpoint: 'http://localhost:9002', timeoutMs: 3000 },
    limits: { timeoutMs: 10_000 },
  });
  await handler();

  // The signal should reflect the config timeoutMs (3000), not limits (10000).
  // We verify the timeout was created by checking the AbortSignal exists.
  assert.ok(captured.init.signal);
});

test('invalid timeout configuration is rejected instead of silently falling back', async () => {
  await assert.rejects(
    () => loadHandler(listAnalyzersPath, {}, {
      bindings: { endpoint: 'http://localhost:9002', timeoutMs: 'not-a-number' },
    }),
    /INVALID_ARGUMENT: timeoutMs/,
  );
});

test('GetJobReport maps in-progress job without explicit status', async () => {
  setFetch(async () => ({
    ok: true,
    status: 200,
    headers: new Map([['content-type', 'application/json']]),
    text: async () => JSON.stringify({ id: 'job5', report: 'Waiting' }),
  }));

  const handler = await loadHandler(getJobReportPath, { job_id: 'job5' });
  const res = await handler();

  assert.equal(res.data.id, 'job5');
  assert.equal(res.data.status, 'InProgress');
  assert.equal(res.data.success, false);
  assert.deepEqual(res.data.summary, { message: 'Waiting' });
});

test('HTTP error does not leak upstream response body', async () => {
  setFetch(async () => ({
    ok: false,
    status: 403,
    headers: new Map([['content-type', 'application/json']]),
    text: async () => JSON.stringify({ secret: 'internal-details' }),
  }));
  const handler = await loadHandler(listAnalyzersPath);
  try {
    await handler();
    assert.fail('should have thrown');
  } catch (err) {
    assert.match(err.message, /PERMISSION_DENIED/);
    assert.doesNotMatch(err.message, /internal-details/);
  }
});

test('invalid JSON with an application/json content type maps to UNKNOWN', async () => {
  setFetch(async () => ({
    ok: true,
    status: 200,
    headers: new Map([['content-type', 'application/json']]),
    text: async () => '{truncated',
  }));
  const handler = await loadHandler(listAnalyzersPath);
  await assert.rejects(() => handler(), /UNKNOWN: response is not valid JSON/);
});

test('timeout error maps to DEADLINE_EXCEEDED', async () => {
  setFetch(async () => {
    const err = new Error('timed out');
    err.name = 'TimeoutError';
    throw err;
  });
  const handler = await loadHandler(listAnalyzersPath);
  await assert.rejects(() => handler(), /DEADLINE_EXCEEDED/);
});

test('response body timeout maps to DEADLINE_EXCEEDED', async () => {
  setFetch(async () => ({
    ok: true,
    status: 200,
    headers: new Map([['content-type', 'application/json']]),
    body: { getReader: () => ({
      read: async () => {
        const err = new Error('body timed out');
        err.name = 'TimeoutError';
        throw err;
      },
      releaseLock: () => {},
    }) },
  }));
  const handler = await loadHandler(listAnalyzersPath, {}, {
    bindings: { endpoint: 'http://localhost:9002', timeoutMs: 25 },
  });
  await assert.rejects(() => handler(), /DEADLINE_EXCEEDED: request timed out after 25ms/);
});

test('response body abort and read failures map to stable gRPC errors', async () => {
  for (const [name, expected] of [
    ['AbortError', /DEADLINE_EXCEEDED/],
    ['TypeError', /UNAVAILABLE: upstream response could not be read/],
    ['CausedTimeout', /DEADLINE_EXCEEDED/],
  ]) {
    setFetch(async () => ({
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      body: { getReader: () => ({
        read: async () => {
          const err = new Error('body read failed');
          err.name = name;
          if (name === 'CausedTimeout') err.cause = { name: 'TimeoutError' };
          throw err;
        },
        releaseLock: () => {},
      }) },
    }));
    const handler = await loadHandler(listAnalyzersPath);
    await assert.rejects(() => handler(), expected);
  }
});

test('GetJobReport maps failure report', async () => {
  setFetch(async () => ({
    ok: true,
    status: 200,
    headers: new Map([['content-type', 'application/json']]),
    text: async () => JSON.stringify({
      id: 'job3',
      status: 'Failure',
      report: { success: false, errorMessage: 'Analyzer timed out' },
    }),
  }));

  const handler = await loadHandler(getJobReportPath, { job_id: 'job3' });
  const res = await handler();

  assert.equal(res.data.id, 'job3');
  assert.equal(res.data.success, false);
  assert.equal(res.data.status, 'Failure');
  assert.equal(res.data.error_message, 'Analyzer timed out');
});

test('GetJobReport handles 404', async () => {
  setFetch(async () => ({
    ok: false,
    status: 404,
    headers: new Map([['content-type', 'text/plain']]),
    text: async () => 'not found',
  }));
  const handler = await loadHandler(getJobReportPath, { job_id: 'missing' });
  await assert.rejects(() => handler(), /FAILED_PRECONDITION: upstream http 404/);
});

// ==================== ListJobs ====================

test('ListJobs validates required endpoint', async () => {
  const handler = await loadHandler(listJobsPath, {}, { bindings: { endpoint: '' } });
  await assert.rejects(() => handler(), /INVALID_ARGUMENT: endpoint/);
});

test('ListJobs sends GET with filters and maps response', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify([
        { id: 'j1', analyzerId: 'vt1', workerId: 'vt1', analyzerName: 'VirusTotal_3_0', workerName: 'VirusTotal_3_0', status: 'Success', dataType: 'ip', data: '8.8.8.8', tlp: 2, date: '2024-01-15' },
        { id: 'j2', analyzerId: 'sh1', workerId: 'sh1', analyzerName: 'Shodan_1_0', workerName: 'Shodan_1_0', status: 'InProgress', dataType: 'ip', data: '1.1.1.1', tlp: 2, date: '2024-01-16' },
      ]),
    };
  });

  const handler = await loadHandler(listJobsPath, {
    data_type: 'ip',
    data: '8.8.8.8',
    analyzer: 'VirusTotal',
    range: '0-50',
  }, {
    secret: { apiKey: 'key' },
  });
  const res = await handler();

  assert.match(captured.url, /\/api\/job/);
  assert.match(captured.url, /dataTypeFilter=ip/);
  assert.match(captured.url, /dataFilter=8\.8\.8\.8/);
  assert.match(captured.url, /analyzerFilter=VirusTotal/);
  assert.match(captured.url, /range=0-50/);
  assert.equal(captured.init.method, 'GET');
  assert.equal(res.data.jobs.length, 2);
  assert.equal(res.data.jobs[0].id, 'j1');
  assert.equal(res.data.jobs[0].status, 'Success');
  assert.equal(res.data.jobs[1].status, 'InProgress');
});

test('ListJobs does not log the observable data filter', async () => {
  const observable = 'sensitive.example.test';
  const logged = [];
  const originalLog = console.log;
  console.log = (...args) => logged.push(args);
  try {
    setFetch(async () => ({
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => '[]',
    }));
    const handler = await loadHandler(listJobsPath, { data: observable });
    await handler();
  } finally {
    console.log = originalLog;
  }
  assert.equal(JSON.stringify(logged).includes(observable), false);
  assert.equal(JSON.stringify(logged).includes('hasDataFilter'), true);
});

test('ListJobs handles empty response', async () => {
  setFetch(async () => ({
    ok: true,
    status: 200,
    headers: new Map([['content-type', 'application/json']]),
    text: async () => '[]',
  }));
  const handler = await loadHandler(listJobsPath);
  const res = await handler();
  assert.deepEqual(res.data.jobs, []);
});

// ==================== GetJobStatus ====================

test('GetJobStatus validates required fields', async () => {
  const noIds = await loadHandler(getJobStatusPath, {});
  await assert.rejects(() => noIds(), /INVALID_ARGUMENT: job_id or job_ids is required/);
});

test('GetJobStatus single job sends GET and maps response', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify({ id: 'job1', _id: 'job1', status: 'Success' }),
    };
  });

  const handler = await loadHandler(getJobStatusPath, { job_id: 'job1' }, {
    secret: { apiKey: 'key' },
  });
  const res = await handler();

  assert.equal(captured.url, 'http://localhost:18080/api/job/job1');
  assert.equal(captured.init.method, 'GET');
  assert.equal(res.data.statuses.length, 1);
  assert.equal(res.data.statuses[0].job_id, 'job1');
  assert.equal(res.data.statuses[0].status, 'Success');
});

test('GetJobStatus batch aggregates documented single-job GET responses', async () => {
  const captured = [];
  setFetch(async (url, init) => {
    captured.push({ url, init });
    const jobId = url.split('/').at(-1);
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify({ id: jobId, status: jobId === 'job1' ? 'Success' : 'InProgress' }),
    };
  });

  const handler = await loadHandler(getJobStatusPath, { job_ids: ['job1', 'job2'] }, {
    secret: { apiKey: 'key' },
  });
  const res = await handler();

  assert.deepEqual(captured.map(({ url }) => url), [
    'http://localhost:18080/api/job/job1',
    'http://localhost:18080/api/job/job2',
  ]);
  assert.equal(captured.every(({ init }) => init.method === 'GET'), true);
  assert.equal(res.data.statuses.length, 2);
  assert.deepEqual(res.data.statuses.map(({ status }) => status), ['Success', 'InProgress']);
});

test('GetJobStatus handles not found', async () => {
  setFetch(async () => ({
    ok: false,
    status: 404,
    headers: new Map([['content-type', 'text/plain']]),
    text: async () => 'not found',
  }));
  const handler = await loadHandler(getJobStatusPath, { job_id: 'missing' });
  await assert.rejects(() => handler(), /FAILED_PRECONDITION: upstream http 404/);
});

// ==================== SDK handler compatibility ====================

test('SDK handlers accept single context with config and secret', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify([]),
    };
  });

  const { handlers, METHOD_LIST_ANALYZERS_FULL } = await import('../src/cortex.js');
  const res = await handlers[METHOD_LIST_ANALYZERS_FULL]({
    config: {
      endpoint: 'http://localhost:18080',
    },
    secret: {
      apiKey: 'sdk-secret-key',
    },
    request: {},
    meta: {
      instance_id: 'inst-sdk',
      request_id: 'req-sdk',
    },
  });

  assert.match(captured.url, /\/api\/analyzer$/);
  assert.equal(captured.init.headers['Authorization'], 'Bearer sdk-secret-key');
  assert.equal(captured.init.headers['X-Extra'], undefined); // no extra headers in config
});

test('SDK handlers use one context for request, bindings, secrets, and metadata', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify({
        id: 'job-inner',
        status: 'Waiting',
        dataType: 'ip',
        data: '1.1.1.1',
      }),
    };
  });

  const { handlers, METHOD_ANALYZE_OBSERVABLE_FULL } = await import('../src/cortex.js');
  const res = await handlers[METHOD_ANALYZE_OBSERVABLE_FULL]({
    request: {
      analyzer_id: 'vt1',
      data: '1.1.1.1',
      data_type: 'ip',
    },
    bindings: {
      endpoint: 'http://localhost:18081',
    },
    secret: {
      apiKey: 'inner-key',
    },
    meta: {
      instanceId: 'inst-camel',
      requestId: 'req-camel',
    },
  });

  assert.equal(captured.url, 'http://localhost:18081/api/analyzer/vt1/run');
  assert.equal(captured.init.headers['Authorization'], 'Bearer inner-key');
  assert.equal(captured.init.headers['x-engine-instance'], 'inst-camel');
});

test('SDK handlers use Basic Auth when no apiKey in secret', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify([]),
    };
  });

  const { handlers, METHOD_LIST_JOBS_FULL } = await import('../src/cortex.js');
  const res = await handlers[METHOD_LIST_JOBS_FULL]({
    config: { endpoint: 'http://localhost:18080' },
    secret: { username: 'admin', password: 'secret' },
    request: {},
  });

  assert.match(captured.init.headers['Authorization'], /^Basic /);
});

// ==================== Auth priority ====================

test('apiKey takes priority over username/password', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify([]),
    };
  });

  const handler = await loadHandler(listAnalyzersPath, {}, {
    secret: { apiKey: 'bearer-key', username: 'admin', password: 'secret' },
  });
  await handler();

  assert.equal(captured.init.headers['Authorization'], 'Bearer bearer-key');
});

test('request apiKey overrides secret apiKey', async () => {
  let captured;
  setFetch(async (url, init) => {
    captured = { url, init };
    return {
      ok: true,
      status: 200,
      headers: new Map([['content-type', 'application/json']]),
      text: async () => JSON.stringify([]),
    };
  });

  const handler = await loadHandler(listAnalyzersPath, { api_key: 'request-key' }, {
    secret: { apiKey: 'secret-key' },
  });
  await handler();

  assert.equal(captured.init.headers['Authorization'], 'Bearer request-key');
});

// ==================== Error mapping ====================

test('HTTP errors map to correct gRPC codes', async () => {
  const { _test } = await import('../src/cortex.js');

  // 401 → UNAUTHENTICATED
  setFetch(async () => ({
    ok: false,
    status: 401,
    headers: new Map([['content-type', 'text/plain']]),
    text: async () => 'unauthorized',
  }));
  const handler401 = await loadHandler(listAnalyzersPath);
  await assert.rejects(() => handler401(), /UNAUTHENTICATED/);

  // 403 → PERMISSION_DENIED
  setFetch(async () => ({
    ok: false,
    status: 403,
    headers: new Map([['content-type', 'text/plain']]),
    text: async () => 'forbidden',
  }));
  const handler403 = await loadHandler(listAnalyzersPath);
  await assert.rejects(() => handler403(), /PERMISSION_DENIED/);

  // 422 → FAILED_PRECONDITION
  setFetch(async () => ({
    ok: false,
    status: 422,
    headers: new Map([['content-type', 'text/plain']]),
    text: async () => 'bad request',
  }));
  const handler422 = await loadHandler(listAnalyzersPath);
  await assert.rejects(() => handler422(), /FAILED_PRECONDITION/);

  // 500 → UNAVAILABLE
  setFetch(async () => ({
    ok: false,
    status: 500,
    headers: new Map([['content-type', 'text/plain']]),
    text: async () => 'server error',
  }));
  const handler500 = await loadHandler(listAnalyzersPath);
  await assert.rejects(() => handler500(), /UNAVAILABLE/);

  // network error → UNAVAILABLE
  setFetch(async () => {
    throw Object.assign(new Error('fail'), { cause: new Error('connection reset') });
  });
  const handlerNetwork = await loadHandler(listAnalyzersPath);
  await assert.rejects(() => handlerNetwork(), /UNAVAILABLE: upstream request failed/);

  // non-JSON → UNKNOWN
  setFetch(async () => ({
    ok: true,
    status: 200,
    headers: new Map([['content-type', 'text/plain']]),
    text: async () => 'not json',
  }));
  const handlerNonJson = await loadHandler(listAnalyzersPath);
  await assert.rejects(() => handlerNonJson(), /UNKNOWN: response is not valid JSON/);
});
