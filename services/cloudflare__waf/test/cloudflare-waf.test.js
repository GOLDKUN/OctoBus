import test from 'node:test';
import assert from 'node:assert/strict';

const PKG = 'Cloudflare_WAF.Cloudflare_WAF';
const blockPath = `/${PKG}/BlockIP`;
const unblockPath = `/${PKG}/UnblockIP`;
const listPath = `/${PKG}/ListAccessRules`;
const getSecPath = `/${PKG}/GetSecurityLevel`;
const setSecPath = `/${PKG}/SetSecurityLevel`;

const buildCtx = (req = {}, overrides = {}) => ({
  bindings: { zoneId: 'zone-1', apiToken: 'tok-123', ...overrides.bindings },
  limits: { timeoutMs: 10_000, ...overrides.limits },
  meta: { instance_id: 'inst', request_id: 'req', ...overrides.meta },
  req,
});

// Mock global.fetch with a Response-like object. `impl` receives (url, init)
// and returns { status, body } (body is JSON-serialized) or { status, raw }.
const setFetch = (impl) => {
  global.fetch = async (url, init) => {
    const out = await impl(url, init);
    if (out && out.throwNetwork) {
      const e = new Error(out.throwNetwork);
      if (out.errorName) e.name = out.errorName;
      throw e;
    }
    if (out?.response) return out.response;
    const status = out?.status ?? 200;
    const text = out?.raw !== undefined ? out.raw : JSON.stringify(out?.body ?? {});
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: (name) => out?.headers?.[String(name).toLowerCase()] ?? null },
      async text() { return text; },
    };
  };
};

const loadRpc = async (req, overrides = {}) => {
  const { rpcdef } = await import('../src/cloudflare-waf.js');
  return rpcdef(buildCtx(req, overrides));
};

const cfOk = (result, resultInfo) => ({
  body: { success: true, errors: [], messages: [], result, result_info: resultInfo },
});

const rule = (id, value, mode = 'block') => ({
  id,
  mode,
  notes: '',
  configuration: { target: value.includes('/') ? 'ip_range' : 'ip', value },
});

test('internal helpers: bindings, headers, mode, target, struct, conversions', async () => {
  const { _test } = await import('../src/cloudflare-waf.js');

  assert.deepEqual(_test.mergedBindings({
    config: { endpoint: 'http://config', keep: 'c' },
    secret: { apiToken: 's' },
    bindings: { endpoint: 'http://binding' },
  }), { endpoint: 'http://binding', keep: 'c', apiToken: 's' });

  assert.deepEqual(_test.parseHeaders(undefined), {});
  assert.deepEqual(_test.parseHeaders(''), {});
  assert.deepEqual(_test.parseHeaders('{"X":"1"}'), { X: '1' });
  assert.deepEqual(_test.parseHeaders('{bad'), {});
  assert.deepEqual(_test.parseHeaders('[1]'), {});
  assert.deepEqual(_test.parseHeaders(['x']), {});
  assert.deepEqual(_test.parseHeaders({ A: 'b' }), { A: 'b' });

  assert.equal(_test.normalizeBaseUrl('https://api.cloudflare.com/client/v4/'), 'https://api.cloudflare.com/client/v4');
  assert.equal(_test.normalizeBaseUrl('ftp://x'), null);

  assert.equal(_test.toOptionalString({ value: '  hi ' }), 'hi');
  assert.equal(_test.toOptionalString('   '), undefined);
  assert.equal(_test.toOptionalString(null), undefined);

  assert.equal(_test.toPositiveInt(undefined), undefined);
  assert.equal(_test.toPositiveInt({ value: 5 }), 5);
  assert.equal(_test.toPositiveInt('abc'), null);

  assert.equal(_test.inferTarget('1.2.3.4'), 'ip');
  assert.equal(_test.inferTarget('1.2.3.0/24'), 'ip_range');

  assert.equal(_test.normalizeMode({}, { required: true }), 'block');
  assert.equal(_test.normalizeMode({}, { required: false }), undefined);
  assert.equal(_test.normalizeMode({ mode: 'challenge' }, { required: true }), 'challenge');
  assert.throws(() => _test.normalizeMode({ mode: 'nope' }, { required: true }), /INVALID_ARGUMENT/);

  assert.deepEqual(_test.mapAccessRule({ id: 7, mode: 'block', configuration: { target: 'ip', value: '1.1.1.1' }, notes: 'n' }, 'zone'),
    { id: '7', mode: 'block', target: 'ip', value: '1.1.1.1', notes: 'n', scope: 'zone' });
  assert.deepEqual(_test.mapAccessRule({}, ''), { id: '', mode: '', target: '', value: '', notes: '', scope: '' });

  assert.equal(_test.toStructValue(null), undefined);
  assert.equal(_test.toStructValue('x'), undefined);
  assert.equal(_test.toStructValue([1, 2]), undefined);
  assert.deepEqual(_test.toStructValue({ a: 1, b: null, c: [true], d: { e: 'f' }, g: Symbol.for('s') }), {
    fields: {
      a: { numberValue: 1 },
      b: { nullValue: 'NULL_VALUE' },
      c: { listValue: { values: [{ boolValue: true }] } },
      d: { structValue: { fields: { e: { stringValue: 'f' } } } },
      g: { stringValue: 'Symbol(s)' },
    },
  });

  assert.deepEqual(_test.requireTargets({ targets: [' 1.1.1.1 '] }, ['targets']), ['1.1.1.1']);
  assert.throws(() => _test.requireTargets({ targets: 'x' }, ['targets']), /must be an array/);
  assert.throws(() => _test.requireTargets({ targets: [] }, ['targets']), /non-empty/);
  assert.throws(() => _test.requireTargets({ targets: [''] }, ['targets']), /non-empty strings/);
  assert.deepEqual(
    _test.requireTargets({ targets: ['2001:db8::1', '2001:db8::/64', '192.0.2.0/24'] }, ['targets']),
    ['2001:db8::1', '2001:db8::/64', '192.0.2.0/24'],
  );
  for (const target of ['example.com', '1.2.3.4/33', '2001:db8::/129', '1.2.3.4/-1', '1.2.3.4/24/1']) {
    assert.throws(
      () => _test.requireTargets({ targets: [target] }, ['targets']),
      /valid IP addresses or CIDR ranges/,
    );
  }
  assert.throws(() => _test.requireTargets({}, ['targets']), /required/);

  const err = _test.errorWithCode('NEW_CODE', 'msg');
  assert.equal(err.legacyCode, 'NEW_CODE');
});

test('BlockIP creates a new rule when none exists', async () => {
  const calls = [];
  setFetch((url, init) => {
    calls.push({ url, method: init.method, headers: init.headers, body: init.body });
    if (init.method === 'GET') return cfOk([], { total_count: 0 });
    if (init.method === 'POST') {
      const body = JSON.parse(init.body);
      return cfOk(rule('r1', body.configuration.value, body.mode));
    }
    return cfOk(null);
  });
  const handler = (await loadRpc({ targets: ['1.2.3.4'], notes: 'bad actor' }))[blockPath];
  const out = await handler();
  assert.equal(out.created_count, 1);
  assert.deepEqual(out.rules, [{ id: 'r1', mode: 'block', target: 'ip', value: '1.2.3.4', notes: '', scope: 'zone' }]);
  // first call lists, sends Bearer + audit headers, then POST
  assert.match(calls[0].url, /\/zones\/zone-1\/firewall\/access_rules\/rules\?/);
  assert.match(calls[0].url, /configuration\.value=1\.2\.3\.4/);
  assert.match(calls[0].url, /mode=block/);
  assert.equal(calls[0].headers.authorization, 'Bearer tok-123');
  assert.equal(calls[0].headers['x-request-id'], 'req');
  assert.equal(calls[1].method, 'POST');
  assert.deepEqual(JSON.parse(calls[1].body), { mode: 'block', configuration: { target: 'ip', value: '1.2.3.4' }, notes: 'bad actor' });
});

test('BlockIP is idempotent: reuses existing rule, created_count=0', async () => {
  let posted = false;
  setFetch((url, init) => {
    if (init.method === 'GET') return cfOk([rule('exist', '5.5.5.5', 'block')]);
    if (init.method === 'POST') { posted = true; return cfOk(rule('new', '5.5.5.5')); }
    return cfOk(null);
  });
  const handler = (await loadRpc({ targets: ['5.5.5.5'] }))[blockPath];
  const out = await handler();
  assert.equal(out.created_count, 0);
  assert.equal(out.rules[0].id, 'exist');
  assert.equal(posted, false);
});

test('BlockIP scans result_info pagination before deciding to create', async () => {
  const pages = [];
  let posted = false;
  setFetch((url, init) => {
    if (init.method === 'GET') {
      const page = Number(new URL(url).searchParams.get('page'));
      pages.push(page);
      if (page === 1) {
        return cfOk(Array.from({ length: 50 }, (_, i) => rule(`other-${i}`, '6.6.6.6')), {
          page: 1, per_page: 50, total_pages: 2, total_count: 51,
        });
      }
      return cfOk([rule('existing-page-2', '5.5.5.5')], {
        page: 2, per_page: 50, total_pages: 2, total_count: 51,
      });
    }
    if (init.method === 'POST') posted = true;
    return cfOk(null);
  });

  const handler = (await loadRpc({ targets: ['5.5.5.5'] }))[blockPath];
  const out = await handler();
  assert.deepEqual(pages, [1, 2]);
  assert.equal(out.created_count, 0);
  assert.equal(out.rules[0].id, 'existing-page-2');
  assert.equal(posted, false);
});

test('BlockIP handles multiple targets and CIDR target inference', async () => {
  setFetch((url, init) => {
    if (init.method === 'GET') return cfOk([]);
    if (init.method === 'POST') {
      const body = JSON.parse(init.body);
      return cfOk(rule(`id-${body.configuration.value}`, body.configuration.value, body.mode));
    }
    return cfOk(null);
  });
  const handler = (await loadRpc({ targets: ['1.1.1.1', '10.0.0.0/8'], mode: 'challenge' }))[blockPath];
  const out = await handler();
  assert.equal(out.created_count, 2);
  assert.equal(out.rules[1].target, 'ip_range');
  assert.equal(out.rules[1].mode, 'challenge');
});

test('BlockIP deduplicates normalized targets within one request', async () => {
  let gets = 0;
  let posts = 0;
  setFetch((url, init) => {
    if (init.method === 'GET') {
      gets += 1;
      return cfOk([], { total_count: 0 });
    }
    if (init.method === 'POST') {
      posts += 1;
      const body = JSON.parse(init.body);
      return cfOk(rule('once', body.configuration.value, body.mode));
    }
    return cfOk(null);
  });

  const handler = (await loadRpc({ targets: [' 1.2.3.4 ', '1.2.3.4'] }))[blockPath];
  const out = await handler();
  assert.equal(gets, 1);
  assert.equal(posts, 1);
  assert.equal(out.created_count, 1);
  assert.equal(out.rules.length, 1);
});

test('BlockIP serializes concurrent creation for the same scope, mode, and target', async () => {
  let storedRule;
  let gets = 0;
  let posts = 0;
  setFetch(async (url, init) => {
    if (init.method === 'GET') {
      gets += 1;
      return cfOk(storedRule ? [storedRule] : [], { total_count: storedRule ? 1 : 0 });
    }
    if (init.method === 'POST') {
      posts += 1;
      await new Promise((resolve) => setTimeout(resolve, 10));
      storedRule = rule('concurrent-once', '3.3.3.3');
      return cfOk(storedRule);
    }
    return cfOk(null);
  });

  const first = (await loadRpc({ targets: ['3.3.3.3'] }))[blockPath];
  const second = (await loadRpc({ targets: ['3.3.3.3'] }))[blockPath];
  const [a, b] = await Promise.all([first(), second()]);
  assert.equal(posts, 1);
  assert.equal(gets, 2);
  assert.equal(a.created_count + b.created_count, 1);
  assert.equal(a.rules[0].id, 'concurrent-once');
  assert.equal(b.rules[0].id, 'concurrent-once');
});

test('BlockIP reports completed creations when a later target fails', async () => {
  let posts = 0;
  setFetch((url, init) => {
    if (init.method === 'GET') return cfOk([], { total_count: 0 });
    if (init.method === 'POST') {
      posts += 1;
      if (posts === 2) return { status: 429, body: { success: false, errors: [] } };
      const body = JSON.parse(init.body);
      return cfOk(rule('created-first', body.configuration.value, body.mode));
    }
    return cfOk(null);
  });

  const handler = (await loadRpc({ targets: ['1.1.1.1', '2.2.2.2'] }))[blockPath];
  await assert.rejects(handler(), (err) => {
    assert.equal(err.legacyCode, 'RESOURCE_EXHAUSTED');
    assert.deepEqual(err.partial_created_ids, ['created-first']);
    assert.equal(err.partial_created_count, 1);
    assert.match(err.message, /partial_created_ids=\["created-first"\]/);
    return true;
  });
});

test('BlockIP rejects missing targets and invalid mode', async () => {
  setFetch(() => cfOk([]));
  const noTargets = (await loadRpc({}))[blockPath];
  await assert.rejects(noTargets(), /INVALID_ARGUMENT.*targets is required/);
  const badMode = (await loadRpc({ targets: ['1.1.1.1'], mode: 'destroy' }))[blockPath];
  await assert.rejects(badMode(), /INVALID_ARGUMENT.*mode must be one of/);
});

test('UnblockIP deletes matching rules and is idempotent on absence', async () => {
  const deleted = [];
  setFetch((url, init) => {
    if (init.method === 'GET') {
      const value = new URL(url).searchParams.get('configuration.value');
      if (value === '9.9.9.9') return cfOk([rule('d1', '9.9.9.9'), rule('d2', '9.9.9.9', 'challenge')]);
      return cfOk([]);
    }
    if (init.method === 'DELETE') { deleted.push(url); return cfOk({ id: 'x' }); }
    return cfOk(null);
  });
  const found = (await loadRpc({ targets: ['9.9.9.9'] }))[unblockPath];
  const out = await found();
  assert.deepEqual(out.deleted_ids, ['d1', 'd2']);
  assert.equal(out.deleted_count, 2);
  assert.equal(deleted.length, 2);

  const none = (await loadRpc({ targets: ['8.8.8.8'] }))[unblockPath];
  const out2 = await none();
  assert.deepEqual(out2.deleted_ids, []);
  assert.equal(out2.deleted_count, 0);
});

test('UnblockIP mode filter narrows deletions', async () => {
  setFetch((url, init) => {
    if (init.method === 'GET') return cfOk([rule('keep', '7.7.7.7', 'challenge'), rule('kill', '7.7.7.7', 'block')]);
    if (init.method === 'DELETE') return cfOk({ id: 'x' });
    return cfOk(null);
  });
  const handler = (await loadRpc({ targets: ['7.7.7.7'], mode: 'block' }))[unblockPath];
  const out = await handler();
  assert.deepEqual(out.deleted_ids, ['kill']);
});

test('UnblockIP deletes matches from every result_info page', async () => {
  const deleted = [];
  setFetch((url, init) => {
    if (init.method === 'GET') {
      const page = Number(new URL(url).searchParams.get('page'));
      const result = page === 1
        ? Array.from({ length: 50 }, (_, i) => rule(`p1-${i}`, '4.4.4.4'))
        : [rule('p2-0', '4.4.4.4')];
      return cfOk(result, { page, per_page: 50, total_pages: 2, total_count: 51 });
    }
    if (init.method === 'DELETE') {
      deleted.push(url);
      return cfOk({ id: 'deleted' });
    }
    return cfOk(null);
  });

  const handler = (await loadRpc({ targets: ['4.4.4.4'] }))[unblockPath];
  const out = await handler();
  assert.equal(out.deleted_count, 51);
  assert.equal(deleted.length, 51);
  assert.equal(out.deleted_ids.at(-1), 'p2-0');
});

test('UnblockIP treats a concurrent DELETE 404 as already unblocked', async () => {
  setFetch((url, init) => {
    if (init.method === 'GET') return cfOk([rule('gone', '7.7.7.7')]);
    if (init.method === 'DELETE') return { status: 404, body: { success: false, errors: [{ code: 7003 }] } };
    return cfOk(null);
  });
  const handler = (await loadRpc({ targets: ['7.7.7.7'] }))[unblockPath];
  const out = await handler();
  assert.deepEqual(out.deleted_ids, []);
  assert.equal(out.deleted_count, 0);
});

test('UnblockIP reports completed deletions when a later delete fails', async () => {
  let deletes = 0;
  setFetch((url, init) => {
    if (init.method === 'GET') {
      return cfOk([rule('deleted-first', '7.7.7.7'), rule('rate-limited', '7.7.7.7')]);
    }
    if (init.method === 'DELETE') {
      deletes += 1;
      if (deletes === 2) return { status: 429, body: { success: false, errors: [] } };
      return cfOk({ id: 'deleted-first' });
    }
    return cfOk(null);
  });

  const handler = (await loadRpc({ targets: ['7.7.7.7'] }))[unblockPath];
  await assert.rejects(handler(), (err) => {
    assert.equal(err.legacyCode, 'RESOURCE_EXHAUSTED');
    assert.deepEqual(err.partial_deleted_ids, ['deleted-first']);
    assert.equal(err.partial_deleted_count, 1);
    assert.match(err.message, /partial_deleted_ids=\["deleted-first"\]/);
    return true;
  });
});

test('ListAccessRules maps rules, total_count, and pagination query', async () => {
  let seenUrl = '';
  setFetch((url, init) => {
    seenUrl = url;
    assert.equal(init.method, 'GET');
    return cfOk([rule('a', '1.1.1.1'), rule('b', '2.2.2.0/24', 'whitelist')], { total_count: 42 });
  });
  const handler = (await loadRpc({ value: '1.1.1.1', mode: 'block', page: 2, per_page: 25 }))[listPath];
  const out = await handler();
  assert.equal(out.total_count, 42);
  assert.equal(out.rules.length, 2);
  assert.equal(out.rules[1].target, 'ip_range');
  assert.match(seenUrl, /configuration\.value=1\.1\.1\.1/);
  assert.match(seenUrl, /mode=block/);
  assert.match(seenUrl, /page=2/);
  assert.match(seenUrl, /per_page=25/);
});

test('ListAccessRules falls back total_count to length and validates paging', async () => {
  setFetch(() => cfOk([rule('a', '1.1.1.1')], {}));
  const handler = (await loadRpc({}))[listPath];
  const out = await handler();
  assert.equal(out.total_count, 1);

  setFetch(() => cfOk([]));
  const badPage = (await loadRpc({ page: 0 }))[listPath];
  await assert.rejects(badPage(), /page must be an integer >= 1/);
  const badPer = (await loadRpc({ per_page: 51 }))[listPath];
  await assert.rejects(badPer(), /per_page must be an integer/);
  const nanPer = (await loadRpc({ per_page: 'x' }))[listPath];
  await assert.rejects(nanPer(), /per_page must be an integer/);
});

test('GetSecurityLevel and SetSecurityLevel map value + raw', async () => {
  setFetch((url, init) => {
    assert.match(url, /\/zones\/zone-1\/settings\/security_level$/);
    if (init.method === 'GET') return cfOk({ id: 'security_level', value: 'high', editable: true });
    if (init.method === 'PATCH') {
      assert.deepEqual(JSON.parse(init.body), { value: 'under_attack' });
      return cfOk({ id: 'security_level', value: 'under_attack', editable: true });
    }
    return cfOk(null);
  });
  const get = (await loadRpc({}))[getSecPath];
  const g = await get();
  assert.equal(g.value, 'high');
  assert.deepEqual(g.raw.fields.value, { stringValue: 'high' });

  const set = (await loadRpc({ value: 'under_attack' }))[setSecPath];
  const s = await set();
  assert.equal(s.value, 'under_attack');
});

test('SetSecurityLevel validates value', async () => {
  setFetch(() => cfOk({}));
  const missing = (await loadRpc({}))[setSecPath];
  await assert.rejects(missing(), /value is required/);
  const bad = (await loadRpc({ value: 'paranoid' }))[setSecPath];
  await assert.rejects(bad(), /value must be one of/);
});

test('scope resolution: account_id wins, missing scope errors', async () => {
  let seen = '';
  setFetch((url) => { seen = url; return cfOk([]); });
  const acct = (await loadRpc({ account_id: 'acct-9', value: '1.1.1.1' }, { bindings: { zoneId: 'zone-1', accountId: 'cfg-acct', apiToken: 't' } }))[listPath];
  await acct();
  assert.match(seen, /\/accounts\/acct-9\/firewall\/access_rules\/rules/);

  // no zone & no account anywhere
  const noScope = (await loadRpc({ value: '1.1.1.1' }, { bindings: { zoneId: '', apiToken: 't' } }))[listPath];
  await assert.rejects(noScope(), /zone_id or account_id is required/);

  const noZone = (await loadRpc({}, { bindings: { zoneId: '', apiToken: 't' } }))[getSecPath];
  await assert.rejects(noZone(), /zone_id is required/);
});

test('auth: missing token errors; legacy email+key used as fallback', async () => {
  const noAuth = (await loadRpc({ value: '1.1.1.1' }, { bindings: { zoneId: 'z', apiToken: '', authEmail: '', authKey: '' } }))[listPath];
  await assert.rejects(noAuth(), /apiToken \(or authEmail \+ authKey\) is required/);

  let headers;
  setFetch((url, init) => { headers = init.headers; return cfOk([]); });
  const legacy = (await loadRpc({ value: '1.1.1.1' }, { bindings: { zoneId: 'z', apiToken: '', authEmail: 'a@b.com', authKey: 'k' } }))[listPath];
  await legacy();
  assert.equal(headers['x-auth-email'], 'a@b.com');
  assert.equal(headers['x-auth-key'], 'k');
  assert.equal(headers.authorization, undefined);

  setFetch(() => ({ throwNetwork: 'proxy echoed x-auth-email: a@b.com and x-auth-key: k' }));
  const redacted = (await loadRpc({ value: '1.1.1.1' }, {
    bindings: { zoneId: 'z', apiToken: '', authEmail: 'a@b.com', authKey: 'k' },
  }))[listPath];
  await assert.rejects(redacted(), (err) => {
    assert.doesNotMatch(err.message, /a@b\.com|x-auth-key: k/);
    assert.match(err.message, /x-auth-email=\[REDACTED\]/);
    return true;
  });
});

test('error mapping: http 403, 429, 400, success:false, auth code, network, bad json', async () => {
  setFetch(() => ({ status: 403, body: { success: false, errors: [{ code: 9109 }] } }));
  let h = (await loadRpc({ value: '1.1.1.1' }))[listPath];
  await assert.rejects(h(), /PERMISSION_DENIED.*upstream http 403/);

  setFetch(() => ({ status: 429, body: { success: false, errors: [{ code: 10000 }] } }));
  h = (await loadRpc({ value: '1.1.1.1' }))[listPath];
  await assert.rejects(h(), /RESOURCE_EXHAUSTED.*upstream http 429/);

  setFetch(() => ({ status: 400, body: { success: false, errors: [{ code: 1004 }] } }));
  h = (await loadRpc({ value: '1.1.1.1' }))[listPath];
  await assert.rejects(h(), /FAILED_PRECONDITION.*upstream http 400/);

  setFetch(() => ({ status: 200, body: { success: false, errors: [{ code: 1004, message: 'bad' }] } }));
  h = (await loadRpc({ value: '1.1.1.1' }))[listPath];
  await assert.rejects(h(), /FAILED_PRECONDITION/);

  setFetch(() => ({ status: 200, body: { success: false, errors: [{ code: 10000, message: 'auth' }] } }));
  h = (await loadRpc({ value: '1.1.1.1' }))[listPath];
  await assert.rejects(h(), /PERMISSION_DENIED/);

  setFetch(() => ({ status: 500, body: { success: false, errors: [] } }));
  h = (await loadRpc({ value: '1.1.1.1' }))[listPath];
  await assert.rejects(h(), /UNAVAILABLE.*upstream http 500/);

  setFetch(() => ({ throwNetwork: 'ECONNREFUSED' }));
  h = (await loadRpc({ value: '1.1.1.1' }))[listPath];
  await assert.rejects(h(), /UNAVAILABLE.*ECONNREFUSED/);

  setFetch(() => ({ status: 200, raw: 'not-json{' }));
  h = (await loadRpc({ value: '1.1.1.1' }))[listPath];
  await assert.rejects(h(), /UNKNOWN.*not valid JSON/);

  setFetch(() => ({ status: 200, raw: '' }));
  h = (await loadRpc({ value: '1.1.1.1' }))[listPath];
  const out = await h();
  assert.deepEqual(out.rules, []);
});

test('binding fallbacks: default endpoint, AbortSignal timeout, TLS dispatcher, config account scope, unknown meta', async () => {
  let seen;
  setFetch((url, init) => { seen = { url, init }; return cfOk([rule('z', '1.1.1.1')], { total_count: 1 }); });
  // invalid endpoint -> default; no limits.timeoutMs -> bindings.timeoutMs; skipTlsVerify true;
  // account only from config; meta empty -> 'unknown' audit headers.
  const handler = (await loadRpc({ value: '1.1.1.1' }, {
    limits: { timeoutMs: 0 },
    meta: { instance_id: '', request_id: '' },
    bindings: { zoneId: '', endpoint: 'not-a-url', timeoutMs: 2222, skipTlsVerify: true, accountId: 'cfg-acct', apiToken: 't' },
  }))[listPath];
  const out = await handler();
  assert.equal(out.rules[0].id, 'z');
  assert.match(seen.url, /^https:\/\/api\.cloudflare\.com\/client\/v4\/accounts\/cfg-acct\//);
  assert.ok(seen.init.signal instanceof AbortSignal);
  assert.equal(seen.init.redirect, 'error');
  assert.ok(seen.init.dispatcher);
  assert.equal(seen.init.timeoutMs, undefined);
  assert.equal(seen.init.insecureSkipVerify, undefined);
  assert.equal(seen.init.tlsInsecureSkipVerify, undefined);
  assert.equal(seen.init.headers['x-engine-instance'], 'unknown');
  assert.equal(seen.init.headers['x-request-id'], 'unknown');
});

test('success:false with non-array errors maps to FAILED_PRECONDITION', async () => {
  setFetch(() => ({ status: 200, body: { success: false, errors: null } }));
  const handler = (await loadRpc({ value: '1.1.1.1' }))[listPath];
  await assert.rejects(handler(), /FAILED_PRECONDITION.*success=false/);
});

test('transport enforces timeout, disables redirects, redacts credentials, and bounds response bodies', async () => {
  setFetch(() => ({ throwNetwork: 'Timeout exceeded', errorName: 'TimeoutError' }));
  let handler = (await loadRpc({ value: '1.1.1.1' }))[listPath];
  await assert.rejects(handler(), /DEADLINE_EXCEEDED.*10000ms/);

  setFetch(() => ({ throwNetwork: 'authorization: Bearer tok-123' }));
  handler = (await loadRpc({ value: '1.1.1.1' }))[listPath];
  await assert.rejects(handler(), (err) => {
    assert.match(err.message, /UNAVAILABLE/);
    assert.doesNotMatch(err.message, /tok-123/);
    assert.match(err.message, /REDACTED/);
    return true;
  });

  const { _test } = await import('../src/cloudflare-waf.js');
  await assert.rejects(
    _test.readResponseText({ headers: { get: () => '3' }, text: async () => 'abc' }, 2),
    /RESOURCE_EXHAUSTED/,
  );

  let cancelled = false;
  const chunks = [new Uint8Array([97, 98]), new Uint8Array([99])];
  const reader = {
    async read() { return chunks.length ? { done: false, value: chunks.shift() } : { done: true }; },
    async cancel() { cancelled = true; },
  };
  await assert.rejects(
    _test.readResponseText({ headers: { get: () => null }, body: { getReader: () => reader } }, 2),
    /RESOURCE_EXHAUSTED/,
  );
  assert.equal(cancelled, true);
  assert.equal(_test.redact('apiToken=tok-123', ['tok-123']), 'apiToken=[REDACTED]');

  setFetch(() => ({ response: {
    ok: true,
    status: 200,
    headers: { get: () => null },
    body: { getReader: () => ({ read: async () => { const e = new Error('body timed out'); e.name = 'TimeoutError'; throw e; } }) },
  } }));
  handler = (await loadRpc({ value: '1.1.1.1' }))[listPath];
  await assert.rejects(handler(), /DEADLINE_EXCEEDED.*10000ms/);
});

test('SetSecurityLevel avoids a PATCH when the requested level already matches', async () => {
  let calls = 0;
  setFetch((url, init) => {
    calls += 1;
    assert.equal(init.method, 'GET');
    return cfOk({ id: 'security_level', value: 'high', editable: true });
  });
  const handler = (await loadRpc({ value: 'high' }))[setSecPath];
  const out = await handler();
  assert.equal(out.value, 'high');
  assert.equal(calls, 1);
});

test('handlers / registerHandlers run through the legacy ctx wrapper', async () => {
  setFetch((url, init) => {
    if (init.method === 'GET') return cfOk([rule('h1', '1.1.1.1')], { total_count: 1 });
    return cfOk(null);
  });
  const { handlers, _test } = await import('../src/cloudflare-waf.js');
  const fullList = `${PKG}/ListAccessRules`;
  const out = await handlers[fullList]({
    bindings: { zoneId: 'zone-1', apiToken: 't' },
    req: { value: '1.1.1.1' },
  });
  assert.equal(out.rules[0].id, 'h1');

  // resolveCallContext: (req, ctx) two-arg form
  const reg = _test.registerHandlers({ bindings: { zoneId: 'zone-1', apiToken: 't' } });
  const out2 = await reg[`/${PKG}/ListAccessRules`]({ value: '1.1.1.1' }, { meta: { request_id: 'r2' } });
  assert.equal(out2.rules[0].id, 'h1');
});
