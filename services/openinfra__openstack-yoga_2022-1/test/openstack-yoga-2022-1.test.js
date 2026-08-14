import assert from 'node:assert/strict';
import test from 'node:test';

import { GrpcError, grpcStatus } from '@chaitin-ai/octobus-sdk';

import {
  METHOD_GET_SERVER_FULL,
  METHOD_GET_SERVER_PATH,
  METHOD_LIST_FLAVORS_FULL,
  METHOD_LIST_FLAVORS_PATH,
  METHOD_LIST_NETWORKS_FULL,
  METHOD_LIST_NETWORKS_PATH,
  METHOD_LIST_PROJECTS_FULL,
  METHOD_LIST_PROJECTS_PATH,
  METHOD_LIST_SERVERS_FULL,
  METHOD_LIST_SERVERS_PATH,
  METHOD_LIST_VOLUMES_FULL,
  METHOD_LIST_VOLUMES_PATH,
  _test,
  handlers,
  rpcdef,
} from '../src/openstack-yoga-2022-1.js';
import { service } from '../src/service.js';
import {
  PASSWORD,
  PROJECT_ID,
  PROJECT_NAME,
  TOKEN,
  USERNAME,
  createMockServer,
} from './mock_upstream.js';

const originalFetch = globalThis.fetch;
const originalConsoleLog = console.log;

const baseBindings = {
  auth_url: 'https://identity.example.com:5000',
  region: 'RegionOne',
  project_name: PROJECT_NAME,
  project_domain_name: 'Default',
  user_domain_name: 'Default',
};
const baseSecret = { username: USERNAME, password: PASSWORD };
const buildCtx = (overrides = {}) => ({
  config: { ...baseBindings, ...(overrides.config || {}) },
  secret: { ...baseSecret, ...(overrides.secret || {}) },
  bindings: overrides.bindings || {},
  limits: { timeoutMs: 30_000, ...(overrides.limits || {}) },
  meta: { instance_id: 'inst-1', request_id: 'req-1', ...(overrides.meta || {}) },
  req: overrides.req || {},
});

const expectGrpcError = async (fn, legacyCode, checker = () => {}) => {
  let caught;
  try { await fn(); } catch (err) { caught = err; }
  assert.ok(caught, 'expected function to reject');
  assert.ok(caught instanceof GrpcError);
  assert.equal(caught.legacyCode, legacyCode);
  assert.equal(caught.code, ({
    FAILED_PRECONDITION: grpcStatus.FAILED_PRECONDITION,
    INVALID_ARGUMENT: grpcStatus.INVALID_ARGUMENT,
    NOT_FOUND: grpcStatus.NOT_FOUND,
    PERMISSION_DENIED: grpcStatus.PERMISSION_DENIED,
    UNAVAILABLE: grpcStatus.UNAVAILABLE,
    UNKNOWN: grpcStatus.UNKNOWN,
  })[legacyCode]);
  checker(caught);
};

const setFetch = (impl) => { globalThis.fetch = impl; };

const responseOf = (status, body, extraHeaders = {}) => ({
  status,
  headers: { get: (name) => {
    const key = String(name || '').toLowerCase();
    for (const [h, v] of Object.entries(extraHeaders)) {
      if (h.toLowerCase() === key) return v;
    }
    return null;
  } },
  text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
});

const authOk = () => responseOf(201, {
  token: { user: { id: 'u-1', name: USERNAME }, project: { id: PROJECT_ID, name: PROJECT_NAME } },
}, { 'x-subject-token': TOKEN });

test.afterEach(() => {
  globalThis.fetch = originalFetch;
  console.log = originalConsoleLog;
});

test('service exports handlers and rpcdef paths', () => {
  assert.equal(typeof service, 'object');
  for (const full of [
    METHOD_LIST_PROJECTS_FULL, METHOD_LIST_SERVERS_FULL, METHOD_GET_SERVER_FULL,
    METHOD_LIST_NETWORKS_FULL, METHOD_LIST_VOLUMES_FULL, METHOD_LIST_FLAVORS_FULL,
  ]) {
    assert.equal(typeof handlers[full], 'function', `${full} handler missing`);
  }
  const defs = rpcdef(buildCtx());
  for (const path of [
    METHOD_LIST_PROJECTS_PATH, METHOD_LIST_SERVERS_PATH, METHOD_GET_SERVER_PATH,
    METHOD_LIST_NETWORKS_PATH, METHOD_LIST_VOLUMES_PATH, METHOD_LIST_FLAVORS_PATH,
  ]) {
    assert.equal(typeof defs[path], 'function', `${path} rpcdef missing`);
  }
});

test('service catalog selects regional public endpoints safely', () => {
  const token = {
    authUrl: 'https://identity.example/v3', projectId: 'project 1',
    catalog: [{ type: 'compute', endpoints: [
      { interface: 'internal', region: 'RegionOne', url: 'https://internal.example/v2.1/{project_id}' },
      { interface: 'public', region: 'RegionTwo', url: 'https://r2.example/v2.1/{project_id}' },
      { interface: 'public', region: 'RegionOne', url: 'https://nova.example/v2.1/{project_id}' },
    ] }],
  };
  assert.equal(_test.endpointFor(token, 'compute', 'RegionOne'), 'https://nova.example/v2.1/project%201');
  assert.equal(_test.serviceUrl(token, 'compute', '/legacy', '/servers', 'RegionOne'), 'https://nova.example/v2.1/project%201/servers');
  assert.equal(_test.serviceUrl(token, 'compute', '/legacy', '/servers', 'RegionOne', 'override'), 'https://nova.example/v2.1/override/servers');
  assert.equal(_test.endpointFor({ ...token, catalog: [] }, 'compute'), token.authUrl);
  assert.equal(_test.endpointFor({ ...token, catalog: [{ type: 'compute', endpoints: [{ interface: 'public', url: 'ftp://bad' }] }] }, 'compute'), token.authUrl);
  const pythonCatalog = { ...token, catalog: [{ type: 'compute', endpoints: [{ interface: 'public', url: 'https://nova.example/v2.1/%(project_id)s/%(tenant_id)s' }] }] };
  assert.equal(_test.endpointFor(pythonCatalog, 'compute'), 'https://nova.example/v2.1/project%201/project%201');
  const networkCatalog = { ...token, catalog: [{ type: 'network', endpoints: [{ interface: 'public', url: 'https://neutron.example' }] }] };
  assert.equal(_test.serviceUrl(networkCatalog, 'network', '/legacy', '/v2.0/networks', 'RegionOne'), 'https://neutron.example/v2.0/networks');
  const volumeCatalog = { ...token, catalog: [{ type: 'volumev3', endpoints: [{ interface: 'public', url: 'https://cinder.example/v3/%(project_id)s' }] }] };
  assert.equal(_test.serviceUrl(volumeCatalog, 'volumev3', '/legacy', '/volumes', 'RegionOne'), 'https://cinder.example/v3/project%201/volumes');
});

test('loopback HTTP is accepted for local smoke without weakening remote defaults', () => {
  assert.equal(_test.normalizeAuthUrl('http://127.0.0.1:5000', false), 'http://127.0.0.1:5000');
  assert.equal(_test.normalizeAuthUrl('http://localhost:5000/', false), 'http://localhost:5000');
  assert.equal(_test.normalizeAuthUrl('https://user:pass@example.com', false), '');
});

test('password whitespace is preserved for Keystone authentication', () => {
  const body = _test.buildAuthRequestBody(buildCtx({ secret: { password: ' secret ' } }));
  assert.equal(body.auth.identity.password.user.password, ' secret ');
});

test('project domain defaults independently from a custom user domain', () => {
  const body = _test.buildAuthRequestBody(buildCtx({ config: { project_domain_name: '', user_domain_name: 'LDAP' } }));
  assert.equal(body.auth.identity.password.user.domain.name, 'LDAP');
  assert.equal(body.auth.scope.project.domain.name, 'Default');
});

test('validates required bindings and secrets', async () => {
  await expectGrpcError(
    () => handlers[METHOD_LIST_PROJECTS_FULL]({}, buildCtx({ config: { auth_url: '' } })),
    'INVALID_ARGUMENT', (err) => assert.match(err.message, /auth_url/));
  await expectGrpcError(
    () => handlers[METHOD_LIST_PROJECTS_FULL]({}, buildCtx({ config: { auth_url: 'http://insecure.local' } })),
    'INVALID_ARGUMENT', (err) => assert.match(err.message, /auth_url/));
  await expectGrpcError(
    () => handlers[METHOD_LIST_PROJECTS_FULL]({}, buildCtx({ config: { auth_url: 'ftp://bad.local' } })),
    'INVALID_ARGUMENT', (err) => assert.match(err.message, /auth_url/));
  await expectGrpcError(
    () => handlers[METHOD_LIST_PROJECTS_FULL]({}, buildCtx({ secret: { username: '' } })),
    'INVALID_ARGUMENT', (err) => assert.match(err.message, /username/));
  await expectGrpcError(
    () => handlers[METHOD_LIST_PROJECTS_FULL]({}, buildCtx({ secret: { password: '' } })),
    'INVALID_ARGUMENT', (err) => assert.match(err.message, /password/));
  await expectGrpcError(
    () => handlers[METHOD_GET_SERVER_FULL]({}, buildCtx()),
    'INVALID_ARGUMENT', (err) => assert.match(err.message, /server_id/));
});

test('obtainToken issues correct Keystone request and returns token + projectId', async () => {
  const calls = [];
  setFetch(async (url, init) => {
    calls.push({ url: String(url), init });
    if (String(url).endsWith('/v3/auth/tokens')) return authOk();
    return responseOf(200, []);
  });
  const token = await _test.obtainToken(buildCtx());
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://identity.example.com:5000/v3/auth/tokens');
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.headers['Content-Type'], 'application/json');
  const body = JSON.parse(calls[0].init.body);
  assert.deepEqual(body.auth.identity.methods, ['password']);
  assert.equal(body.auth.identity.password.user.name, USERNAME);
  assert.equal(body.auth.identity.password.user.password, PASSWORD);
  assert.equal(body.auth.identity.password.user.domain.name, 'Default');
  assert.equal(body.auth.scope.project.name, PROJECT_NAME);
  assert.equal(body.auth.scope.project.domain.name, 'Default');
  assert.equal(token.token, TOKEN);
  assert.equal(token.projectId, PROJECT_ID);
  assert.equal(token.authUrl, 'https://identity.example.com:5000');

  setFetch(async () => responseOf(401, { error: 'bad creds' }));
  await expectGrpcError(() => _test.obtainToken(buildCtx()), 'PERMISSION_DENIED');

  setFetch(async () => responseOf(201, { token: { project: { id: PROJECT_ID } } }));
  await expectGrpcError(() => _test.obtainToken(buildCtx()), 'UNKNOWN', (err) => assert.match(err.message, /X-Subject-Token/));

  setFetch(async () => responseOf(201, { token: { user: { id: 'u' } } }, { 'x-subject-token': TOKEN }));
  await expectGrpcError(() => _test.obtainToken(buildCtx()), 'FAILED_PRECONDITION');

  setFetch(async () => responseOf(500, 'boom'));
  await expectGrpcError(() => _test.obtainToken(buildCtx()), 'UNAVAILABLE');

  setFetch(async () => { throw Object.assign(new Error('net'), { cause: new Error('connection refused') }); });
  await expectGrpcError(() => _test.obtainToken(buildCtx()), 'UNAVAILABLE');
});

test('obtainToken captures token.expires_at', async () => {
  setFetch(async () => responseOf(201, {
    token: { user: { id: 'u' }, project: { id: PROJECT_ID }, expires_at: '2030-01-01T00:00:00Z' },
  }, { 'x-subject-token': TOKEN }));
  const t = await _test.obtainToken(buildCtx());
  assert.equal(t.expiresAt, '2030-01-01T00:00:00Z');
});

test('ListProjects happy path via mock upstream', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const ctx = buildCtx({ config: { auth_url: baseUrl, allowInsecureHttp: true } });
    const result = await handlers[METHOD_LIST_PROJECTS_FULL]({}, ctx);
    assert.equal(result.projects.length, 2);
    assert.equal(result.projects[0].id, 'proj-aaa');
    assert.equal(result.projects[0].name, 'alpha');
    assert.equal(result.projects[0].enabled, true);
    assert.equal(result.projects[0].is_domain, false);
    assert.deepEqual(JSON.parse(result.projects[0].tags_json), ['alpha-tag']);
    assert.match(result.projects[0].links_json, /proj-aaa/);
    assert.equal(result.projects[1].name, 'beta');
  } finally { await mock.close(); }
});

test('ListServers happy path via mock upstream', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const ctx = buildCtx({ config: { auth_url: baseUrl, allowInsecureHttp: true } });
    const result = await handlers[METHOD_LIST_SERVERS_FULL]({}, ctx);
    assert.equal(result.servers.length, 2);
    const s0 = result.servers[0];
    assert.equal(s0.id, 'srv-0001');
    assert.equal(s0.status, 'ACTIVE');
    assert.equal(s0.flavor_id, 'flavor-small');
    assert.equal(s0.image_id, 'img-cirros');
    assert.equal(s0.addresses['net-1111'], '10.0.0.5');
    assert.equal(s0.os_dcf_disk_config, 'AUTO');
    assert.equal(s0.description, 'web-1 description');
    assert.equal(s0.key_name, 'web-1-key');
    assert.equal(s0.locked, false);
    assert.equal(s0.host_status, 'UP');
    assert.equal(s0.progress, 0);
    assert.deepEqual(JSON.parse(s0.tags), ['tag-web-1']);
    assert.equal(s0.os_ext_az_availability_zone, 'nova');
    assert.equal(s0.os_ext_srv_attr_host, 'host-01');
    assert.equal(s0.os_ext_srv_attr_hostname, 'web-1.local');
    assert.equal(s0.os_srv_usg_launched_at, '2026-01-01T00:00:00.000000');
    assert.equal(s0.os_srv_usg_terminated_at, '');
    assert.deepEqual(JSON.parse(s0.security_groups_json), [{ name: 'default' }]);
    assert.match(s0.links_json, /srv-0001/);
  } finally { await mock.close(); }
});

test('GetServer happy path via mock upstream', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const ctx = buildCtx({ config: { auth_url: baseUrl, allowInsecureHttp: true } });
    const result = await handlers[METHOD_GET_SERVER_FULL]({ server_id: 'srv-0002' }, ctx);
    assert.equal(result.server.id, 'srv-0002');
    assert.equal(result.server.name, 'db-1');
    assert.equal(result.server.status, 'SHUTOFF');
    assert.equal(result.server.flavor_id, 'flavor-large');
    assert.equal(result.server.key_name, 'db-1-key');
    assert.equal(result.server.description, 'db-1 description');
    assert.equal(result.server.os_dcf_disk_config, 'AUTO');
    assert.equal(result.server.os_ext_srv_attr_root_device_name, '/dev/vda');
  } finally { await mock.close(); }
});

test('GetServer 404 maps to NOT_FOUND', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const ctx = buildCtx({ config: { auth_url: baseUrl, allowInsecureHttp: true } });
    await expectGrpcError(
      () => handlers[METHOD_GET_SERVER_FULL]({ server_id: 'srv-missing' }, ctx),
      'NOT_FOUND',
    );
  } finally { await mock.close(); }
});

test('ListNetworks happy path via mock upstream', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const ctx = buildCtx({ config: { auth_url: baseUrl, allowInsecureHttp: true } });
    const result = await handlers[METHOD_LIST_NETWORKS_FULL]({}, ctx);
    assert.equal(result.networks.length, 2);
    const n0 = result.networks[0];
    assert.equal(n0.id, 'net-1111');
    assert.equal(n0.admin_state_up, true);
    assert.equal(n0.dns_domain, 'local.');
    assert.equal(n0.mtu, 1450);
    assert.equal(n0.revision_number, 1);
    assert.equal(n0.port_security_enabled, true);
    assert.equal(n0.is_default, false);
    assert.equal(n0.vlan_transparent, false);
    assert.equal(n0.qinq, false);
    assert.equal(n0.l2_adjacency, false);
    assert.deepEqual(JSON.parse(n0.availability_zones_json), ['nova']);
    assert.deepEqual(JSON.parse(n0.subnets_json), ['subnet-1111']);

    const n1 = result.networks[1];
    assert.equal(n1.external, true);
    assert.equal(n1.shared, true);
    assert.equal(n1.qos_policy_id, 'qos-public');
    assert.equal(n1.is_default, true);
    assert.equal(n1.port_security_enabled, false);
    assert.equal(n1.vlan_transparent, true);
    assert.equal(n1.l2_adjacency, true);
    assert.equal(n1.ipv4_address_scope, 'asc-ipv4-public');
  } finally { await mock.close(); }
});

test('ListVolumes happy path via mock upstream', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const ctx = buildCtx({ config: { auth_url: baseUrl, allowInsecureHttp: true } });
    const result = await handlers[METHOD_LIST_VOLUMES_FULL]({}, ctx);
    assert.equal(result.volumes.length, 2);
    const v0 = result.volumes[0];
    assert.equal(v0.id, 'vol-aaaa');
    assert.equal(v0.status, 'in-use');
    assert.equal(v0.size, 20);
    assert.equal(v0.volume_type, 'ssd');
    assert.equal(v0.description, 'Data volume 1');
    assert.equal(v0.encrypted, true);
    assert.equal(v0.multiattach, false);
    assert.equal(v0.bootable, 'true');
    assert.equal(v0.replication_status, 'disabled');
    assert.equal(v0.os_vol_host_attr_host, 'host-01@ssd#ssd');
    assert.equal(v0.consumes_quota, 'true');
    assert.equal(v0.provider_id, 'provider-uuid-1');
    assert.equal(v0.service_uuid, 'svc-uuid-1');
    assert.deepEqual(JSON.parse(v0.attachments_json), [
      { id: 'att-1', server_id: 'srv-0001', device: '/dev/vdb', host_name: 'host-01' },
    ]);
    assert.match(v0.links_json, /vol-aaaa/);

    const v1 = result.volumes[1];
    assert.equal(v1.size, 100);
    assert.equal(v1.multiattach, true);
    assert.equal(v1.encrypted, false);
    assert.equal(v1.snapshot_id, 'snap-1');
    assert.equal(v1.source_volid, 'vol-source');
    assert.equal(v1.consistencygroup_id, 'cg-1');
    assert.equal(v1.migration_status, 'migrating');
    assert.equal(v1.group_id, 'group-1');
    assert.equal(v1.cluster_name, 'cluster-1');
  } finally { await mock.close(); }
});

test('ListFlavors happy path via mock upstream', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const ctx = buildCtx({ config: { auth_url: baseUrl, allowInsecureHttp: true } });
    const result = await handlers[METHOD_LIST_FLAVORS_FULL]({}, ctx);
    assert.equal(result.flavors.length, 2);
    const f0 = result.flavors[0];
    assert.equal(f0.id, 'flavor-small');
    assert.equal(f0.vcpus, 1);
    assert.equal(f0.ram, 2048);
    assert.equal(f0.disk, 20);
    assert.equal(f0.is_public, true);
    assert.equal(f0.ephemeral, 0);
    assert.equal(f0.description, 'Small flavor');
    assert.match(f0.extra_specs_json, /hw:numa_nodes/);
    assert.match(f0.links_json, /flavor-small/);
    assert.equal(result.flavors[1].name, 'm1.large');
    assert.equal(result.flavors[1].ephemeral, 40);
  } finally { await mock.close(); }
});

test('HTTP 401/403/4xx/5xx map to expected gRPC codes', async () => {
  let mode = '401';
  setFetch(async (url) => {
    if (String(url).endsWith('/v3/auth/tokens')) {
      if (mode === '401') return responseOf(401, { error: 'no' });
      if (mode === '403') return responseOf(403, { error: 'no' });
      if (mode === '500') return responseOf(500, 'boom');
      return responseOf(200, {}, { 'x-subject-token': 'tok' });
    }
    if (mode === 'api401') return responseOf(401, 'nope');
    if (mode === 'api403') return responseOf(403, 'nope');
    if (mode === 'api404') return responseOf(404, 'missing');
    if (mode === 'api500') return responseOf(500, 'broken');
    return responseOf(200, { servers: [] });
  });

  for (const [currentMode, expected] of [
    ['401', 'PERMISSION_DENIED'], ['403', 'PERMISSION_DENIED'], ['500', 'UNAVAILABLE'],
  ]) {
    mode = currentMode;
    await expectGrpcError(() => handlers[METHOD_LIST_SERVERS_FULL]({}, buildCtx()), expected);
  }

  setFetch(async (url) => {
    if (String(url).endsWith('/v3/auth/tokens')) {
      return responseOf(201, { token: { user: { id: 'u' }, project: { id: PROJECT_ID } } }, { 'x-subject-token': TOKEN });
    }
    if (mode === 'api401') return responseOf(401, 'nope');
    if (mode === 'api403') return responseOf(403, 'nope');
    if (mode === 'api404') return responseOf(404, 'missing');
    if (mode === 'api500') return responseOf(500, 'broken');
    return responseOf(200, { servers: [] });
  });

  mode = 'ok';
  for (const [currentMode, expected] of [
    ['api401', 'PERMISSION_DENIED'], ['api403', 'PERMISSION_DENIED'],
    ['api404', 'NOT_FOUND'], ['api500', 'UNAVAILABLE'],
  ]) {
    mode = currentMode;
    await expectGrpcError(() => handlers[METHOD_LIST_SERVERS_FULL]({}, buildCtx()), expected);
  }
});

test('rpcdef falls back to context request', async () => {
  setFetch(async (url) => {
    if (String(url).endsWith('/v3/auth/tokens')) return authOk();
    if (String(url).endsWith(`/v2/${PROJECT_ID}/servers/srv-0001`)) {
      return responseOf(200, { server: { id: 'srv-0001', name: 'web-1', status: 'ACTIVE' } });
    }
    return responseOf(200, {});
  });
  const defs = rpcdef(buildCtx({ req: { server_id: 'srv-0001' } }));
  const result = await defs[METHOD_GET_SERVER_PATH]();
  assert.equal(result.server.id, 'srv-0001');
});

test('mock upstream rejects bad credentials and invalid tokens', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    setFetch(originalFetch);
    const badAuth = await fetch(`${baseUrl}/v3/auth/tokens`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ auth: { identity: { methods: ['password'], password: { user: { name: 'x', password: 'x' } } } } }),
    });
    assert.equal(badAuth.status, 401);

    const authRes = await fetch(`${baseUrl}/v3/auth/tokens`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        auth: {
          identity: { methods: ['password'], password: { user: { name: USERNAME, password: PASSWORD, domain: { name: 'Default' } } } },
          scope: { project: { name: PROJECT_NAME, domain: { name: 'Default' } } },
        },
      }),
    });
    assert.equal(authRes.status, 201);
    assert.equal(authRes.headers.get('x-subject-token'), TOKEN);

    const projectsRes = await fetch(`${baseUrl}/v3/projects`, { headers: { 'X-Auth-Token': 'invalid-token' } });
    assert.equal(projectsRes.status, 401);

    const badProject = await fetch(`${baseUrl}/v2/p-UNKNOWN/servers`, { headers: { 'X-Auth-Token': TOKEN } });
    assert.equal(badProject.status, 404);

    const boom = await fetch(`${baseUrl}/v2/p-HTTP500/servers`, { headers: { 'X-Auth-Token': TOKEN } });
    assert.equal(boom.status, 500);

    const unknown = await fetch(`${baseUrl}/v3/projects/whatever`, { headers: { 'X-Auth-Token': TOKEN } });
    assert.equal(unknown.status, 404);

    const putRes = await fetch(`${baseUrl}/v3/projects`, { method: 'PUT', headers: { 'X-Auth-Token': TOKEN } });
    assert.equal(putRes.status, 405);

    const noScope = await fetch(`${baseUrl}/v3/auth/tokens`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ auth: { identity: { methods: ['password'], password: { user: { name: USERNAME, password: PASSWORD } } } } }),
    });
    assert.equal(noScope.status, 401);
  } finally { await mock.close(); }
});

test('helper functions cover parsing, mapping, and error branches', () => {
  assert.equal(_test.grpcCodeFor('PERMISSION_DENIED'), grpcStatus.PERMISSION_DENIED);
  assert.equal(_test.grpcCodeFor('NOPE'), grpcStatus.UNKNOWN);
  assert.equal(_test.engineError('FAILED_PRECONDITION', 'x').legacyCode, 'FAILED_PRECONDITION');
  assert.ok(_test.engineError('FAILED_PRECONDITION', 'x') instanceof GrpcError);

  assert.equal(_test.hasOwn(null, 'x'), false);
  assert.equal(_test.firstDefined(undefined, null, 0, 'x'), 0);
  assert.equal(_test.unwrapScalar({ value: { value: 'nested' } }), 'nested');
  assert.equal(_test.unwrapScalar(undefined), undefined);

  assert.equal(_test.toTrimmedString(null), '');
  assert.equal(_test.toTrimmedString({ value: ' x ' }), 'x');
  assert.equal(_test.toJsonString({ a: 1 }), '{"a":1}');
  assert.equal(_test.toJsonString(null), '');
  assert.equal(_test.toJsonString('already'), 'already');

  assert.equal(_test.normalizeAuthUrl(' https://id.example/ ', false), 'https://id.example');
  assert.equal(_test.normalizeAuthUrl('http://insecure/', false), '');
  assert.equal(_test.normalizeAuthUrl('http://insecure/', true), 'http://insecure');
  assert.equal(_test.normalizeAuthUrl('ftp://bad', true), '');

  assert.deepEqual(_test.mergedBindings({ config: { a: 1 }, secret: { b: 2 }, bindings: { a: 3 } }), { a: 3, b: 2 });
  assert.deepEqual(_test.resolveCallContext().req, {});
  assert.deepEqual(_test.resolveCallContext({ request: { x: 1 } }).req, { x: 1 });

  assert.equal(_test.resolveAuthUrl({ auth_url: 'https://x/' }), 'https://x');
  assert.equal(_test.resolveAuthUrl({ authUrl: 'https://x/' }), 'https://x');
  assert.equal(_test.resolveAuthUrl({ identityEndpoint: 'https://x/' }), 'https://x');
  assert.equal(_test.resolveAuthUrl({}), '');
  assert.equal(_test.resolveRegion({ region: 'R1' }), 'R1');
  assert.equal(_test.resolveProjectName({ project_name: 'p' }), 'p');
  assert.equal(_test.resolveProjectDomainName({ project_domain_name: 'pd' }), 'pd');
  assert.equal(_test.resolveUserDomainName({ user_domain_name: 'ud' }), 'ud');
  assert.equal(_test.resolveUsername({ username: 'u' }), 'u');
  assert.equal(_test.resolvePassword({ password: 'p' }), 'p');
  assert.equal(_test.resolveTimeoutMs(), 15000);
  assert.equal(_test.resolveTimeoutMs({ limits: { timeoutMs: 'bad' }, bindings: { timeoutMs: 9 } }), 15000);
  assert.equal(_test.resolveTimeoutMs({ limits: {}, bindings: { timeoutMs: 9 } }), 9);
  assert.equal(_test.resolveTimeoutMs({ limits: {}, bindings: { timeoutMs: -1 } }), 15000);

  assert.deepEqual(_test.buildTlsOptions({}), {});
  assert.ok(_test.buildTlsOptions({ skipTlsVerify: true }, 'https://example.com').dispatcher);
  assert.deepEqual(_test.buildTlsOptions({ skipTlsVerify: true }, 'http://example.com'), {});

  assert.equal(_test.getServerId({ server_id: 's1' }), 's1');
  assert.equal(_test.getServerId({ serverId: { value: ' s2 ' } }), 's2');
  assert.throws(() => _test.getServerId({}), /server_id/);

  assert.equal(_test.substitutePath('/v2/{project_id}/servers/{server_id}', { project_id: 'p', server_id: 's' }), '/v2/p/servers/s');
  assert.equal(_test.substitutePath('/v3/projects', {}), '/v3/projects');

  assert.deepEqual(_test.mapAddresses({ net1: [{ addr: '10.0.0.1' }, { addr: '10.0.0.2' }] }), { net1: '10.0.0.1,10.0.0.2' });
  assert.deepEqual(_test.mapAddresses(null), {});
  assert.deepEqual(_test.mapAddresses({ net1: 'bad' }), {});

  // Project new fields
  const p = _test.mapProjects({ projects: [{ id: 'p1', name: 'n', enabled: true, domain_id: 'd1', description: 'desc', parent_id: 'root', is_domain: true, tags: ['t1'], links: { self: 'x' } }] })[0];
  assert.equal(p.is_domain, true);
  assert.deepEqual(JSON.parse(p.tags_json), ['t1']);
  assert.match(p.links_json, /self/);

  // Server with all new fields
  const fullSrv = {
    id: 's1', name: 'web', status: 'ACTIVE', addresses: { n: [{ addr: '1.1.1.1' }] },
    'OS-DCF:diskConfig': 'AUTO',
    description: 'desc', key_name: 'k', locked: 'yes', host_status: 'UP', progress: '50',
    config_drive: 'True', tags: ['a', 'b'],
    'OS-EXT-AZ:availability_zone': 'nova',
    'OS-EXT-SRV-ATTR:host': 'h', 'OS-EXT-SRV-ATTR:hostname': 'h.local',
    'OS-EXT-SRV-ATTR:hypervisor_hostname': 'hyp',
    'OS-EXT-SRV-ATTR:instance_name': 'inst', 'OS-EXT-SRV-ATTR:kernel_id': 'k',
    'OS-EXT-SRV-ATTR:launch_index': '3',
    'OS-EXT-SRV-ATTR:ramdisk_id': 'r', 'OS-EXT-SRV-ATTR:reservation_id': 'res',
    'OS-EXT-SRV-ATTR:root_device_name': '/dev/vda', 'OS-EXT-SRV-ATTR:user_data': 'u',
    'OS-SRV-USG:launched_at': '2026', 'OS-SRV-USG:terminated_at': null,
    'os-extended-volumes:volumes_attached': [{ id: 'v1' }],
    security_groups: [{ name: 'default' }],
    trusted_image_certificates: ['cert-1'],
    links: [{ rel: 'self', href: 'http://x/s1' }],
  };
  const srvMapped = _test.mapServers({ servers: [fullSrv] })[0];
  assert.equal(srvMapped.os_dcf_disk_config, 'AUTO');
  assert.equal(srvMapped.description, 'desc');
  assert.equal(srvMapped.key_name, 'k');
  assert.equal(srvMapped.locked, true);
  assert.equal(srvMapped.host_status, 'UP');
  assert.equal(srvMapped.progress, 50);
  assert.equal(srvMapped.config_drive, 'True');
  assert.deepEqual(JSON.parse(srvMapped.tags), ['a', 'b']);
  assert.equal(srvMapped.os_ext_az_availability_zone, 'nova');
  assert.equal(srvMapped.os_ext_srv_attr_host, 'h');
  assert.equal(srvMapped.os_ext_srv_attr_launch_index, 3);
  assert.equal(srvMapped.os_srv_usg_launched_at, '2026');
  assert.equal(srvMapped.os_srv_usg_terminated_at, '');
  assert.deepEqual(JSON.parse(srvMapped.os_extended_volumes_volumes_attached_json), [{ id: 'v1' }]);
  assert.deepEqual(JSON.parse(srvMapped.security_groups_json), [{ name: 'default' }]);
  assert.deepEqual(JSON.parse(srvMapped.trusted_image_certificates_json), ['cert-1']);
  assert.match(srvMapped.links_json, /self/);

  // Single-server map with minimal input uses defaults
  const single = _test.mapServer({ server: { id: 's1', name: 'web' } });
  assert.equal(single.id, 's1');
  assert.equal(single.name, 'web');
  assert.equal(single.status, '');
  assert.equal(single.locked, false);
  assert.equal(single.progress, 0);
  assert.equal(single.security_groups_json, '[]');
  assert.equal(single.links_json, '[]');

  // Networks with new fields
  const netMapped = _test.mapNetworks({ networks: [{
    id: 'n1', name: 'priv', admin_state_up: true, shared: false, 'router:external': false,
    dns_domain: 'd', mtu: '9000', qos_policy_id: 'q', revision_number: '7',
    created_at: '2026-01-01', updated_at: '2026-01-02',
    port_security_enabled: 'no', is_default: 1, ipv4_address_scope: 'asc',
    availability_zone_hints: ['z1'], availability_zones: ['z2'],
    subnets: ['s1', 's2'], vlan_transparent: 'yes', qinq: 'no', l2_adjacency: 'true',
  }] })[0];
  assert.equal(netMapped.dns_domain, 'd');
  assert.equal(netMapped.mtu, 9000);
  assert.equal(netMapped.qos_policy_id, 'q');
  assert.equal(netMapped.revision_number, 7);
  assert.equal(netMapped.port_security_enabled, false);
  assert.equal(netMapped.is_default, true);
  assert.equal(netMapped.vlan_transparent, true);
  assert.equal(netMapped.qinq, false);
  assert.equal(netMapped.l2_adjacency, true);
  assert.deepEqual(JSON.parse(netMapped.availability_zone_hints_json), ['z1']);

  // Volumes with new fields
  const volMapped = _test.mapVolumes({ volumes: [{
    id: 'v1', name: 'data', size: '50', status: 'ok', bootable: 'true', encrypted: 'yes', multiattach: 1,
    description: 'd', consistencygroup_id: 'cg', migration_status: 'm', replication_status: 'r',
    snapshot_id: 's', source_volid: 'sv',
    'os-vol-host-attr:host': 'h@ssd', 'os-vol-mig-status-attr:migstat': 'mig', 'os-vol-mig-status-attr:name_id': 'mn',
    provider_id: 'p', group_id: 'g', service_uuid: 'su', cluster_name: 'cn', consumes_quota: 'true',
    volume_type_id: 'vti', attachments: [{ id: 'a' }], metadata: { k: 'v' },
    links: [{ rel: 'self' }], shared_targets: [{ host: 'h' }],
  }] })[0];
  assert.equal(volMapped.size, 50);
  assert.equal(volMapped.encrypted, true);
  assert.equal(volMapped.multiattach, true);
  assert.equal(volMapped.description, 'd');
  assert.equal(volMapped.snapshot_id, 's');
  assert.equal(volMapped.source_volid, 'sv');
  assert.equal(volMapped.provider_id, 'p');
  assert.equal(volMapped.cluster_name, 'cn');
  assert.equal(volMapped.consumes_quota, 'true');
  assert.equal(volMapped.volume_type_id, 'vti');
  assert.deepEqual(JSON.parse(volMapped.attachments_json), [{ id: 'a' }]);
  assert.deepEqual(JSON.parse(volMapped.metadata_json), { k: 'v' });
  assert.match(volMapped.links_json, /self/);

  // Flavors with new fields
  const flMapped = _test.mapFlavors({ flavors: [{
    id: 'f', name: 'tiny', vcpus: 1, ram: 512, disk: 1, swap: 0,
    'OS-FLV-EXT-DATA:ephemeral': 20,
    'os-flavor-access:is_public': true, 'OS-FLV-DISABLED:disabled': false,
    description: 'tiny', extra_specs: { hw: 'x' }, links: [{ rel: 'self' }],
  }] })[0];
  assert.equal(flMapped.ephemeral, 20);
  assert.equal(flMapped.description, 'tiny');
  assert.equal(flMapped.is_public, true);
  assert.match(flMapped.extra_specs_json, /hw/);

  assert.equal(_test.mapHttpStatusToCode(401), 'PERMISSION_DENIED');
  assert.equal(_test.mapHttpStatusToCode(403), 'PERMISSION_DENIED');
  assert.equal(_test.mapHttpStatusToCode(404), 'NOT_FOUND');
  assert.equal(_test.mapHttpStatusToCode(400), 'FAILED_PRECONDITION');
  assert.equal(_test.mapHttpStatusToCode(500), 'UNAVAILABLE');

  assert.doesNotThrow(() => _test.assertUpstreamStatus(200, 'ok', 'x'));
  assert.throws(() => _test.assertUpstreamStatus(401, 'no', 'x'), /PERMISSION_DENIED/);
  assert.throws(() => _test.assertUpstreamStatus(404, 'missing', 'x'), /NOT_FOUND/);
  assert.throws(() => _test.assertUpstreamStatus(500, 'boom', 'x'), /UNAVAILABLE/);

  const ctx = buildCtx();
  const body = _test.buildAuthRequestBody(ctx);
  assert.deepEqual(body.auth.identity.methods, ['password']);
  assert.equal(body.auth.identity.password.user.name, USERNAME);
  assert.equal(body.auth.identity.password.user.password, PASSWORD);
  assert.equal(body.auth.identity.password.user.domain.name, 'Default');
  assert.equal(body.auth.scope.project.name, PROJECT_NAME);
  assert.equal(body.auth.scope.project.domain.name, 'Default');

  const logs = [];
  console.log = (...args) => logs.push(args);
  _test.logFlow(buildCtx({ meta: { instance_id: 'i', request_id: 'r' } }), 'action', { ok: true });
  const circular = {};
  circular.self = circular;
  _test.logFlow({}, 'fallback', circular);
  assert.match(logs[0][0], /\[OpenStack_Yoga_2022_1\]\[action\]\[inst=i req=r\]/);
  assert.match(logs[1][0], /\[OpenStack_Yoga_2022_1\]\[fallback\]/);

  assert.deepEqual(_test.buildUpstreamHeaders('abc'), { 'X-Auth-Token': 'abc', Accept: 'application/json' });

  assert.equal(_test.toInt64('15'), 15);
  assert.equal(_test.toInt64(null), 0);
  assert.equal(_test.toBool('yes'), true);
  assert.equal(_test.toBool('off'), false);
  assert.equal(_test.toBool('maybe', true), true);

  assert.equal(_test.pickProjectIdOverride({ project_id: 'p1' }), 'p1');
  assert.equal(_test.pickProjectIdOverride({}), '');
});

test('ListFlavors extra_specs preserved as JSON and links include self+bookmark', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const ctx = buildCtx({ config: { auth_url: baseUrl, allowInsecureHttp: true } });
    const result = await handlers[METHOD_LIST_FLAVORS_FULL]({}, ctx);
    const small = result.flavors[0];
    assert.match(small.extra_specs_json, /hw:numa_nodes/);
    assert.match(small.links_json, /self/);
    assert.match(small.links_json, /bookmark/);
  } finally { await mock.close(); }
});

test('ListVolumes attachments_json deserializes a real volume-server attachment', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const ctx = buildCtx({ config: { auth_url: baseUrl, allowInsecureHttp: true } });
    const result = await handlers[METHOD_LIST_VOLUMES_FULL]({}, ctx);
    const v = result.volumes[0];
    const atts = JSON.parse(v.attachments_json);
    assert.equal(atts[0].server_id, 'srv-0001');
    assert.equal(atts[0].device, '/dev/vdb');
  } finally { await mock.close(); }
});

test('ListProjects tags and links surfaces from mock payload', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const ctx = buildCtx({ config: { auth_url: baseUrl, allowInsecureHttp: true } });
    const result = await handlers[METHOD_LIST_PROJECTS_FULL]({}, ctx);
    assert.deepEqual(JSON.parse(result.projects[0].tags_json), ['alpha-tag']);
    assert.match(result.projects[0].links_json, /self/);
  } finally { await mock.close(); }
});

test('toJsonString covers all branches', () => {
  assert.equal(_test.toJsonString('{"a":1}'), '{"a":1}');
  assert.equal(_test.toJsonString(null), '');
  assert.equal(_test.toJsonString([1, 2, 3]), '[1,2,3]');
});

test('performAuthenticatedGet end-to-end covers all branches', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    setFetch(originalFetch);
    const ctx = buildCtx({ config: { auth_url: baseUrl, allowInsecureHttp: true } });
    const result = await _test.performAuthenticatedGet(ctx, '/v2/{project_id}/servers', { project_id: PROJECT_ID }, 'ListServers');
    assert.equal(result.httpStatus, 200);
    assert.equal(result.projectId, PROJECT_ID);
    assert.equal(result.json.servers.length, 2);
    assert.equal(result.json.servers[0].id, 'srv-0001');

    const result2 = await _test.performAuthenticatedGet(ctx, '/v3/projects', {}, 'ListProjects');
    assert.equal(result2.json.projects.length, 2);

    const result3 = await _test.performAuthenticatedGet(ctx, '/v2.0/networks', {}, 'ListNetworks');
    assert.equal(result3.json.networks.length, 2);
  } finally { await mock.close(); }
});

test('performAuthenticatedGet rejects 401 as PERMISSION_DENIED', async () => {
  setFetch(async (url) => {
    if (String(url).endsWith('/v3/auth/tokens')) {
      return responseOf(201, { token: { user: { id: 'u' }, project: { id: PROJECT_ID } } }, { 'x-subject-token': TOKEN });
    }
    return responseOf(401, 'no auth');
  });
  await expectGrpcError(
    () => _test.performAuthenticatedGet(buildCtx(), '/v3/projects', {}, 'ListProjects'),
    'PERMISSION_DENIED',
  );
});

test('performAuthenticatedGet rejects invalid JSON as UNKNOWN', async () => {
  setFetch(async (url) => {
    if (String(url).endsWith('/v3/auth/tokens')) {
      return responseOf(201, { token: { user: { id: 'u' }, project: { id: PROJECT_ID } } }, { 'x-subject-token': TOKEN });
    }
    return responseOf(200, 'not-valid-json{');
  });
  await expectGrpcError(
    () => _test.performAuthenticatedGet(buildCtx(), '/v3/projects', {}, 'ListProjects'),
    'UNKNOWN',
    (err) => assert.match(err.message, /not valid JSON/),
  );
});

test('obtainToken handles unparseable auth body (catch branch) by throwing FAILED_PRECONDITION', async () => {
  setFetch(async () => responseOf(201, 'this is not json {', { 'x-subject-token': TOKEN }));
  await expectGrpcError(
    () => _test.obtainToken(buildCtx()),
    'FAILED_PRECONDITION',
    (err) => assert.match(err.message, /missing token\.project\.id/),
  );
});

test('obtainToken falls back to project.name when project.id missing', async () => {
  setFetch(async () => responseOf(201, {
    token: {
      project: { name: 'fallback-name' },
      user: { id: 'u' },
    },
  }, { 'x-subject-token': TOKEN }));
  const t = await _test.obtainToken(buildCtx());
  assert.equal(t.projectId, 'fallback-name');
});

test('obtainToken extracts expires_at from token', async () => {
  setFetch(async () => responseOf(201, {
    token: { project: { id: 'p' }, user: { id: 'u' }, expires_at: '2030-01-01T00:00:00Z' },
  }, { 'x-subject-token': TOKEN }));
  const t = await _test.obtainToken(buildCtx());
  assert.equal(t.expiresAt, '2030-01-01T00:00:00Z');
});

test('obtainToken throws FAILED_PRECONDITION when empty body and X-Subject-Token present', async () => {
  // Empty body -> JSON.parse('') -> throws -> catch sets projectId='' -> FAILED_PRECONDITION thrown
  setFetch(async () => responseOf(201, '', { 'x-subject-token': TOKEN }));
  await expectGrpcError(
    () => _test.obtainToken(buildCtx()),
    'FAILED_PRECONDITION',
  );
});

test('buildAuthRequestBody covers all branch combinations', () => {
  // Both userDomain and projectDomain set
  const b1 = _test.buildAuthRequestBody(buildCtx({
    config: { ...baseBindings, user_domain_name: 'CustomUser', project_domain_name: 'CustomProj' },
  }));
  assert.equal(b1.auth.identity.password.user.domain.name, 'CustomUser');
  assert.equal(b1.auth.scope.project.name, PROJECT_NAME);
  assert.equal(b1.auth.scope.project.domain.name, 'CustomProj');

  // Default user_domain and project_domain
  const b2 = _test.buildAuthRequestBody(buildCtx());
  assert.equal(b2.auth.identity.password.user.domain.name, 'Default');
  assert.equal(b2.auth.scope.project.name, PROJECT_NAME);
  assert.equal(b2.auth.scope.project.domain.name, 'Default');

  // user_domain set, no project_domain -> project_domain falls back to user_domain
  const b3 = _test.buildAuthRequestBody(buildCtx({
    config: { ...baseBindings, project_domain_name: '' },
  }));
  assert.equal(b3.auth.identity.password.user.domain.name, 'Default');
  // project_domain: resolveProjectDomainName returns '' (empty), then '' || userDomain || Default
  // resolveProjectDomainName: bindings.project_domain_name='' -> toTrimmedString('') = ''
  // '' || 'Default' || 'Default' = 'Default'
  assert.equal(b3.auth.scope.project.domain.name, 'Default');
});

test('normalizeAuthUrl covers all input branches', () => {
  assert.equal(_test.normalizeAuthUrl('https://x/', false), 'https://x');
  assert.equal(_test.normalizeAuthUrl('http://x/', false), '');
  assert.equal(_test.normalizeAuthUrl('http://x/', true), 'http://x');
  assert.equal(_test.normalizeAuthUrl('', false), '');
  assert.equal(_test.normalizeAuthUrl('ftp://x', false), '');
  assert.equal(_test.normalizeAuthUrl('  https://x  ', false), 'https://x');
  assert.equal(_test.normalizeAuthUrl('https://x//', false), 'https://x');
});

test('mapHttpStatusToCode covers 200, 4xx, 5xx branches', () => {
  assert.equal(_test.mapHttpStatusToCode(200), 'UNAVAILABLE');
  assert.equal(_test.mapHttpStatusToCode(204), 'UNAVAILABLE');
  assert.equal(_test.mapHttpStatusToCode(401), 'PERMISSION_DENIED');
  assert.equal(_test.mapHttpStatusToCode(403), 'PERMISSION_DENIED');
  assert.equal(_test.mapHttpStatusToCode(404), 'NOT_FOUND');
  assert.equal(_test.mapHttpStatusToCode(400), 'FAILED_PRECONDITION');
  assert.equal(_test.mapHttpStatusToCode(499), 'FAILED_PRECONDITION');
  assert.equal(_test.mapHttpStatusToCode(500), 'UNAVAILABLE');
  assert.equal(_test.mapHttpStatusToCode(502), 'UNAVAILABLE');
  assert.equal(_test.mapHttpStatusToCode(504), 'UNAVAILABLE');
});

test('toBool covers all input types', () => {
  // boolean
  assert.equal(_test.toBool(true), true);
  assert.equal(_test.toBool(false), false);
  // number (non-zero is true, zero is false)
  assert.equal(_test.toBool(1), true);
  assert.equal(_test.toBool(0), false);
  // NaN is not zero so is treated as true
  assert.equal(_test.toBool(NaN), true);
  // string true variants
  assert.equal(_test.toBool('true'), true);
  assert.equal(_test.toBool('TRUE'), true);
  assert.equal(_test.toBool('1'), true);
  assert.equal(_test.toBool('yes'), true);
  assert.equal(_test.toBool('YES'), true);
  assert.equal(_test.toBool('on'), true);
  // string false variants
  assert.equal(_test.toBool('false'), false);
  assert.equal(_test.toBool('FALSE'), false);
  assert.equal(_test.toBool('0'), false);
  assert.equal(_test.toBool('no'), false);
  assert.equal(_test.toBool('off'), false);
  assert.equal(_test.toBool(''), false);
  // string with whitespace
  assert.equal(_test.toBool('  true  '), true);
  // unrecognized string returns fallback
  assert.equal(_test.toBool('maybe', true), true);
  assert.equal(_test.toBool('maybe', false), false);
  // null/undefined return fallback
  assert.equal(_test.toBool(null, 'def'), 'def');
  assert.equal(_test.toBool(undefined, 'def'), 'def');
});

test('mapServerCommon returns null for non-object input', () => {
  assert.equal(_test.mapServerCommon(null), null);
  assert.equal(_test.mapServerCommon(undefined), null);
  assert.equal(_test.mapServerCommon('not-an-object'), null);
});

test('mapServer empty payload returns the full default-shaped object', () => {
  const m = _test.mapServer({ server: {} });
  assert.equal(m.id, '');
  assert.equal(m.tags, '[]');
  assert.equal(m.security_groups_json, '[]');
  assert.equal(m.links_json, '[]');
  assert.equal(m.os_extended_volumes_volumes_attached_json, '[]');
  assert.equal(m.trusted_image_certificates_json, '[]');
});

test('resolveTimeoutMs falls back to default when timeout is not positive', () => {
  assert.equal(_test.resolveTimeoutMs({ limits: {}, bindings: {} }), 15000);
  assert.equal(_test.resolveTimeoutMs({ limits: { timeoutMs: 0 }, bindings: {} }), 15000);
});

test('mapAddresses returns {} when entries are not arrays', () => {
  assert.deepEqual(_test.mapAddresses({ n1: 'not-array' }), {});
  assert.deepEqual(_test.mapAddresses({ n1: null }), {});
});

test('list mappers handle missing keys', () => {
  assert.deepEqual(_test.mapServers({}), []);
  assert.deepEqual(_test.mapServers({ servers: null }), []);
  assert.deepEqual(_test.mapNetworks({}), []);
  assert.deepEqual(_test.mapNetworks({ networks: null }), []);
  assert.deepEqual(_test.mapVolumes({}), []);
  assert.deepEqual(_test.mapVolumes({ volumes: null }), []);
  assert.deepEqual(_test.mapFlavors({}), []);
  assert.deepEqual(_test.mapFlavors({ flavors: null }), []);
  assert.deepEqual(_test.mapProjects({}), []);
  assert.deepEqual(_test.mapProjects({ projects: null }), []);
});

test('GetServer invalid server_id propagates to NOT_FOUND via mock 404', async () => {
  const mock = createMockServer();
  const baseUrl = await mock.start();
  try {
    const ctx = buildCtx({ config: { auth_url: baseUrl, allowInsecureHttp: true } });
    await expectGrpcError(
      () => handlers[METHOD_GET_SERVER_FULL]({ server_id: 'srv-missing' }, ctx),
      'NOT_FOUND',
    );
  } finally { await mock.close(); }
});


test('emptyServer default shape', () => {
  const e = _test.emptyServer();
  assert.equal(e.id, '');
  assert.equal(e.locked, false);
  assert.equal(e.progress, 0);
  assert.equal(e.tags, '[]');
  assert.equal(e.security_groups_json, '[]');
  assert.equal(e.links_json, '[]');
  assert.equal(e.trusted_image_certificates_json, '[]');
  assert.equal(e.os_extended_volumes_volumes_attached_json, '[]');
  assert.equal(e.os_srv_usg_launched_at, '');
  assert.equal(e.os_srv_usg_terminated_at, '');
});
