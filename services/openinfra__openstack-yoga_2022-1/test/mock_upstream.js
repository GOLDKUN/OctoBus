/* node:coverage disable */
import http from 'node:http';
import { randomUUID } from 'node:crypto';

export const USERNAME = 'octobus-user';
export const PASSWORD = 'octobus-pass';
export const PROJECT_NAME = 'service';
export const PROJECT_ID = 'p-abcdef123456';
export const USER_DOMAIN = 'Default';
export const PROJECT_DOMAIN = 'Default';
export const TOKEN = 'mock-keystone-token-xyz';

const NETWORK_ID_1 = 'net-1111';
const NETWORK_ID_2 = 'net-2222';
const FLAVOR_ID_1 = 'flavor-small';
const FLAVOR_ID_2 = 'flavor-large';
const SERVER_ID_1 = 'srv-0001';
const SERVER_ID_2 = 'srv-0002';
const VOLUME_ID_1 = 'vol-aaaa';
const VOLUME_ID_2 = 'vol-bbbb';
const PROJECT_A = 'proj-aaa';
const PROJECT_B = 'proj-bbb';

const readJsonBody = (req, limit = 1024 * 1024) => new Promise((resolve, reject) => {
  let raw = '';
  req.on('data', (chunk) => {
    raw += chunk;
    if (raw.length > limit) req.destroy(new Error('payload too large'));
  });
  req.on('end', () => {
    if (!raw.trim()) return resolve({});
    try { resolve(JSON.parse(raw)); } catch (err) { reject(err); }
  });
  req.on('error', reject);
});

const sendJson = (res, status, payload) => {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'content-length': Buffer.byteLength(body),
  });
  res.end(body);
};

const authOkBody = (baseUrl) => ({
  token: {
    methods: ['password'],
    user: { id: 'u-0001', name: USERNAME, domain: { id: 'ud-1', name: USER_DOMAIN } },
    project: { id: PROJECT_ID, name: PROJECT_NAME, domain: { id: 'pd-1', name: PROJECT_DOMAIN } },
    issued_at: '2026-01-01T00:00:00.000000Z',
    expires_at: '2026-01-01T01:00:00.000000Z',
    catalog: [
      { type: 'compute', name: 'nova', endpoints: [{ interface: 'public', region: 'RegionOne', region_id: 'RegionOne', url: `${baseUrl}/v2.1/%(project_id)s` }] },
      { type: 'network', name: 'neutron', endpoints: [{ interface: 'public', region: 'RegionOne', region_id: 'RegionOne', url: baseUrl }] },
      { type: 'volumev3', name: 'cinderv3', endpoints: [{ interface: 'public', region: 'RegionOne', region_id: 'RegionOne', url: `${baseUrl}/v3/%(project_id)s` }] },
    ],
  },
});

const projectsPayload = () => ({
  links: { self: 'http://localhost/v3/projects', previous: null, next: null },
  projects: [
    {
      id: PROJECT_A, name: 'alpha', domain_id: 'pd-1', enabled: true,
      description: 'Alpha project', parent_id: 'root', is_domain: false,
      tags: ['alpha-tag'],
      links: { self: 'http://localhost/v3/projects/proj-aaa' },
    },
    {
      id: PROJECT_B, name: 'beta', domain_id: 'pd-1', enabled: true,
      description: 'Beta project', parent_id: 'root', is_domain: false,
      tags: [],
      links: { self: 'http://localhost/v3/projects/proj-bbb' },
    },
  ],
});

const serverBaseFields = (id, name, status, az, host, flavorId, imageId, networkId, addr) => ({
  id, name, status,
  tenant_id: PROJECT_ID, user_id: 'u-0001',
  created: '2026-01-01T00:00:00Z', updated: '2026-01-01T00:30:00Z',
  hostId: host,
  'OS-DCF:diskConfig': 'AUTO',
  description: `${name} description`,
  key_name: `${name}-key`,
  locked: false, locked_reason: null,
  host_status: 'UP', progress: 0,
  config_drive: '',
  tags: [`tag-${name}`],
  'OS-EXT-AZ:availability_zone': az,
  'OS-EXT-SRV-ATTR:host': host,
  'OS-EXT-SRV-ATTR:hostname': `${name}.local`,
  'OS-EXT-SRV-ATTR:hypervisor_hostname': `${host}.hyper.local`,
  'OS-EXT-SRV-ATTR:instance_name': `instance-${id}`,
  'OS-EXT-SRV-ATTR:kernel_id': 'kernel-xyz',
  'OS-EXT-SRV-ATTR:launch_index': 0,
  'OS-EXT-SRV-ATTR:ramdisk_id': 'ramdisk-xyz',
  'OS-EXT-SRV-ATTR:reservation_id': 'r-0001',
  'OS-EXT-SRV-ATTR:root_device_name': '/dev/vda',
  'OS-EXT-SRV-ATTR:user_data': 'IyEvYmluL2Jhc2gK',
  'OS-SRV-USG:launched_at': '2026-01-01T00:00:00.000000',
  'OS-SRV-USG:terminated_at': null,
  'os-extended-volumes:volumes_attached': [],
  security_groups: [{ name: 'default' }],
  trusted_image_certificates: ['trusted-cert-1'],
  flavor: { id: flavorId },
  image: { id: imageId },
  addresses: { [networkId]: [{ addr, version: 4 }] },
  accessIPv4: addr, accessIPv6: '',
  metadata: { group: 'web' },
  'OS-EXT-STS:power_state': status === 'ACTIVE' ? 'Running' : 'Shutdown',
  'OS-EXT-STS:vm_state': status === 'ACTIVE' ? 'active' : 'stopped',
  'OS-EXT-STS:task_state': null,
  links: [
    { rel: 'self', href: `http://localhost/v2/${PROJECT_ID}/servers/${id}` },
    { rel: 'bookmark', href: `http://localhost/${PROJECT_ID}/servers/${id}` },
  ],
});

const serversPayload = () => ({
  servers: [
    serverBaseFields(SERVER_ID_1, 'web-1', 'ACTIVE', 'nova', 'host-01', FLAVOR_ID_1, 'img-cirros', NETWORK_ID_1, '10.0.0.5'),
    serverBaseFields(SERVER_ID_2, 'db-1', 'SHUTOFF', 'nova', 'host-02', FLAVOR_ID_2, 'img-ubuntu', NETWORK_ID_2, '10.0.1.7'),
  ],
});

const serverDetailPayload = (id) => ({
  server: serverBaseFields(
    id,
    id === SERVER_ID_2 ? 'db-1' : 'web-1',
    id === SERVER_ID_2 ? 'SHUTOFF' : 'ACTIVE',
    'nova', 'host-01',
    id === SERVER_ID_2 ? FLAVOR_ID_2 : FLAVOR_ID_1,
    'img-cirros', NETWORK_ID_1, '10.0.0.5',
  ),
});

const networksPayload = () => ({
  networks: [
    {
      id: NETWORK_ID_1, name: 'private', status: 'ACTIVE',
      admin_state_up: true, shared: false, 'router:external': false,
      tenant_id: PROJECT_ID, project_id: PROJECT_ID,
      'provider:network_type': 'vxlan', 'provider:segmentation_id': '1001',
      dns_domain: 'local.', mtu: 1450, qos_policy_id: null,
      revision_number: 1, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-02T00:00:00Z',
      port_security_enabled: true, is_default: false,
      ipv4_address_scope: null, ipv6_address_scope: null,
      availability_zone_hints: [], availability_zones: ['nova'],
      subnets: ['subnet-1111'],
      vlan_transparent: false, qinq: false, l2_adjacency: false,
    },
    {
      id: NETWORK_ID_2, name: 'public', status: 'ACTIVE',
      admin_state_up: true, shared: true, 'router:external': true,
      tenant_id: PROJECT_ID, project_id: PROJECT_ID,
      'provider:network_type': 'flat', 'provider:segmentation_id': '',
      dns_domain: '', mtu: 1500, qos_policy_id: 'qos-public',
      revision_number: 2, created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-02T00:00:00Z',
      port_security_enabled: false, is_default: true,
      ipv4_address_scope: 'asc-ipv4-public', ipv6_address_scope: null,
      availability_zone_hints: ['nova'], availability_zones: ['nova'],
      subnets: ['subnet-2222', 'subnet-3333'],
      vlan_transparent: true, qinq: false, l2_adjacency: true,
    },
  ],
});

const volumesPayload = () => ({
  volumes: [
    {
      id: VOLUME_ID_1, name: 'data-1', status: 'in-use', size: 20,
      volume_type: 'ssd', volume_type_id: 'type-ssd',
      created_at: '2026-01-01T00:00:00.000000', updated_at: '2026-01-02T00:00:00.000000',
      tenant_id: PROJECT_ID, project_id: PROJECT_ID,
      availability_zone: 'nova', bootable: 'true',
      description: 'Data volume 1', encrypted: true, multiattach: false,
      consistencygroup_id: null, migration_status: null, replication_status: 'disabled',
      snapshot_id: null, source_volid: null,
      'os-vol-host-attr:host': 'host-01@ssd#ssd',
      'os-vol-mig-status-attr:migstat': null,
      'os-vol-mig-status-attr:name_id': null,
      provider_id: 'provider-uuid-1', group_id: null, service_uuid: 'svc-uuid-1',
      cluster_name: null, consumes_quota: 'true',
      attachments: [{ id: 'att-1', server_id: SERVER_ID_1, device: '/dev/vdb', host_name: 'host-01' }],
      metadata: { attached: 'true' },
      shared_targets: [],
      links: [{ rel: 'self', href: `http://localhost/v3/${PROJECT_ID}/volumes/${VOLUME_ID_1}` }],
    },
    {
      id: VOLUME_ID_2, name: 'data-2', status: 'available', size: 100,
      volume_type: 'hdd', volume_type_id: 'type-hdd',
      created_at: '2026-01-01T01:00:00.000000', updated_at: '2026-01-02T01:00:00.000000',
      tenant_id: PROJECT_ID, project_id: PROJECT_ID,
      availability_zone: 'nova', bootable: 'false',
      description: 'Data volume 2', encrypted: false, multiattach: true,
      consistencygroup_id: 'cg-1', migration_status: 'migrating', replication_status: 'enabled',
      snapshot_id: 'snap-1', source_volid: 'vol-source',
      'os-vol-host-attr:host': 'host-02@hdd#hdd',
      'os-vol-mig-status-attr:migstat': 'migrating',
      'os-vol-mig-status-attr:name_id': 'mig-name-1',
      provider_id: 'provider-uuid-2', group_id: 'group-1', service_uuid: 'svc-uuid-2',
      cluster_name: 'cluster-1', consumes_quota: 'false',
      attachments: [], metadata: { project: 'beta' },
      shared_targets: [{ host: 'host-02' }],
      links: [{ rel: 'self', href: `http://localhost/v3/${PROJECT_ID}/volumes/${VOLUME_ID_2}` }],
    },
  ],
});

const flavorsPayload = () => ({
  flavors: [
    {
      id: FLAVOR_ID_1, name: 'm1.small', vcpus: 1, ram: 2048, disk: 20, swap: 0, rxtx_factor: 1,
      'OS-FLV-EXT-DATA:ephemeral': 0,
      'os-flavor-access:is_public': true,
      'OS-FLV-DISABLED:disabled': false,
      description: 'Small flavor',
      extra_specs: { 'hw:numa_nodes': '1' },
      links: [
        { rel: 'self', href: `http://localhost/v2/${PROJECT_ID}/flavors/${FLAVOR_ID_1}` },
        { rel: 'bookmark', href: `http://localhost/${PROJECT_ID}/flavors/${FLAVOR_ID_1}` },
      ],
    },
    {
      id: FLAVOR_ID_2, name: 'm1.large', vcpus: 4, ram: 8192, disk: 80, swap: 0, rxtx_factor: 2,
      'OS-FLV-EXT-DATA:ephemeral': 40,
      'os-flavor-access:is_public': true,
      'OS-FLV-DISABLED:disabled': false,
      description: 'Large flavor',
      extra_specs: { 'hw:numa_nodes': '2' },
      links: [
        { rel: 'self', href: `http://localhost/v2/${PROJECT_ID}/flavors/${FLAVOR_ID_2}` },
        { rel: 'bookmark', href: `http://localhost/${PROJECT_ID}/flavors/${FLAVOR_ID_2}` },
      ],
    },
  ],
});

const requireAuth = (req, res) => {
  const token = req.headers['x-auth-token'];
  if (!token) { sendJson(res, 401, { error: { code: 401, message: 'X-Auth-Token header is required' } }); return false; }
  if (token === 'invalid-token') { sendJson(res, 401, { error: { code: 401, message: 'Token is not valid' } }); return false; }
  if (token === 'forbidden-token') { sendJson(res, 403, { error: { code: 403, message: 'Token is forbidden' } }); return false; }
  return true;
};

export function createMockServer() {
  const requests = [];
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const path = url.pathname;
    requests.push({ method: req.method, path, headers: req.headers });

    if (req.method === 'POST' && path === '/v3/auth/tokens') {
      let body;
      try { body = await readJsonBody(req); }
      catch (err) { sendJson(res, 400, { error: { code: 400, message: `bad json: ${err.message}` } }); return; }
      const user = body?.auth?.identity?.password?.user;
      if (!user || !user.name || !user.password) { sendJson(res, 400, { error: { code: 400, message: 'identity.password.user.{name,password} required' } }); return; }
      if (user.name !== USERNAME || user.password !== PASSWORD) { sendJson(res, 401, { error: { code: 401, message: 'invalid credentials' } }); return; }
      const expectedUserDomain = body?.auth?.identity?.password?.user?.domain?.name || USER_DOMAIN;
      if (expectedUserDomain !== USER_DOMAIN) { sendJson(res, 401, { error: { code: 401, message: 'user domain mismatch' } }); return; }
      const scope = body?.auth?.scope?.project;
      if (!scope || !scope.name) { sendJson(res, 401, { error: { code: 401, message: 'scope.project.name required' } }); return; }
      if (scope.name !== PROJECT_NAME) { sendJson(res, 401, { error: { code: 401, message: 'unknown project' } }); return; }
      res.writeHead(201, { 'Content-Type': 'application/json', 'X-Subject-Token': TOKEN });
      res.end(JSON.stringify(authOkBody(`http://${req.headers.host}`)));
      return;
    }

    if (req.method !== 'GET') {
      res.writeHead(405, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { code: 405, message: 'method not allowed' } }));
      return;
    }
    if (!requireAuth(req, res)) return;

    if (path === '/v3/projects') { sendJson(res, 200, projectsPayload()); return; }

    const serversListMatch = path.match(/^\/v2(?:\.1)?\/([^/]+)\/servers$/);
    if (serversListMatch) {
      const requestedProjectId = serversListMatch[1];
      if (requestedProjectId === 'p-UNKNOWN') { sendJson(res, 404, { error: { code: 404, message: 'project not found' } }); return; }
      if (requestedProjectId === 'p-HTTP500') { sendJson(res, 500, { error: { code: 500, message: 'internal error' } }); return; }
      sendJson(res, 200, serversPayload());
      return;
    }

    const serverDetailMatch = path.match(/^\/v2(?:\.1)?\/([^/]+)\/servers\/([^/]+)$/);
    if (serverDetailMatch) {
      const [, projectPart, serverId] = serverDetailMatch;
      if (projectPart === 'p-HTTP500') { sendJson(res, 500, { error: { code: 500, message: 'internal error' } }); return; }
      if (serverId === 'srv-missing') { sendJson(res, 404, { itemNotFound: { code: 404, message: `server ${serverId} not found` } }); return; }
      sendJson(res, 200, serverDetailPayload(serverId));
      return;
    }

    const flavorsMatch = path.match(/^\/v2(?:\.1)?\/([^/]+)\/flavors$/);
    if (flavorsMatch) { sendJson(res, 200, flavorsPayload()); return; }

    if (path === '/v2.0/networks') { sendJson(res, 200, networksPayload()); return; }

    const volumesMatch = path.match(/^\/v3\/([^/]+)\/volumes$/);
    if (volumesMatch) {
      const requestedProjectId = volumesMatch[1];
      if (requestedProjectId === 'p-UNKNOWN') { sendJson(res, 404, { error: { code: 404, message: 'project not found' } }); return; }
      sendJson(res, 200, volumesPayload());
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { code: 404, message: `no route for ${path}` } }));
  });

  return {
    requests,
    async start() {
      await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
      const address = server.address();
      return `http://${address.address}:${address.port}`;
    },
    async close() {
      await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())));
    },
  };
}

export const TEST_PROJECT_ID = PROJECT_ID;
export const TEST_SERVER_ID = SERVER_ID_1;
export const TEST_VOLUME_ID = VOLUME_ID_1;
export const TEST_FLAVOR_ID = FLAVOR_ID_1;
export const TEST_NETWORK_ID = NETWORK_ID_1;
export const RANDOM_HELPER = randomUUID;
