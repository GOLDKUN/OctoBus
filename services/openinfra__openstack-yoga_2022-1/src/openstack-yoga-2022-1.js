import { GrpcError, grpcStatus } from '@chaitin-ai/octobus-sdk';
import { Agent } from 'undici';

export const METHOD_LIST_PROJECTS_PATH = '/OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListProjects';
export const METHOD_LIST_SERVERS_PATH = '/OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListServers';
export const METHOD_GET_SERVER_PATH = '/OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/GetServer';
export const METHOD_LIST_NETWORKS_PATH = '/OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListNetworks';
export const METHOD_LIST_VOLUMES_PATH = '/OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListVolumes';
export const METHOD_LIST_FLAVORS_PATH = '/OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListFlavors';

export const METHOD_LIST_PROJECTS_FULL = 'OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListProjects';
export const METHOD_LIST_SERVERS_FULL = 'OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListServers';
export const METHOD_GET_SERVER_FULL = 'OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/GetServer';
export const METHOD_LIST_NETWORKS_FULL = 'OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListNetworks';
export const METHOD_LIST_VOLUMES_FULL = 'OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListVolumes';
export const METHOD_LIST_FLAVORS_FULL = 'OpenStack_Yoga_2022_1.OpenStack_Yoga_2022_1/ListFlavors';

export const DEFAULT_TIMEOUT_MS = 15000;
export const MAX_TIMEOUT_MS = 120000;
export const DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
export const DEFAULT_DOMAIN_NAME = 'Default';

let insecureDispatcher;

const grpcCodeFor = (code) => ({
  FAILED_PRECONDITION: grpcStatus.FAILED_PRECONDITION,
  INVALID_ARGUMENT: grpcStatus.INVALID_ARGUMENT,
  NOT_FOUND: grpcStatus.NOT_FOUND,
  PERMISSION_DENIED: grpcStatus.PERMISSION_DENIED,
  UNAVAILABLE: grpcStatus.UNAVAILABLE,
  UNKNOWN: grpcStatus.UNKNOWN,
})[code] ?? grpcStatus.UNKNOWN;

const engineError = (code, message) => {
  const err = new GrpcError(grpcCodeFor(code), `${code}: ${message}`);
  err.legacyCode = code;
  return err;
};

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj ?? {}, key);

const firstDefined = (...values) => values.find((value) => value !== undefined && value !== null);

const unwrapScalar = (value) => {
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'object' && value !== null && hasOwn(value, 'value')) return unwrapScalar(value.value);
  return value;
};

const toTrimmedString = (value) => {
  const raw = unwrapScalar(value);
  if (raw === undefined || raw === null) return '';
  return String(raw).trim();
};

const toJsonString = (value) => {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value;
  try { return JSON.stringify(value); } catch { return ''; }
};

const normalizeAuthUrl = (value, allowInsecure) => {
  const raw = toTrimmedString(value);
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    if (parsed.username || parsed.password) return '';
    const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
    const loopback = ['127.0.0.1', '::1', 'localhost'].includes(hostname);
    if (parsed.protocol === 'https:' || (parsed.protocol === 'http:' && (allowInsecure || loopback))) {
      parsed.pathname = parsed.pathname.replace(/\/+$/, '').replace(/\/v3$/i, '') || '/';
      return parsed.toString().replace(/\/+$/, '');
    }
  } catch { /* invalid URL */ }
  return '';
};

const mergedBindings = (ctx = {}) => ({
  ...(ctx.config ?? {}),
  ...(ctx.secret ?? {}),
  ...(ctx.bindings ?? {}),
});

const resolveCallContext = (ctx = {}) => ({
  ...ctx,
  bindings: mergedBindings(ctx),
  limits: ctx.limits ?? {},
  meta: ctx.meta ?? {},
  req: ctx.req ?? ctx.request ?? {},
});

const resolveAuthUrl = (bindings = {}) => {
  const allowInsecure = Boolean(bindings.allowInsecureHttp ?? bindings.allow_insecure_http);
  return normalizeAuthUrl(
    firstDefined(bindings.auth_url, bindings.authUrl, bindings.identityEndpoint),
    allowInsecure,
  );
};

const resolveRegion = (bindings = {}) => toTrimmedString(firstDefined(bindings.region));
const resolveProjectName = (bindings = {}) => {
  if (!hasOwn(bindings, 'project_name') && hasOwn(bindings, 'projectName')) {
    throw engineError('INVALID_ARGUMENT', 'projectName is not supported; use project_name instead');
  }
  return toTrimmedString(bindings.project_name);
};
const resolveProjectDomainName = (bindings = {}) => toTrimmedString(firstDefined(bindings.project_domain_name, bindings.projectDomainName));
const resolveUserDomainName = (bindings = {}) => toTrimmedString(firstDefined(bindings.user_domain_name, bindings.userDomainName));
const resolveUsername = (bindings = {}) => toTrimmedString(firstDefined(bindings.username));
const resolvePassword = (bindings = {}) => {
  const raw = unwrapScalar(firstDefined(bindings.password));
  return raw === undefined || raw === null ? '' : String(raw);
};

const resolveTimeoutMs = (ctx = {}) => {
  const raw = Number(firstDefined(ctx.limits?.timeoutMs, ctx.bindings?.timeoutMs, DEFAULT_TIMEOUT_MS));
  return Number.isFinite(raw) && raw > 0 ? Math.min(Math.floor(raw), MAX_TIMEOUT_MS) : DEFAULT_TIMEOUT_MS;
};

const resolveMaxResponseBytes = (ctx = {}) => {
  const raw = Number(firstDefined(ctx.limits?.maxResponseBytes, ctx.bindings?.maxResponseBytes, DEFAULT_MAX_RESPONSE_BYTES));
  return Number.isFinite(raw) && raw >= 1024 ? Math.min(Math.floor(raw), 50 * 1024 * 1024) : DEFAULT_MAX_RESPONSE_BYTES;
};

const buildTlsOptions = (bindings = {}, url = '') => {
  const enabled = Boolean(bindings.skipTlsVerify || bindings.tlsInsecureSkipVerify || bindings.insecureSkipVerify);
  if (!enabled || !String(url).startsWith('https:')) return {};
  insecureDispatcher ??= new Agent({ connect: { rejectUnauthorized: false } });
  return { dispatcher: insecureDispatcher };
};

const requireAuthUrl = (ctx = {}) => {
  const authUrl = resolveAuthUrl(ctx.bindings || {});
  if (!authUrl) throw engineError('INVALID_ARGUMENT', 'auth_url is required in bindings (https://, or http:// with allowInsecureHttp=true)');
  return authUrl;
};
const requireUsername = (ctx = {}) => {
  const username = resolveUsername(ctx.bindings || {});
  if (!username) throw engineError('INVALID_ARGUMENT', 'username is required in secrets');
  return username;
};
const requirePassword = (ctx = {}) => {
  const password = resolvePassword(ctx.bindings || {});
  if (!password) throw engineError('INVALID_ARGUMENT', 'password is required in secrets');
  return password;
};
const requireServerId = (req = {}) => {
  const id = toTrimmedString(firstDefined(req.server_id, req.serverId));
  if (!id) throw engineError('INVALID_ARGUMENT', 'server_id is required');
  return id;
};

const buildLogPrefix = (ctx = {}, action) => {
  const meta = ctx.meta || {};
  const trace = [];
  if (meta.instance_id || meta.instanceId) trace.push(`inst=${meta.instance_id || meta.instanceId}`);
  if (meta.request_id || meta.requestId) trace.push(`req=${meta.request_id || meta.requestId}`);
  return `[OpenStack_Yoga_2022_1][${action}]${trace.length ? `[${trace.join(' ')}]` : ''}`;
};

const logFlow = (ctx, action, details) => {
  const prefix = buildLogPrefix(ctx, action);
  try { console.log(prefix, JSON.stringify(details)); }
  catch { console.log(prefix, details); }
};

const buildAuthRequestBody = (rawCtx) => {
  const callCtx = resolveCallContext(rawCtx);
  const bindings = callCtx.bindings || {};
  const projectName = resolveProjectName(bindings);
  const userDomain = resolveUserDomainName(bindings) || DEFAULT_DOMAIN_NAME;
  const projectDomain = resolveProjectDomainName(bindings) || DEFAULT_DOMAIN_NAME;
  const body = {
    auth: {
      identity: {
        methods: ['password'],
        password: {
          user: {
            name: requireUsername(callCtx),
            password: requirePassword(callCtx),
          },
        },
      },
    },
  };
  if (userDomain) body.auth.identity.password.user.domain = { name: userDomain };
  if (projectName) {
    body.auth.scope = { project: { name: projectName } };
    if (projectDomain) body.auth.scope.project.domain = { name: projectDomain };
  }
  return body;
};

const fetchHttp = async (url, init = {}, ctx = {}) => {
  const bindings = ctx.bindings || {};
  const timeoutMs = resolveTimeoutMs(ctx);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let res;
  try {
    res = await fetch(url, { signal: controller.signal, redirect: 'error', ...buildTlsOptions(bindings, url), ...init });
  } catch (err) {
    const errMsg = err?.name === 'AbortError' ? `timeout after ${timeoutMs}ms` : 'upstream unavailable';
    throw engineError('UNAVAILABLE', `upstream fetch failed: ${errMsg}`);
  }
  try {
  const httpStatus = Number(res?.status || 0);
  const maximum = resolveMaxResponseBytes(ctx);
  const declared = Number(res?.headers?.get?.('content-length') || 0);
  if (Number.isFinite(declared) && declared > maximum) throw engineError('UNAVAILABLE', 'upstream response is too large');
  let text = '';
  try {
    if (typeof res?.body?.getReader === 'function') {
      const reader = res.body.getReader();
      const chunks = [];
      let received = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > maximum) {
          await reader.cancel();
          throw engineError('UNAVAILABLE', 'upstream response is too large');
        }
        chunks.push(Buffer.from(value));
      }
      text = Buffer.concat(chunks).toString('utf8');
    } else {
      text = await res.text();
      if (Buffer.byteLength(text) > maximum) throw engineError('UNAVAILABLE', 'upstream response is too large');
    }
  } catch (err) {
    if (err instanceof GrpcError) throw err;
    throw engineError('UNAVAILABLE', `upstream response read failed: ${err?.message || 'read error'}`);
  }
  return { res, httpStatus, rawBody: String(text ?? '') };
  } finally {
    clearTimeout(timer);
  }
};

const mapHttpStatusToCode = (httpStatus) => {
  if (httpStatus === 401 || httpStatus === 403) return 'PERMISSION_DENIED';
  if (httpStatus === 404) return 'NOT_FOUND';
  if (httpStatus >= 400 && httpStatus < 500) return 'FAILED_PRECONDITION';
  return 'UNAVAILABLE';
};

const assertUpstreamStatus = (httpStatus, rawBody, label) => {
  if (httpStatus >= 200 && httpStatus < 300) return;
  const code = mapHttpStatusToCode(httpStatus);
  throw engineError(code, `${label} upstream HTTP ${httpStatus}`);
};

const obtainToken = async (callCtxOrRaw) => {
  const callCtx = resolveCallContext(callCtxOrRaw);
  const authUrl = requireAuthUrl(callCtx);
  const url = `${authUrl}/v3/auth/tokens`;
  const body = JSON.stringify(buildAuthRequestBody(callCtx));
  logFlow(callCtx, 'auth:request', { url, project: resolveProjectName(callCtx.bindings || {}) });
  const { res, httpStatus, rawBody } = await fetchHttp(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body,
  }, callCtx);
  if (httpStatus !== 201 && httpStatus !== 200) {
    const code = mapHttpStatusToCode(httpStatus);
    logFlow(callCtx, 'auth:error', { httpStatus });
    throw engineError(code, `keystone auth HTTP ${httpStatus}`);
  }
  let parsedBody = {};
  try { parsedBody = rawBody ? JSON.parse(rawBody) : {}; } catch { /* handled below */ }
  const bodyToken = typeof parsedBody?.token === 'string' ? parsedBody.token : '';
  const subjectToken = res?.headers?.get?.('x-subject-token') || res?.headers?.get?.('X-Subject-Token') || bodyToken;
  let projectId = '';
  let userId = '';
  let expiresAt = '';
  let catalog = [];
  try {
    const json = parsedBody;
    projectId = toTrimmedString(json?.token?.project?.id);
    userId = toTrimmedString(json?.token?.user?.id);
    expiresAt = toTrimmedString(json?.token?.expires_at);
    catalog = Array.isArray(json?.token?.catalog) ? json.token.catalog : [];
    if (!projectId) {
      const tokenProject = json?.token?.project || {};
      projectId = toTrimmedString(tokenProject.id || tokenProject.name);
    }
    if (!projectId && bodyToken) projectId = resolveProjectName(callCtx.bindings || {});
  } catch {
    // body is not JSON; project id will remain empty
  }
  if (!subjectToken) throw engineError('UNKNOWN', 'keystone auth response missing X-Subject-Token header');
  if (!projectId) throw engineError('FAILED_PRECONDITION', 'keystone auth response missing token.project.id (token has no scoped project)');
  logFlow(callCtx, 'auth:ok', { httpStatus, projectId, userId, expiresAt });
  return { token: subjectToken, projectId, userId, expiresAt, authUrl, catalog };
};

const endpointFor = (tokenCtx, type, region = '') => {
  const service = tokenCtx.catalog.find((item) => item?.type === type || item?.name === type);
  const endpoints = Array.isArray(service?.endpoints) ? service.endpoints : [];
  const publicEndpoints = endpoints.filter((item) => item?.interface === 'public');
  const endpoint = region
    ? publicEndpoints.find((item) => item?.region === region || item?.region_id === region)
    : publicEndpoints[0];
  if (region && service && !endpoint) {
    throw engineError('FAILED_PRECONDITION', `no public ${type} endpoint for region ${region}`);
  }
  const encodedProject = encodeURIComponent(tokenCtx.projectId);
  const raw = toTrimmedString(endpoint?.url)
    .replace(/\{project_id\}/g, encodedProject)
    .replace(/%\((?:project_id|tenant_id)\)s/g, encodedProject);
  if (!raw) return tokenCtx.authUrl;
  try {
    const parsed = new URL(raw);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username || parsed.password) return tokenCtx.authUrl;
    return parsed.toString().replace(/\/+$/, '');
  } catch { return tokenCtx.authUrl; }
};

const serviceUrl = (tokenCtx, type, legacyPath, catalogPath, region = '', projectId = tokenCtx.projectId) => {
  const endpoint = endpointFor({ ...tokenCtx, projectId }, type, region);
  return endpoint === tokenCtx.authUrl ? `${endpoint}${legacyPath}` : `${endpoint}${catalogPath}`;
};

const buildUpstreamHeaders = (token) => ({ 'X-Auth-Token': token, Accept: 'application/json' });

const substitutePath = (template, params = {}) => {
  let out = String(template);
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue;
    out = out.split(`{${key}}`).join(encodeURIComponent(String(value)));
  }
  return out;
};

const buildQueryString = (params = {}) => {
  const entries = Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '');
  if (!entries.length) return '';
  return '?' + entries.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join('&');
};

const performAuthenticatedGet = async (callCtx, pathTemplate, params = {}, label = 'api', cachedTokenCtx = null) => {
  const tokenCtx = cachedTokenCtx || await obtainToken(callCtx);
  const authUrl = tokenCtx.authUrl;
  const path = substitutePath(pathTemplate, params);
  const url = `${authUrl}${path}`;
  const headers = buildUpstreamHeaders(tokenCtx.token);
  logFlow(callCtx, `${label}:request`, { url, projectId: tokenCtx.projectId });
  const { httpStatus, rawBody } = await fetchHttp(url, { method: 'GET', headers }, callCtx);
  assertUpstreamStatus(httpStatus, rawBody, label);
  let json = {};
  try { json = rawBody ? JSON.parse(rawBody) : {}; }
  catch { throw engineError('UNKNOWN', `${label} response is not valid JSON: ${rawBody.slice(0, 128)}`); }
  return { httpStatus, rawBody, json, projectId: tokenCtx.projectId };
};

const toInt64 = (value) => {
  const raw = unwrapScalar(value);
  if (raw === undefined || raw === null || raw === '') return 0;
  const num = Number(raw);
  return Number.isFinite(num) ? Math.trunc(num) : 0;
};

const toBool = (value, fallback = false) => {
  const raw = unwrapScalar(value);
  if (raw === undefined || raw === null) return fallback;
  if (typeof raw === 'boolean') return raw;
  if (typeof raw === 'number') return raw !== 0;
  if (typeof raw === 'string') {
    const normalized = raw.trim().toLowerCase();
    if (['true', '1', 'yes', 'on'].includes(normalized)) return true;
    if (['false', '0', 'no', 'off', ''].includes(normalized)) return false;
  }
  return fallback;
};

const mapAddresses = (value) => {
  if (!value || typeof value !== 'object') return {};
  const out = {};
  for (const [netKey, entries] of Object.entries(value)) {
    if (!Array.isArray(entries)) continue;
    const parts = [];
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object') continue;
      const addr = toTrimmedString(entry.addr || entry.address);
      if (addr) parts.push(addr);
    }
    if (parts.length) out[String(netKey)] = parts.join(',');
  }
  return out;
};

const pickProjectIdOverride = (req = {}) => toTrimmedString(firstDefined(req.project_id, req.projectId));

const mapProjects = (json) => {
  const list = Array.isArray(json?.projects) ? json.projects : [];
  return list.map((p) => ({
    id: toTrimmedString(p?.id),
    name: toTrimmedString(p?.name),
    domain_id: toTrimmedString(p?.domain_id ?? p?.domainId ?? p?.domain?.id),
    enabled: toBool(p?.enabled, true),
    description: toTrimmedString(p?.description),
    parent_id: toTrimmedString(p?.parent_id ?? p?.parentId),
    is_domain: toBool(p?.is_domain, false),
    tags_json: toJsonString(Array.isArray(p?.tags) ? p.tags : []),
    links_json: toJsonString(p?.links ?? {}),
  }));
};

const mapServerCommon = (s) => {
  if (!s || typeof s !== 'object') return null;
  return {
    id: toTrimmedString(s?.id),
    name: toTrimmedString(s?.name),
    status: toTrimmedString(s?.status),
    tenant_id: toTrimmedString(s?.tenant_id ?? s?.tenantId),
    user_id: toTrimmedString(s?.user_id ?? s?.userId),
    created: toTrimmedString(s?.created),
    updated: toTrimmedString(s?.updated),
    host_id: toTrimmedString(s?.hostId ?? s?.host_id),
    flavor_id: toTrimmedString(s?.flavor?.id ?? s?.flavorId ?? s?.flavor_id),
    image_id: toTrimmedString(s?.image?.id ?? s?.imageId ?? s?.image_id),
    addresses: mapAddresses(s?.addresses),
    access_ip_v4: toTrimmedString(s?.accessIPv4 ?? s?.access_ip_v4),
    access_ip_v6: toTrimmedString(s?.accessIPv6 ?? s?.access_ip_v6),
    power_state: toTrimmedString(s?.['OS-EXT-STS:power_state'] ?? s?.power_state ?? s?.powerState),
    vm_state: toTrimmedString(s?.['OS-EXT-STS:vm_state'] ?? s?.vm_state ?? s?.vmState),
    task_state: toTrimmedString(s?.['OS-EXT-STS:task_state'] ?? s?.task_state ?? s?.taskState),

    os_dcf_disk_config: toTrimmedString(s?.['OS-DCF:diskConfig']),
    description: toTrimmedString(s?.description),
    key_name: toTrimmedString(s?.key_name ?? s?.keyName),
    locked: toBool(s?.locked, false),
    locked_reason: toTrimmedString(s?.locked_reason ?? s?.lockedReason),
    host_status: toTrimmedString(s?.host_status ?? s?.hostStatus),
    progress: toInt64(s?.progress),
    config_drive: toTrimmedString(s?.config_drive ?? s?.configDrive),
    tags: toJsonString(Array.isArray(s?.tags) ? s.tags : []),
    os_ext_az_availability_zone: toTrimmedString(s?.['OS-EXT-AZ:availability_zone']),

    os_ext_srv_attr_host: toTrimmedString(s?.['OS-EXT-SRV-ATTR:host']),
    os_ext_srv_attr_hostname: toTrimmedString(s?.['OS-EXT-SRV-ATTR:hostname']),
    os_ext_srv_attr_hypervisor_hostname: toTrimmedString(s?.['OS-EXT-SRV-ATTR:hypervisor_hostname']),
    os_ext_srv_attr_instance_name: toTrimmedString(s?.['OS-EXT-SRV-ATTR:instance_name']),
    os_ext_srv_attr_kernel_id: toTrimmedString(s?.['OS-EXT-SRV-ATTR:kernel_id']),
    os_ext_srv_attr_launch_index: toInt64(s?.['OS-EXT-SRV-ATTR:launch_index']),
    os_ext_srv_attr_ramdisk_id: toTrimmedString(s?.['OS-EXT-SRV-ATTR:ramdisk_id']),
    os_ext_srv_attr_reservation_id: toTrimmedString(s?.['OS-EXT-SRV-ATTR:reservation_id']),
    os_ext_srv_attr_root_device_name: toTrimmedString(s?.['OS-EXT-SRV-ATTR:root_device_name']),
    os_ext_srv_attr_user_data: toTrimmedString(s?.['OS-EXT-SRV-ATTR:user_data']),

    os_srv_usg_launched_at: toTrimmedString(s?.['OS-SRV-USG:launched_at']),
    os_srv_usg_terminated_at: toTrimmedString(s?.['OS-SRV-USG:terminated_at']),

    os_extended_volumes_volumes_attached_json: toJsonString(s?.['os-extended-volumes:volumes_attached'] ?? []),
    security_groups_json: toJsonString(Array.isArray(s?.security_groups) ? s.security_groups : []),
    trusted_image_certificates_json: toJsonString(s?.trusted_image_certificates ?? []),
    links_json: toJsonString(s?.links ?? []),
  };
};

const mapServers = (json) => {
  const list = Array.isArray(json?.servers) ? json.servers : [];
  return list.map(mapServerCommon).filter(Boolean);
};

const emptyServer = () => ({
  id: '', name: '', status: '', tenant_id: '', user_id: '', created: '', updated: '',
  host_id: '', flavor_id: '', image_id: '', addresses: {}, access_ip_v4: '', access_ip_v6: '',
  power_state: '', vm_state: '', task_state: '',
  os_dcf_disk_config: '', description: '', key_name: '', locked: false, locked_reason: '',
  host_status: '', progress: 0, config_drive: '', tags: '[]',
  os_ext_az_availability_zone: '',
  os_ext_srv_attr_host: '', os_ext_srv_attr_hostname: '', os_ext_srv_attr_hypervisor_hostname: '',
  os_ext_srv_attr_instance_name: '', os_ext_srv_attr_kernel_id: '', os_ext_srv_attr_launch_index: 0,
  os_ext_srv_attr_ramdisk_id: '', os_ext_srv_attr_reservation_id: '',
  os_ext_srv_attr_root_device_name: '', os_ext_srv_attr_user_data: '',
  os_srv_usg_launched_at: '', os_srv_usg_terminated_at: '',
  os_extended_volumes_volumes_attached_json: '[]', security_groups_json: '[]',
  trusted_image_certificates_json: '[]', links_json: '[]',
});

const mapServer = (json) => mapServerCommon(json?.server) || emptyServer();

const mapNetworks = (json) => {
  const list = Array.isArray(json?.networks) ? json.networks : [];
  return list.map((n) => ({
    id: toTrimmedString(n?.id),
    name: toTrimmedString(n?.name),
    status: toTrimmedString(n?.status),
    admin_state_up: toBool(n?.admin_state_up ?? n?.adminStateUp, false),
    shared: toBool(n?.shared, false),
    external: toBool(n?.['router:external'] ?? n?.external, false),
    tenant_id: toTrimmedString(n?.tenant_id ?? n?.tenantId),
    project_id: toTrimmedString(n?.project_id ?? n?.projectId),
    network_type: toTrimmedString(n?.['provider:network_type'] ?? n?.network_type ?? n?.providerNetworkType),
    segmentation_id: toTrimmedString(n?.['provider:segmentation_id'] ?? n?.segmentation_id ?? n?.providerSegmentationId),

    dns_domain: toTrimmedString(n?.dns_domain),
    mtu: toInt64(n?.mtu),
    qos_policy_id: toTrimmedString(n?.qos_policy_id),
    revision_number: toInt64(n?.revision_number),
    created_at: toTrimmedString(n?.created_at),
    updated_at: toTrimmedString(n?.updated_at),
    port_security_enabled: toBool(n?.port_security_enabled, true),
    is_default: toBool(n?.is_default, false),

    ipv4_address_scope: toTrimmedString(n?.ipv4_address_scope),
    ipv6_address_scope: toTrimmedString(n?.ipv6_address_scope),
    availability_zone_hints_json: toJsonString(Array.isArray(n?.availability_zone_hints) ? n.availability_zone_hints : []),
    availability_zones_json: toJsonString(Array.isArray(n?.availability_zones) ? n.availability_zones : []),
    subnets_json: toJsonString(Array.isArray(n?.subnets) ? n.subnets : []),
    vlan_transparent: toBool(n?.vlan_transparent, false),
    qinq: toBool(n?.qinq, false),
    l2_adjacency: toBool(n?.l2_adjacency, false),
  }));
};

const mapVolumes = (json) => {
  const list = Array.isArray(json?.volumes) ? json.volumes : [];
  return list.map((v) => ({
    id: toTrimmedString(v?.id),
    name: toTrimmedString(v?.name),
    status: toTrimmedString(v?.status),
    size: toInt64(v?.size),
    volume_type: toTrimmedString(v?.volume_type ?? v?.volumeType),
    created_at: toTrimmedString(v?.created_at ?? v?.createdAt),
    updated_at: toTrimmedString(v?.updated_at ?? v?.updatedAt),
    tenant_id: toTrimmedString(v?.tenant_id ?? v?.tenantId),
    project_id: toTrimmedString(v?.project_id ?? v?.projectId),
    availability_zone: toTrimmedString(v?.availability_zone ?? v?.availabilityZone),
    bootable: toTrimmedString(v?.bootable),

    description: toTrimmedString(v?.description),
    encrypted: toBool(v?.encrypted, false),
    multiattach: toBool(v?.multiattach, false),
    consistencygroup_id: toTrimmedString(v?.consistencygroup_id),
    migration_status: toTrimmedString(v?.migration_status),
    replication_status: toTrimmedString(v?.replication_status),
    snapshot_id: toTrimmedString(v?.snapshot_id),
    source_volid: toTrimmedString(v?.source_volid),
    os_vol_host_attr_host: toTrimmedString(v?.['os-vol-host-attr:host']),
    os_vol_mig_status_attr_migstat: toTrimmedString(v?.['os-vol-mig-status-attr:migstat']),
    os_vol_mig_status_attr_name_id: toTrimmedString(v?.['os-vol-mig-status-attr:name_id']),
    provider_id: toTrimmedString(v?.provider_id),
    group_id: toTrimmedString(v?.group_id),
    service_uuid: toTrimmedString(v?.service_uuid),
    cluster_name: toTrimmedString(v?.cluster_name),
    consumes_quota: toTrimmedString(v?.consumes_quota),
    volume_type_id: toTrimmedString(v?.volume_type_id),
    attachments_json: toJsonString(Array.isArray(v?.attachments) ? v.attachments : []),
    metadata_json: toJsonString(v?.metadata ?? {}),
    links_json: toJsonString(Array.isArray(v?.links) ? v.links : []),
    shared_targets_json: toJsonString(v?.shared_targets ?? []),
  }));
};

const mapFlavors = (json) => {
  const list = Array.isArray(json?.flavors) ? json.flavors : [];
  return list.map((f) => ({
    id: toTrimmedString(f?.id),
    name: toTrimmedString(f?.name),
    vcpus: toInt64(f?.vcpus),
    ram: toInt64(f?.ram),
    disk: toInt64(f?.disk),
    swap: toInt64(f?.swap),
    rxtx_factor: toInt64(f?.rxtx_factor ?? f?.rxtxFactor),
    is_public: toBool(f?.['os-flavor-access:is_public'] ?? f?.is_public ?? f?.public, true),
    disabled: toBool(f?.['OS-FLV-DISABLED:disabled'] ?? f?.disabled, false),
    description: toTrimmedString(f?.description),
    ephemeral: toInt64(f?.['OS-FLV-EXT-DATA:ephemeral'] ?? f?.ephemeral),
    extra_specs_json: toJsonString(f?.extra_specs ?? {}),
    links_json: toJsonString(Array.isArray(f?.links) ? f.links : []),
  }));
};

const handleListProjects = async (req = {}, ctx = {}) => {
  const callCtx = resolveCallContext(ctx);
  requireAuthUrl(callCtx);
  requireUsername(callCtx);
  requirePassword(callCtx);
  const tokenCtx = await obtainToken(callCtx);
  const url = `${tokenCtx.authUrl}/v3/projects?limit=1000`;
  const headers = buildUpstreamHeaders(tokenCtx.token);
  logFlow(callCtx, 'ListProjects:request', { url });
  const { httpStatus, rawBody } = await fetchHttp(url, { method: 'GET', headers }, callCtx);
  assertUpstreamStatus(httpStatus, rawBody, 'ListProjects');
  let projectsJson = {};
  try { projectsJson = rawBody ? JSON.parse(rawBody) : {}; }
  catch { throw engineError('UNKNOWN', `ListProjects response is not valid JSON: ${rawBody.slice(0, 128)}`); }
  return { projects: mapProjects(projectsJson) };
};

const handleListServers = async (req = {}, ctx = {}) => {
  const callCtx = resolveCallContext(ctx);
  const projectIdOverride = pickProjectIdOverride(req);
  const tokenCtx = await obtainToken(callCtx);
  const projectId = projectIdOverride || tokenCtx.projectId;
  const params = { limit: 1000 };
  const statusFilter = toTrimmedString(req.status);
  const nameFilter = toTrimmedString(req.name);
  if (statusFilter) params.status = statusFilter;
  if (nameFilter) params.name = nameFilter;
  const queryString = Object.entries(params).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  const suffix = queryString ? `?${queryString}` : '';
  const url = serviceUrl(tokenCtx, 'compute', `/v2/${encodeURIComponent(projectId)}/servers${suffix}`, `/servers${suffix}`, resolveRegion(callCtx.bindings), projectId);
  const headers = buildUpstreamHeaders(tokenCtx.token);
  logFlow(callCtx, 'ListServers:request', { url, projectId });
  const { httpStatus, rawBody } = await fetchHttp(url, { method: 'GET', headers }, callCtx);
  assertUpstreamStatus(httpStatus, rawBody, 'ListServers');
  let serversJson = {};
  try { serversJson = rawBody ? JSON.parse(rawBody) : {}; }
  catch { throw engineError('UNKNOWN', `ListServers response is not valid JSON: ${rawBody.slice(0, 128)}`); }
  return { servers: mapServers(serversJson) };
};

const handleGetServer = async (req = {}, ctx = {}) => {
  const callCtx = resolveCallContext(ctx);
  const serverId = requireServerId(req);
  const projectIdOverride = pickProjectIdOverride(req);
  const tokenCtx = await obtainToken(callCtx);
  const projectId = projectIdOverride || tokenCtx.projectId;
  const url = serviceUrl(tokenCtx, 'compute', `/v2/${encodeURIComponent(projectId)}/servers/${encodeURIComponent(serverId)}`, `/servers/${encodeURIComponent(serverId)}`, resolveRegion(callCtx.bindings), projectId);
  const headers = buildUpstreamHeaders(tokenCtx.token);
  logFlow(callCtx, 'GetServer:request', { url, serverId, projectId });
  const { httpStatus, rawBody } = await fetchHttp(url, { method: 'GET', headers }, callCtx);
  assertUpstreamStatus(httpStatus, rawBody, 'GetServer');
  let serverJson = {};
  try { serverJson = rawBody ? JSON.parse(rawBody) : {}; }
  catch { throw engineError('UNKNOWN', `GetServer response is not valid JSON: ${rawBody.slice(0, 128)}`); }
  return { server: mapServer(serverJson) };
};

const handleListNetworks = async (req = {}, ctx = {}) => {
  const callCtx = resolveCallContext(ctx);
  const projectIdOverride = pickProjectIdOverride(req);
  const tokenCtx = await obtainToken(callCtx);
  const projectId = projectIdOverride || tokenCtx.projectId;
  const pathParams = { project_id: projectId };
  const queryParams = { project_id: projectId, limit: 1000 };
  const statusFilter = toTrimmedString(req.status);
  const nameFilter = toTrimmedString(req.name);
  if (statusFilter) queryParams.status = statusFilter;
  if (nameFilter) queryParams.name = nameFilter;
  const queryString = buildQueryString(queryParams);
  const path = substitutePath('/v2.0/networks', pathParams);
  const url = serviceUrl(tokenCtx, 'network', `${path}${queryString}`, `/v2.0/networks${queryString}`, resolveRegion(callCtx.bindings), projectId);
  const headers = buildUpstreamHeaders(tokenCtx.token);
  logFlow(callCtx, 'ListNetworks:request', { url, projectId });
  const { httpStatus, rawBody } = await fetchHttp(url, { method: 'GET', headers }, callCtx);
  assertUpstreamStatus(httpStatus, rawBody, 'ListNetworks');
  let json = {};
  try { json = rawBody ? JSON.parse(rawBody) : {}; }
  catch { throw engineError('UNKNOWN', `ListNetworks response is not valid JSON: ${rawBody.slice(0, 128)}`); }
  return { networks: mapNetworks(json) };
};

const handleListVolumes = async (req = {}, ctx = {}) => {
  const callCtx = resolveCallContext(ctx);
  const projectIdOverride = pickProjectIdOverride(req);
  const tokenCtx = await obtainToken(callCtx);
  const projectId = projectIdOverride || tokenCtx.projectId;
  const pathParams = { project_id: projectId };
  const queryParams = { limit: 1000 };
  const statusFilter = toTrimmedString(req.status);
  const nameFilter = toTrimmedString(req.name);
  if (statusFilter) queryParams.status = statusFilter;
  if (nameFilter) queryParams.name = nameFilter;
  const queryString = buildQueryString(queryParams);
  const path = substitutePath('/v3/{project_id}/volumes', pathParams);
  const url = serviceUrl(tokenCtx, 'volumev3', `${path}${queryString}`, `/volumes${queryString}`, resolveRegion(callCtx.bindings), projectId);
  const headers = buildUpstreamHeaders(tokenCtx.token);
  logFlow(callCtx, 'ListVolumes:request', { url, projectId });
  const { httpStatus, rawBody } = await fetchHttp(url, { method: 'GET', headers }, callCtx);
  assertUpstreamStatus(httpStatus, rawBody, 'ListVolumes');
  let json = {};
  try { json = rawBody ? JSON.parse(rawBody) : {}; }
  catch { throw engineError('UNKNOWN', `ListVolumes response is not valid JSON: ${rawBody.slice(0, 128)}`); }
  return { volumes: mapVolumes(json) };
};

const handleListFlavors = async (req = {}, ctx = {}) => {
  const callCtx = resolveCallContext(ctx);
  const projectIdOverride = pickProjectIdOverride(req);
  const tokenCtx = await obtainToken(callCtx);
  const projectId = projectIdOverride || tokenCtx.projectId;
  const url = serviceUrl(tokenCtx, 'compute', `/v2/${encodeURIComponent(projectId)}/flavors?limit=1000`, '/flavors?limit=1000', resolveRegion(callCtx.bindings), projectId);
  const headers = buildUpstreamHeaders(tokenCtx.token);
  const { httpStatus, rawBody } = await fetchHttp(url, { method: 'GET', headers }, callCtx);
  assertUpstreamStatus(httpStatus, rawBody, 'ListFlavors');
  let json;
  try { json = rawBody ? JSON.parse(rawBody) : {}; } catch { throw engineError('UNKNOWN', 'ListFlavors response is not valid JSON'); }
  return { flavors: mapFlavors(json) };
};

export function rpcdef(ctx = {}) {
  const callCtx = resolveCallContext(ctx);
  return {
    [METHOD_LIST_PROJECTS_PATH]: async (req) => handleListProjects(req ?? callCtx.req ?? {}, callCtx),
    [METHOD_LIST_SERVERS_PATH]: async (req) => handleListServers(req ?? callCtx.req ?? {}, callCtx),
    [METHOD_GET_SERVER_PATH]: async (req) => handleGetServer(req ?? callCtx.req ?? {}, callCtx),
    [METHOD_LIST_NETWORKS_PATH]: async (req) => handleListNetworks(req ?? callCtx.req ?? {}, callCtx),
    [METHOD_LIST_VOLUMES_PATH]: async (req) => handleListVolumes(req ?? callCtx.req ?? {}, callCtx),
    [METHOD_LIST_FLAVORS_PATH]: async (req) => handleListFlavors(req ?? callCtx.req ?? {}, callCtx),
  };
}

const requestFrom = (ctx = {}) => ctx.request ?? ctx.req ?? {};
const serviceHandler = (handler) => function dispatch(ctxOrRequest) {
  const context = ctxOrRequest ?? {};
  const legacyContext = arguments[1];
  return legacyContext
    ? handler(context, legacyContext)
    : handler(requestFrom(context), context);
};

export const handlers = {
  [METHOD_LIST_PROJECTS_FULL]: serviceHandler(handleListProjects),
  [METHOD_LIST_SERVERS_FULL]: serviceHandler(handleListServers),
  [METHOD_GET_SERVER_FULL]: serviceHandler(handleGetServer),
  [METHOD_LIST_NETWORKS_FULL]: serviceHandler(handleListNetworks),
  [METHOD_LIST_VOLUMES_FULL]: serviceHandler(handleListVolumes),
  [METHOD_LIST_FLAVORS_FULL]: serviceHandler(handleListFlavors),
};

export const _test = {
  assertUpstreamStatus,
  buildAuthRequestBody,
  buildLogPrefix,
  buildTlsOptions,
  buildUpstreamHeaders,
  emptyServer,
  engineError,
  fetchHttp,
  firstDefined,
  getServerId: requireServerId,
  grpcCodeFor,
  handleGetServer,
  handleListFlavors,
  handleListNetworks,
  handleListProjects,
  handleListServers,
  handleListVolumes,
  hasOwn,
  logFlow,
  mapAddresses,
  mapFlavors,
  mapHttpStatusToCode,
  mapNetworks,
  mapProjects,
  mapServer,
  mapServerCommon,
  mapServers,
  mapVolumes,
  mergedBindings,
  normalizeAuthUrl,
  obtainToken,
  pickProjectIdOverride,
  performAuthenticatedGet,
  resolveAuthUrl,
  resolveCallContext,
  resolvePassword,
  resolveProjectDomainName,
  resolveProjectName,
  resolveRegion,
  resolveTimeoutMs,
  resolveMaxResponseBytes,
  resolveUserDomainName,
  resolveUsername,
  substitutePath,
  endpointFor,
  serviceUrl,
  toBool,
  toInt64,
  toJsonString,
  toTrimmedString,
  unwrapScalar,
};
