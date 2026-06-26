/* node:coverage disable */
import http from 'node:http';

export const DEFAULT_USER = 'elastic';
export const DEFAULT_PASSWORD = 'changeme';

const bufferBody = (req) => new Promise((resolve) => {
  if (req._body) { resolve(req._body); return; }
  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => { const raw = Buffer.concat(chunks).toString('utf8'); req._body = raw; resolve(raw); });
});

const parseJsonBody = (raw) => {
  if (!raw || !raw.trim()) return {};
  try { return JSON.parse(raw); } catch { return {}; }
};

const parseBasicAuth = (header) => {
  if (!header || typeof header !== 'string' || !header.startsWith('Basic ')) return null;
  try { const value = Buffer.from(header.slice(6).trim(), 'base64').toString('utf8'); const idx = value.indexOf(':'); return idx === -1 ? { user: value, password: '' } : { user: value.slice(0, idx), password: value.slice(idx + 1) }; } catch { return null; }
};

const sendJson = (res, status, payload) => { const body = JSON.stringify(payload); res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }); res.end(body); };

export function createMockServer({ expectedUser = DEFAULT_USER, expectedPassword = DEFAULT_PASSWORD } = {}) {
  const requests = [];
  const server = http.createServer(async (req, res) => {
    const rawBody = await bufferBody(req);
    const fullUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const path = fullUrl.pathname;
    const entry = {
      method: req.method, path,
      query: Object.fromEntries(fullUrl.searchParams),
      headers: req.headers,
      body: parseJsonBody(rawBody),
    };
    requests.push(entry);

    const auth = parseBasicAuth(req.headers.authorization);
    if (!auth) { sendJson(res, 401, { statusCode: 401, error: 'Unauthorized' }); return; }
    if (expectedUser && auth.user !== expectedUser) { sendJson(res, 403, { statusCode: 403, error: 'Forbidden' }); return; }
    if (expectedPassword && auth.password !== expectedPassword) { sendJson(res, 403, { statusCode: 403, error: 'Forbidden' }); return; }

    if (req.method === 'GET' && path === '/api/status') {
      sendJson(res, 200, {
        name: 'mock-kibana', uuid: 'kibana-uuid-001',
        version: { number: '7.10.0', build_hash: 'abc123', build_number: 1 },
        status: { overall: { state: 'green', level: 'available' }, statuses: [{ id: 'core:elasticsearch@7.10.0', state: 'green', message: 'Ready', level: 'available' }, { id: 'core:savedObjects@7.10.0', state: 'green', message: 'Ready', level: 'available' }] },
      });
      return;
    }

    if (req.method === 'GET' && path === '/api/spaces/space') {
      sendJson(res, 200, [{ id: 'default', name: 'Default', description: 'Default space', color: '#00bfb3', disabledFeatures: [], initials: 'D' }, { id: 'custom', name: 'Custom Space', description: 'Custom', color: '#36a2ef', disabledFeatures: [], initials: 'CS' }]);
      return;
    }

    const spaceMatch = path.match(/^\/api\/spaces\/space\/(.+)$/);
    if (spaceMatch) {
      const spaceId = decodeURIComponent(spaceMatch[1]);
      if (spaceId === 'missing') { sendJson(res, 404, { statusCode: 404, error: 'Not Found' }); return; }
      sendJson(res, 200, { id: spaceId, name: 'Space ' + spaceId, description: 'A space', color: '#00bfb3', disabledFeatures: [], initials: spaceId.charAt(0).toUpperCase() });
      return;
    }

    if (req.method === 'GET' && path === '/api/saved_objects/_find') {
      sendJson(res, 200, { total: 2, page: 1, per_page: 20, saved_objects: [{ id: 'obj-1', type: 'index-pattern', updated_at: '2026-01-01T00:00:00.000Z', version: 1, references: [] }, { id: 'obj-2', type: 'dashboard', updated_at: '2026-01-02T00:00:00.000Z', version: 2, references: [{ name: 'ref1', type: 'index-pattern', id: 'obj-1' }] }] });
      return;
    }

    if (req.method === 'POST' && path === '/api/saved_objects/_bulk_get') {
      const parsed = entry.body;
      const items = Array.isArray(parsed) ? parsed : (Array.isArray(parsed.objects) ? parsed.objects : []);
      const results = items.map((item) => ({ id: item?.id || 'unknown', type: item?.type || 'unknown', version: 1, updated_at: '2026-01-01T00:00:00.000Z', attributes: { title: 'Test' }, references: [], migrationVersion: {}, coreMigrationVersion: '7.10.0' }));
      sendJson(res, 200, { saved_objects: results });
      return;
    }

    if (req.method === 'GET' && path.match(/^\/api\/saved_objects\/[^/]+\/[^/]+$/)) {
      const parts = path.split('/');
      const type = decodeURIComponent(parts[3]);
      const id = decodeURIComponent(parts[4]);
      sendJson(res, 200, { id, type, version: 1, updated_at: '2026-01-01T00:00:00.000Z', attributes: { title: 'Test Object', description: 'Mock' }, references: [], migrationVersion: { dashboard: '7.10.0' }, coreMigrationVersion: '7.10.0' });
      return;
    }

    if (req.method === 'POST' && path === '/api/saved_objects/_export') {
      const ndjson = '{"id":"obj-1","type":"index-pattern","attributes":{"title":"test-*"}}\n{"exportedCount":1,"missingRefCount":0}\n';
      res.writeHead(200, { 'content-type': 'application/ndjson', 'content-length': Buffer.byteLength(ndjson) });
      res.end(ndjson);
      return;
    }

    res.writeHead(404);
    res.end(JSON.stringify({ statusCode: 404, error: 'Not Found' }));
  });

  return {
    requests,
    async start() { await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve)); const addr = server.address(); return `http://${addr.address}:${addr.port}`; },
    async close() { await new Promise((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))); },
  };
}