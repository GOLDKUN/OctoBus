// 360 EPP service test: parameter validation, API mapping, error mapping, auth flow

import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { fork } from 'child_process';
import http from 'http';

import { _test, rpcdef } from '../src/360-epp.js';

const mockUrl = (port) => `http://127.0.0.1:${port}`;

function startMock() {
  return new Promise((resolve, reject) => {
    const child = fork(new URL('mock_upstream.js', import.meta.url), [], {
      stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    });
    child.on('message', (msg) => {
      if (msg?.port) resolve({ child, port: msg.port });
    });
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code !== 0 && code !== null) reject(new Error(`mock exited with ${code}`));
    });
    setTimeout(() => reject(new Error('mock start timeout')), 10000);
  });
}

describe('360 EPP Service', () => {
  let mockServer;
  let mockPort;

  before(async () => {
    const mock = await startMock();
    mockServer = mock.child;
    mockPort = mock.port;
  });

  after(() => {
    if (mockServer) mockServer.kill();
  });

  function makeCtx(overrides = {}, reqOverrides = {}) {
    return {
      req: { ...reqOverrides },
      config: {},
      secret: {},
      bindings: {
        endpoint: mockUrl(mockPort),
        username: 'eppadmin',
        password: 'Chaitin123..',
        skipTlsVerify: true,
        ...overrides,
      },
      meta: { instance_id: 'test-instance' },
      limits: {},
    };
  }

  describe('rpcdef', () => {
    it('should return handlers for all methods', () => {
      const ctx = makeCtx();
      const methods = rpcdef(ctx);
      const keys = Object.keys(methods);
      assert.ok(keys.length >= 7, `expected >=7 methods, got ${keys.length}`);
      assert.ok(keys.every((k) => typeof methods[k] === 'function'));
    });

    it('should throw for missing endpoint', async () => {
      const ctx = makeCtx({ endpoint: '' });
      try {
        await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetDashboardInfo']();
        assert.fail('should have thrown');
      } catch (e) {
        assert.ok(e.message.includes('endpoint') || e.message.includes('baseUrl'));
      }
    });

    it('should throw for missing credentials', async () => {
      const ctx = makeCtx({ username: '', password: '' });
      try {
        await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetDashboardInfo']();
        assert.fail('should have thrown');
      } catch (e) {
        assert.ok(e.message.includes('username') || e.message.includes('password'));
      }
    });
  });

  describe('GetDashboardInfo', () => {
    it('should fetch dashboard info', async () => {
      const ctx = makeCtx();
      const result = await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetDashboardInfo']();
      assert.ok(result.data);
    });
  });

  describe('ListAlarms', () => {
    it('should fetch alarm list', async () => {
      const ctx = makeCtx();
      const result = await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/ListAlarms']();
      assert.ok(result.alarms);
      assert.ok(Array.isArray(result.alarms));
      assert.ok(result.total >= 0);
    });
  });

  describe('GetVirusStats', () => {
    it('should fetch virus stats', async () => {
      const ctx = makeCtx();
      const result = await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetVirusStats']();
      assert.ok(result.data);
    });
  });

  describe('GetLeakFixStats', () => {
    it('should fetch leakfix stats', async () => {
      const ctx = makeCtx();
      const result = await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetLeakFixStats']();
      assert.ok(result.data);
    });
  });

  describe('Login flow', () => {
    it('should login and cache session', async () => {
      const ctx = makeCtx();
      const result1 = await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetDashboardInfo']();
      assert.ok(result1.data);
      // Second call should use cached session
      const result2 = await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetVirusStats']();
      assert.ok(result2.data);
    });
  });

  describe('Error handling', () => {
    it('should handle login failure', async () => {
      const ctx = makeCtx({ password: 'wrong_password' });
      try {
        await rpcdef(ctx)['Qihoo360_EPP.Qihoo360_EPP/GetDashboardInfo']();
        assert.fail('should have thrown');
      } catch (e) {
        assert.ok(e.message.includes('login') || e.message.includes('鉴权') || e.message.includes('auth'));
      }
    });
  });
});
