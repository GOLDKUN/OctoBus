import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { GrpcError, grpcStatus } from '@chaitin-ai/octobus-sdk';

import { rpcdef } from '../src/zhizhangyi-mbs.js';

const ADD_USER = 'zhizhangyi.mbs.UserManagement/AddUser';
const CHECK_LOGIN_NAME = 'zhizhangyi.mbs.UserManagement/CheckLoginName';
const DEL_USERS = 'zhizhangyi.mbs.UserManagement/DelUsers';
const DETAIL_USER = 'zhizhangyi.mbs.UserManagement/DetailUser';
const FORCE_OFFLINE = 'zhizhangyi.mbs.UserManagement/ForceOffline';
const GET_USER_BY_PHONE = 'zhizhangyi.mbs.UserManagement/GetUserByPhone';
const GET_USERS = 'zhizhangyi.mbs.UserManagement/GetUsers';
const IMPORT_USER = 'zhizhangyi.mbs.UserManagement/ImportUser';
const STATE_USERS = 'zhizhangyi.mbs.UserManagement/StateUsers';
const UPD_USER = 'zhizhangyi.mbs.UserManagement/UpdUser';
const UPD_USER_PWD = 'zhizhangyi.mbs.UserManagement/UpdUserPwd';

const originalFetch = globalThis.fetch;

const buildCtx = (req) => ({
  config: { endpoint: 'https://mbs.example' },
  secret: { appkey: 'appkey', secretkey: 'secretkey', orgCode: 'org' },
  req,
});

const signCalc = (secret, ...params) => crypto
  .createHash('md5')
  .update(params.map((param) => (param === undefined || param === null ? '' : String(param))).join('') + secret, 'utf8')
  .digest('hex');

test.afterEach(() => {
  globalThis.fetch = originalFetch;
});

test('AddUser requires password before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({ user_name: 'User', login_name: 'user', dept_id: 'dept' }))[ADD_USER](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.equal(err.legacyCode, 'INVALID_ARGUMENT');
      assert.match(err.message, /password required/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('GetUsers preserves falsy state and is_mdm filters', async () => {
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0,"data":{"total":0,"userInfos":[]}}' };
  };

  await rpcdef(buildCtx({ condition: { dept_id: '1', state: 0, is_mdm: 0 } }))[GET_USERS]();

  assert.equal(captured.url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v1/getUsers');
  assert.deepEqual(JSON.parse(captured.init.body).condition, {
    deptId: '1',
    keyWord: '',
    state: 0,
    isMdm: 0,
  });
});

test('fetch uses AbortSignal and undici dispatcher for timeout and TLS skip', async () => {
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0,"data":{"total":0,"userInfos":[]}}' };
  };

  await rpcdef({
    config: { endpoint: 'https://mbs.example', skipTlsVerify: true },
    secret: { appkey: 'appkey', secretkey: 'secretkey', orgCode: 'org' },
    limits: { timeoutMs: 1234 },
    req: { condition: { dept_id: '1' } },
  })[GET_USERS]();

  assert.equal(captured.url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v1/getUsers');
  assert.ok(captured.init.signal instanceof AbortSignal);
  assert.equal(captured.init.signal.aborted, false);
  assert.ok(captured.init.dispatcher);
  assert.equal(Object.hasOwn(captured.init, 'timeoutMs'), false);
  assert.equal(Object.hasOwn(captured.init, 'insecureSkipVerify'), false);
  assert.equal(Object.hasOwn(captured.init, 'tlsInsecureSkipVerify'), false);
});

test('GetUsers requires dept_id before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({ condition: { state: 1 } }))[GET_USERS](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.equal(err.legacyCode, 'INVALID_ARGUMENT');
      assert.match(err.message, /dept_id required/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('HTTP errors expose only a bounded upstream body summary', async () => {
  const body = 'x'.repeat(260);
  globalThis.fetch = async () => ({ ok: false, status: 500, text: async () => body });

  await assert.rejects(
    () => rpcdef(buildCtx({ condition: { dept_id: '1' } }))[GET_USERS](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.UNAVAILABLE);
      assert.match(err.message, /http 500: x{200}\.\.\./);
      assert.equal(err.message.includes('x'.repeat(220)), false);
      return true;
    },
  );
});

test('AddUser forwards caller-provided 3DES-encrypted password value', async () => {
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0,"data":{"created":true}}' };
  };

  const result = await rpcdef(buildCtx({ user_name: 'User', login_name: 'user', dept_id: 'dept', password: '3des-ciphertext' }))[ADD_USER]();

  assert.equal(captured.url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v1/addUser');
  assert.equal(JSON.parse(captured.init.body).password, '3des-ciphertext');
  assert.equal(result.data.structValue.fields.created.boolValue, true);
});

test('AddUser omits empty numeric fields instead of sending zero values', async () => {
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0,"data":{}}' };
  };

  await rpcdef(buildCtx({ user_name: 'User', login_name: 'user', dept_id: 'dept', password: '3des-ciphertext', is_mdm: '', state: '', weight: '' }))[ADD_USER]();

  const body = JSON.parse(captured.init.body);
  assert.equal(Object.hasOwn(body, 'isMdm'), false);
  assert.equal(Object.hasOwn(body, 'state'), false);
  assert.equal(Object.hasOwn(body, 'weight'), false);
});

test('UpdUser requires dept_id before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({ user_id: 'user-1', user_name: 'User' }))[UPD_USER](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.equal(err.legacyCode, 'INVALID_ARGUMENT');
      assert.match(err.message, /dept_id required/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('UpdUser omits missing loginName instead of sending empty string', async () => {
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0,"data":{}}' };
  };

  await rpcdef(buildCtx({ user_id: 'user-1', user_name: 'User', dept_id: 'dept' }))[UPD_USER]();

  const body = JSON.parse(captured.init.body);
  assert.equal(Object.hasOwn(body, 'loginName'), false);
  assert.equal(body.sign, signCalc('secretkey', 'appkey', 'org', 'user-1', 'User', '', 'dept'));
});

test('UpdUser omits empty numeric fields instead of sending zero values', async () => {
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0,"data":{}}' };
  };

  await rpcdef(buildCtx({ user_id: 'user-1', user_name: 'User', dept_id: 'dept', is_mdm: '', weight: '' }))[UPD_USER]();

  const body = JSON.parse(captured.init.body);
  assert.equal(Object.hasOwn(body, 'isMdm'), false);
  assert.equal(Object.hasOwn(body, 'weight'), false);
});

test('StateUsers requires explicit state before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({ type: 0, user_ids: ['user-1'] }))[STATE_USERS](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.equal(err.legacyCode, 'INVALID_ARGUMENT');
      assert.match(err.message, /state required/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('DelUsers requires user_ids for type zero before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({ type: 0, user_ids: [] }))[DEL_USERS](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.equal(err.legacyCode, 'INVALID_ARGUMENT');
      assert.match(err.message, /user_ids required for type=0/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('StateUsers requires user_ids for type zero before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({ type: 0, state: 1, user_ids: [] }))[STATE_USERS](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.equal(err.legacyCode, 'INVALID_ARGUMENT');
      assert.match(err.message, /user_ids required for type=0/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('DelUsers treats string type zero as userIds mode', async () => {
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await rpcdef(buildCtx({ type: '0', user_ids: ['user-1'] }))[DEL_USERS]();

  assert.equal(captured.url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v1/delUsers');
  const body = JSON.parse(captured.init.body);
  assert.deepEqual(body.userIds, ['user-1']);
  assert.equal(body.type, 0);
  assert.equal(body.sign, signCalc('secretkey', 'appkey', 'org', 'user-1', 0));
  assert.equal(Object.hasOwn(body, 'condition'), false);
});

test('DelUsers rejects invalid type before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({ type: 2, user_ids: ['user-1'] }))[DEL_USERS](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.equal(err.legacyCode, 'INVALID_ARGUMENT');
      assert.match(err.message, /type must be 0 or 1/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('DelUsers requires condition for type one before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({ type: 1 }))[DEL_USERS](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.equal(err.legacyCode, 'INVALID_ARGUMENT');
      assert.match(err.message, /condition required for type=1/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('StateUsers rejects invalid type before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({ type: 'bad', state: 1, user_ids: ['user-1'] }))[STATE_USERS](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.equal(err.legacyCode, 'INVALID_ARGUMENT');
      assert.match(err.message, /type must be 0 or 1/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('StateUsers requires condition for type one before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({ type: 1, state: 1, condition: {} }))[STATE_USERS](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.equal(err.legacyCode, 'INVALID_ARGUMENT');
      assert.match(err.message, /condition required for type=1/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('DelUsers condition mode preserves falsy condition filters', async () => {
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0,"data":null}' };
  };

  const result = await rpcdef(buildCtx({ type: 1, condition: { key_word: 'kw', status: 0, is_mdm: 0, dept_id: 'dept' } }))[DEL_USERS]();

  assert.equal(captured.url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v1/delUsers');
  const body = JSON.parse(captured.init.body);
  assert.deepEqual(body.condition, {
    keyWord: 'kw',
    status: 0,
    isMdm: 0,
    deptId: 'dept',
  });
  assert.equal(body.sign, signCalc('secretkey', 'appkey', 'org', '', 1, 'kw', 0, 0, 'dept'));
  assert.deepEqual(result.data, { nullValue: 'NULL_VALUE' });
});

test('StateUsers condition mode preserves falsy condition filters', async () => {
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0,"data":{"updated":2}}' };
  };

  const result = await rpcdef(buildCtx({ type: 1, state: '0', condition: { key_word: 'kw', status: 0, is_mdm: 0, dept_id: 'dept' } }))[STATE_USERS]();

  assert.equal(captured.url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v1/stateUsers');
  const body = JSON.parse(captured.init.body);
  assert.equal(body.state, '0');
  assert.deepEqual(body.condition, {
    keyWord: 'kw',
    status: 0,
    isMdm: 0,
    deptId: 'dept',
  });
  assert.equal(body.sign, signCalc('secretkey', 'appkey', 'org', '', 1, '0', 'kw', 0, 0, 'dept'));
  assert.equal(result.data.structValue.fields.updated.numberValue, 2);
});

test('UpdUserPwd rejects invalid version before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({ version: '../v1', user_id: 'user-1', password: '3des-ciphertext' }))[UPD_USER_PWD](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.equal(err.legacyCode, 'INVALID_ARGUMENT');
      assert.match(err.message, /version must be v1 or v2/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('UpdUserPwd v1 requires user_id and password before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({ version: 'v1', password: '3des-ciphertext' }))[UPD_USER_PWD](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.match(err.message, /user_id required for v1/);
      return true;
    },
  );
  await assert.rejects(
    () => rpcdef(buildCtx({ version: 'v1', user_id: 'user-1' }))[UPD_USER_PWD](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.match(err.message, /password required as 3DES-encrypted value for v1/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('UpdUserPwd v1 posts to v1 path with encrypted password', async () => {
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0,"data":{}}' };
  };

  const result = await rpcdef(buildCtx({ version: 'v1', user_id: 'user-1', password: '3des-ciphertext' }))[UPD_USER_PWD]();

  assert.equal(captured.url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v1/updUserPwd');
  assert.equal(JSON.parse(captured.init.body).userId, 'user-1');
  assert.equal(JSON.parse(captured.init.body).password, '3des-ciphertext');
  assert.deepEqual(result.data, { structValue: { fields: {} } });
});

test('UpdUserPwd v2 requires login_name and new_pwd before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({ version: 'v2', new_pwd: 'new-ciphertext' }))[UPD_USER_PWD](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.match(err.message, /login_name required for v2/);
      return true;
    },
  );
  await assert.rejects(
    () => rpcdef(buildCtx({ version: 'v2', login_name: 'user' }))[UPD_USER_PWD](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.match(err.message, /new_pwd required as 3DES-encrypted value for v2/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('UpdUserPwd v2 posts to v2 path and forwards oldPwd', async () => {
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0,"data":{"changed":true}}' };
  };

  const result = await rpcdef(buildCtx({ version: 'v2', login_name: 'user', old_pwd: 'old-ciphertext', new_pwd: 'new-ciphertext' }))[UPD_USER_PWD]();

  assert.equal(captured.url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v2/updUserPwd');
  assert.equal(JSON.parse(captured.init.body).loginName, 'user');
  assert.equal(JSON.parse(captured.init.body).oldPwd, 'old-ciphertext');
  assert.equal(JSON.parse(captured.init.body).newPwd, 'new-ciphertext');
  assert.equal(result.data.structValue.fields.changed.boolValue, true);
});

test('StateUsers treats string type zero as userIds mode', async () => {
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await rpcdef(buildCtx({ type: '0', state: '1', user_ids: ['user-1'] }))[STATE_USERS]();

  assert.equal(captured.url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v1/stateUsers');
  const body = JSON.parse(captured.init.body);
  assert.deepEqual(body.userIds, ['user-1']);
  assert.equal(body.type, 0);
  assert.equal(body.state, '1');
  assert.equal(body.sign, signCalc('secretkey', 'appkey', 'org', 'user-1', 0, '1', ''));
  assert.equal(Object.hasOwn(body, 'condition'), false);
});

test('DetailUser requires user_id before calling upstream', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({}))[DETAIL_USER](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.match(err.message, /user_id required/);
      return true;
    },
  );

  assert.equal(called, false);
});

test('DetailUser maps detail response and returns null data when upstream data is empty', async () => {
  const responses = [
    { code: 0, data: { userId: 'user-1', userName: 'User', loginName: 'login', deptId: 'dept', deptName: 'Dept', phoneNumber: '13800000000', job: 'dev', employeeNumber: 'E001', address: 'addr', mobile: '13900000000', email: 'u@example.com', organization: 'org-name', isMdm: 0, state: 1, weight: 2, iconFileId: 'icon', attrs: [{ attrKey: 'role', attrValue: 'admin' }] } },
    { code: 0, data: null },
  ];
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return { ok: true, status: 200, text: async () => JSON.stringify(responses.shift()) };
  };

  const detail = await rpcdef(buildCtx({ user_id: 'user-1' }))[DETAIL_USER]();
  const empty = await rpcdef(buildCtx({ user_id: 'user-2' }))[DETAIL_USER]();

  assert.equal(calls[0].url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v1/detailUser');
  assert.equal(JSON.parse(calls[0].init.body).userId, 'user-1');
  assert.equal(JSON.parse(calls[0].init.body).sign, signCalc('secretkey', 'appkey', 'org', 'user-1'));
  assert.deepEqual(detail.data, {
    user_id: 'user-1',
    user_name: 'User',
    login_name: 'login',
    dept_id: 'dept',
    dept_name: 'Dept',
    phone_number: '13800000000',
    job: 'dev',
    employee_number: 'E001',
    address: 'addr',
    mobile: '13900000000',
    email: 'u@example.com',
    organization: 'org-name',
    is_mdm: 0,
    state: 1,
    weight: 2,
    icon_file_id: 'icon',
    attrs: [{ attr_key: 'role', attr_value: 'admin' }],
  });
  assert.equal(empty.data, null);
});

test('CheckLoginName requires login_name before calling upstream and signs request', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({}))[CHECK_LOGIN_NAME](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.match(err.message, /login_name required/);
      return true;
    },
  );
  assert.equal(called, false);

  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0,"data":{"available":true}}' };
  };

  const result = await rpcdef(buildCtx({ login_name: 'user' }))[CHECK_LOGIN_NAME]();
  const body = JSON.parse(captured.init.body);
  assert.equal(captured.url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v1/checkLoginName');
  assert.equal(body.loginName, 'user');
  assert.equal(body.sign, signCalc('secretkey', 'appkey', 'org', 'user'));
  assert.equal(result.data.structValue.fields.available.boolValue, true);
});

test('GetUserByPhone requires phone and maps array or null data', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({}))[GET_USER_BY_PHONE](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.match(err.message, /phone required/);
      return true;
    },
  );
  assert.equal(called, false);

  const responses = [
    { code: 0, data: [{ userId: 'user-1', userName: 'User', loginName: 'login', phoneNumber: '13800000000', email: 'u@example.com' }] },
    { code: 0, data: null },
  ];
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return { ok: true, status: 200, text: async () => JSON.stringify(responses.shift()) };
  };

  const result = await rpcdef(buildCtx({ phone: '13800000000' }))[GET_USER_BY_PHONE]();
  const empty = await rpcdef(buildCtx({ phone: '13900000000' }))[GET_USER_BY_PHONE]();
  const body = JSON.parse(calls[0].init.body);
  assert.equal(calls[0].url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v1/getUserByPhone');
  assert.equal(body.phone, '13800000000');
  assert.equal(body.sign, signCalc('secretkey', 'appkey', 'org', '13800000000'));
  assert.deepEqual(result.data, [{ user_id: 'user-1', user_name: 'User', login_name: 'login', phone_number: '13800000000', email: 'u@example.com' }]);
  assert.deepEqual(empty.data, []);
});

test('ForceOffline requires user_id before calling upstream and signs request', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({}))[FORCE_OFFLINE](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.match(err.message, /user_id required/);
      return true;
    },
  );
  assert.equal(called, false);

  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0,"data":{"offline":true}}' };
  };

  const result = await rpcdef(buildCtx({ user_id: 'user-1' }))[FORCE_OFFLINE]();
  const body = JSON.parse(captured.init.body);
  assert.equal(captured.url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v1/forceOffline');
  assert.equal(body.userId, 'user-1');
  assert.equal(body.sign, signCalc('secretkey', 'appkey', 'org', 'user-1'));
  assert.equal(result.data.structValue.fields.offline.boolValue, true);
});

test('ImportUser requires file_id and posts default lang with signature', async () => {
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    return { ok: true, status: 200, text: async () => '{"code":0}' };
  };

  await assert.rejects(
    () => rpcdef(buildCtx({}))[IMPORT_USER](),
    (err) => {
      assert.ok(err instanceof GrpcError);
      assert.equal(err.code, grpcStatus.INVALID_ARGUMENT);
      assert.match(err.message, /file_id required/);
      return true;
    },
  );
  assert.equal(called, false);

  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url, init };
    return { ok: true, status: 200, text: async () => '{"code":0,"data":{"imported":3}}' };
  };

  const result = await rpcdef(buildCtx({ file_id: 'file-1' }))[IMPORT_USER]();
  const body = JSON.parse(captured.init.body);
  assert.equal(captured.url, 'https://mbs.example/uusafe/mos/thirdaccess/rest/opt/v1/importUser');
  assert.equal(body.lang, 0);
  assert.equal(body.fileId, 'file-1');
  assert.equal(body.sign, signCalc('secretkey', 'appkey', 'org', 0, 'file-1'));
  assert.equal(result.data.structValue.fields.imported.numberValue, 3);
});
