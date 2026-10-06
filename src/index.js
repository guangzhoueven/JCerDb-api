import { hashPassword, verifyPassword, randomHex, getAuth, hasRole } from './auth.js';

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...headers },
  });

const badRequest = (msg) => json({ error: msg }, 400);
const unauthorized = (msg = '请先登录') => json({ error: msg }, 401);
const forbidden = (msg = '权限不足') => json({ error: msg }, 403);
const notFound = (msg = '不存在') => json({ error: msg }, 404);

const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };

const NAME_RE = /^[A-Za-z0-9_-]{1,64}$/;
const USER_RE = /^[\w\u4e00-\u9fa5-]{2,32}$/;
const KEY_RE = /^[A-Za-z0-9_\u4e00-\u9fa5.-]{1,64}$/;
const RESERVED = new Set(['me', 'data', 'admin', 'register', 'login', 'logout', 'users', 'audit', 'query', 'rename']);

async function readDoc(env, name) {
  const row = await env.DB.prepare('SELECT value, updated_at FROM data WHERE name = ?').bind(name).first();
  if (!row) return null;
  return new Response(row.value, {
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Updated-At': row.updated_at, ...CORS },
  });
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}

async function audit(env, uid, action, detail = '') {
  await env.DB.prepare('INSERT INTO audit (uid, action, detail) VALUES (?, ?, ?)').bind(uid ?? null, action, detail).run();
}

function requireRole(user, role, msg) {
  if (!user) return unauthorized();
  if (!hasRole(user, role)) return forbidden(msg);
  return null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS });

    if (!path.startsWith('/api/')) return env.ASSETS.fetch(request);

    try {
      const res = await route(request, env, url);
      if (res.headers.get('Content-Type')?.includes('application/json')) {
        const newRes = new Response(res.body, res);
        for (const [k, v] of Object.entries(CORS)) newRes.headers.set(k, v);
        return newRes;
      }
      return res;
    } catch (err) {
      return json({ error: '服务器错误: ' + err.message }, 500, CORS);
    }
  },
};

async function route(request, env, url) {
  const { pathname } = url;
  const method = request.method;
  const user = await getAuth(request, env);

  if (method === 'GET' && pathname === '/api/me') {
    return json(user ? { uid: user.uid, username: user.username, role: user.role } : null);
  }

  if (method === 'POST' && pathname === '/api/register') {
    const body = await readBody(request);
    const username = (body?.username || '').trim();
    const password = body?.password || '';
    if (!USER_RE.test(username)) return badRequest('用户名需 2-32 位中文、字母、数字或下划线');
    if (password.length < 6 || password.length > 72) return badRequest('密码长度需 6-72 位');
    const exists = await env.DB.prepare('SELECT 1 FROM users WHERE username = ?').bind(username).first();
    if (exists) return json({ error: '用户名已存在' }, 409);
    const count = await env.DB.prepare('SELECT COUNT(*) AS c FROM users').first();
    const isFirst = count.c === 0;
    const salt = randomHex(16);
    const passHash = await hashPassword(password, salt);
    const status = isFirst ? 'active' : 'pending';
    const role = isFirst ? 'super' : 'user';
    try {
      const res = await env.DB.prepare(
        'INSERT INTO users (username, pass_hash, salt, role, status) VALUES (?, ?, ?, ?, ?)'
      )
        .bind(username, passHash, salt, role, status)
        .run();
      await audit(env, res.meta.last_row_id, 'register', username);
    } catch {
      return json({ error: '用户名已存在' }, 409);
    }
    return json({ ok: true, status, isFirst }, 201);
  }

  if (method === 'POST' && pathname === '/api/login') {
    const body = await readBody(request);
    const username = (body?.username || '').trim();
    const password = body?.password || '';
    const row = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (!row || !(await verifyPassword(password, row.salt, row.pass_hash))) {
      return json({ error: '用户名或密码错误' }, 401);
    }
    if (row.status === 'pending') return json({ error: '账户尚未通过审核，请联系管理员' }, 403);
    if (row.status === 'banned') return json({ error: '账户已被封禁' }, 403);
    const token = randomHex(32);
    await env.DB.prepare('INSERT INTO sessions (token, uid, expires_at) VALUES (?, ?, ?)').bind(
      token,
      row.uid,
      Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 30
    ).run();
    await env.DB.prepare('UPDATE users SET last_login = datetime(\'now\') WHERE uid = ?').bind(row.uid).run();
    await audit(env, row.uid, 'login', username);
    return json({ ok: true, uid: row.uid, username: row.username, role: row.role }, 200, {
      'Set-Cookie': `session=${token}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax`,
    });
  }

  if (method === 'POST' && pathname === '/api/logout') {
    const token = (request.headers.get('Cookie') || '').match(/session=([^;]+)/)?.[1];
    if (token) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return json({ ok: true }, 200, { 'Set-Cookie': 'session=; HttpOnly; Path=/; Max-Age=0' });
  }

  if (method === 'GET' && pathname === '/api/data') {
    const rows = await env.DB.prepare(
      'SELECT name, updated_at, updated_by FROM data ORDER BY updated_at DESC'
    ).all();
    return json(rows.results, 200, CORS);
  }

  if (method === 'GET' && pathname.startsWith('/api/data/')) {
    const name = decodeURIComponent(pathname.slice('/api/data/'.length));
    if (!NAME_RE.test(name)) return badRequest('数据名称不合法');
    const row = await env.DB.prepare('SELECT value, updated_at FROM data WHERE name = ?').bind(name).first();
    if (!row) return notFound('数据不存在');
    return new Response(row.value, {
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-Updated-At': row.updated_at, ...CORS },
    });
  }

  if (method === 'PUT' && pathname.startsWith('/api/data/')) {
    const guard = requireRole(user, 'admin');
    if (guard) return guard;
    const name = decodeURIComponent(pathname.slice('/api/data/'.length));
    if (!NAME_RE.test(name)) return badRequest('数据名称不合法');
    const body = await request.text();
    try {
      JSON.parse(body);
    } catch {
      return badRequest('请求体必须是合法 JSON');
    }
    await env.DB.prepare(
      `INSERT INTO data (name, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
       ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`
    )
      .bind(name, body, user.uid)
      .run();
    await audit(env, user.uid, 'data:put', name);
    return json({ ok: true });
  }

  if (method === 'POST' && pathname === '/api/data/rename') {
    const guard = requireRole(user, 'admin');
    if (guard) return guard;
    const body = await readBody(request);
    const from = String(body?.from || '');
    const to = String(body?.to || '');
    if (!NAME_RE.test(from)) return badRequest('原名称不合法');
    if (!NAME_RE.test(to)) return badRequest('新名称不合法');
    if (RESERVED.has(to)) return badRequest('该名称为系统保留字');
    if (from === to) return json({ ok: true, renamed: false });
    const exists = await env.DB.prepare('SELECT 1 AS x FROM data WHERE name = ?').bind(to).first();
    if (exists) return badRequest('目标名称「' + to + '」已存在');
    const old = await env.DB.prepare('SELECT 1 AS x FROM data WHERE name = ?').bind(from).first();
    if (!old) return notFound('数据「' + from + '」不存在');
    await env.DB.prepare('UPDATE data SET name = ?, updated_by = ?, updated_at = datetime(\'now\') WHERE name = ?')
      .bind(to, user.uid, from)
      .run();
    await audit(env, user.uid, 'data:rename', from + ' -> ' + to);
    return json({ ok: true, renamed: true, name: to });
  }

  if (method === 'DELETE' && pathname.startsWith('/api/data/')) {
    const guard = requireRole(user, 'admin');
    if (guard) return guard;
    const name = decodeURIComponent(pathname.slice('/api/data/'.length));
    if (!NAME_RE.test(name)) return badRequest('数据名称不合法');
    await env.DB.prepare('DELETE FROM data WHERE name = ?').bind(name).run();
    await audit(env, user.uid, 'data:delete', name);
    return json({ ok: true });
  }

  if (method === 'GET' && pathname === '/api/admin/users') {
    const guard = requireRole(user, 'admin', '需要管理员权限');
    if (guard) return guard;
    const rows = await env.DB.prepare(
      'SELECT uid, username, role, status, created_at, last_login FROM users ORDER BY uid'
    ).all();
    return json(rows.results);
  }

  if (method === 'POST' && pathname === '/api/admin/approve') {
    const guard = requireRole(user, 'admin', '需要管理员权限');
    if (guard) return guard;
    const body = await readBody(request);
    const uid = Number(body?.uid);
    if (!Number.isInteger(uid)) return badRequest('uid 无效');
    await env.DB.prepare("UPDATE users SET status = 'active' WHERE uid = ? AND status = 'pending'").bind(uid).run();
    await audit(env, user.uid, 'user:approve', String(uid));
    return json({ ok: true });
  }

  if (method === 'POST' && pathname === '/api/admin/ban') {
    const guard = requireRole(user, 'super', '需要超级管理员权限');
    if (guard) return guard;
    const body = await readBody(request);
    const uid = Number(body?.uid);
    if (!Number.isInteger(uid)) return badRequest('uid 无效');
    if (uid === user.uid) return badRequest('不能封禁自己');
    if (uid === 1) return badRequest('不能封禁 uid=1 超级管理员');
    const target = await env.DB.prepare('SELECT status FROM users WHERE uid = ?').bind(uid).first();
    if (!target) return notFound('用户不存在');
    const next = target.status === 'banned' ? 'active' : 'banned';
    await env.DB.prepare('UPDATE users SET status = ? WHERE uid = ?').bind(next, uid).run();
    if (next === 'banned') await env.DB.prepare('DELETE FROM sessions WHERE uid = ?').bind(uid).run();
    await audit(env, user.uid, 'user:' + next, String(uid));
    return json({ ok: true, status: next });
  }

  if (method === 'POST' && pathname === '/api/admin/setrole') {
    const guard = requireRole(user, 'super', '需要超级管理员权限');
    if (guard) return guard;
    const body = await readBody(request);
    const uid = Number(body?.uid);
    const role = body?.role;
    if (!Number.isInteger(uid)) return badRequest('uid 无效');
    if (!['user', 'admin', 'super'].includes(role)) return badRequest('角色不合法');
    if (uid === user.uid) return badRequest('不能修改自己的角色');
    if (uid === 1 && role !== 'super') return badRequest('uid=1 必须保持超级管理员');
    const target = await env.DB.prepare('SELECT 1 FROM users WHERE uid = ?').bind(uid).first();
    if (!target) return notFound('用户不存在');
    await env.DB.prepare('UPDATE users SET role = ? WHERE uid = ?').bind(role, uid).run();
    await audit(env, user.uid, 'user:role', `${uid}=${role}`);
    return json({ ok: true });
  }

  if (method === 'POST' && pathname === '/api/admin/query') {
    const guard = requireRole(user, 'super', '需要超级管理员权限');
    if (guard) return guard;
    const body = await readBody(request);
    const sql = (body?.sql || '').trim();
    if (!sql) return badRequest('SQL 不能为空');
    if (sql.length > 10000) return badRequest('SQL 过长');
    try {
      const stmt = env.DB.prepare(sql);
      const isQuery = /^\s*(select|pragma|with|explain|values)/i.test(sql);
      if (isQuery) {
        const res = await stmt.all();
        await audit(env, user.uid, 'sql:query', sql.slice(0, 500));
        return json({ ok: true, columns: res.columns, rows: res.results });
      }
      const res = await stmt.run();
      await audit(env, user.uid, 'sql:exec', sql.slice(0, 500));
      return json({ ok: true, meta: res.meta, results: res.results ?? [] });
    } catch (err) {
      return json({ error: 'SQL 错误: ' + err.message }, 400);
    }
  }

  if (method === 'GET' && pathname === '/api/admin/audit') {
    const guard = requireRole(user, 'super', '需要超级管理员权限');
    if (guard) return guard;
    const rows = await env.DB.prepare(
      'SELECT a.id, a.uid, u.username, a.action, a.detail, a.created_at FROM audit a LEFT JOIN users u ON u.uid = a.uid ORDER BY a.id DESC LIMIT 200'
    ).all();
    return json(rows.results);
  }

  // 直连接口：GET /api/<表名>，全局共享，任何人均可读取
  if (method === 'GET') {
    const rest = pathname.slice('/api/'.length);
    if (rest && !rest.includes('/') && NAME_RE.test(rest) && !RESERVED.has(rest)) {
      const res = await readDoc(env, decodeURIComponent(rest));
      if (res) return res;
      return notFound('数据不存在');
    }
  }

  return notFound('接口不存在');
}
