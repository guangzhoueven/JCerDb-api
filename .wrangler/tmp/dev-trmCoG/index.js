var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/auth.js
var ITER = 1e4;
var enc = new TextEncoder();
function randomHex(bytes) {
  const arr = crypto.getRandomValues(new Uint8Array(bytes));
  return Array.from(arr, (b) => b.toString(16).padStart(2, "0")).join("");
}
__name(randomHex, "randomHex");
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
__name(hexToBytes, "hexToBytes");
function bytesToHex(buf) {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}
__name(bytesToHex, "bytesToHex");
async function hashPassword(password, saltHex) {
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: hexToBytes(saltHex), iterations: ITER, hash: "SHA-256" },
    key,
    256
  );
  return bytesToHex(bits);
}
__name(hashPassword, "hashPassword");
async function verifyPassword(password, saltHex, expectedHex) {
  const actual = await hashPassword(password, saltHex);
  if (actual.length !== expectedHex.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual.charCodeAt(i) ^ expectedHex.charCodeAt(i);
  return diff === 0;
}
__name(verifyPassword, "verifyPassword");
function parseCookies(request) {
  const header = request.headers.get("Cookie") || "";
  const jar = {};
  for (const part of header.split(";")) {
    const idx = part.indexOf("=");
    if (idx > 0) jar[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return jar;
}
__name(parseCookies, "parseCookies");
var ROLE_RANK = { user: 0, admin: 1, super: 2 };
async function getAuth(request, env) {
  const token = parseCookies(request).session;
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT u.uid, u.username, u.role, u.status
     FROM sessions s JOIN users u ON u.uid = s.uid
     WHERE s.token = ? AND s.expires_at > ?`
  ).bind(token, Math.floor(Date.now() / 1e3)).first();
  if (!row) return null;
  if (row.status !== "active") return null;
  return row;
}
__name(getAuth, "getAuth");
function hasRole(user, required) {
  if (!user) return false;
  return ROLE_RANK[user.role] >= ROLE_RANK[required];
}
__name(hasRole, "hasRole");

// src/index.js
var json = /* @__PURE__ */ __name((data, status = 200, headers = {}) => new Response(JSON.stringify(data), {
  status,
  headers: { "Content-Type": "application/json; charset=utf-8", ...headers }
}), "json");
var badRequest = /* @__PURE__ */ __name((msg) => json({ error: msg }, 400), "badRequest");
var unauthorized = /* @__PURE__ */ __name((msg = "\u8BF7\u5148\u767B\u5F55") => json({ error: msg }, 401), "unauthorized");
var forbidden = /* @__PURE__ */ __name((msg = "\u6743\u9650\u4E0D\u8DB3") => json({ error: msg }, 403), "forbidden");
var notFound = /* @__PURE__ */ __name((msg = "\u4E0D\u5B58\u5728") => json({ error: msg }, 404), "notFound");
var CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" };
var NAME_RE = /^[A-Za-z0-9_-]{1,64}$/;
var USER_RE = /^[\w\u4e00-\u9fa5-]{2,32}$/;
var RESERVED = /* @__PURE__ */ new Set(["me", "data", "admin", "register", "login", "logout", "users", "audit", "query", "rename"]);
async function readDoc(env, name) {
  const row = await env.DB.prepare("SELECT value, updated_at FROM data WHERE name = ?").bind(name).first();
  if (!row) return null;
  return new Response(row.value, {
    headers: { "Content-Type": "application/json; charset=utf-8", "X-Updated-At": row.updated_at, ...CORS }
  });
}
__name(readDoc, "readDoc");
async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}
__name(readBody, "readBody");
async function audit(env, uid, action, detail = "") {
  await env.DB.prepare("INSERT INTO audit (uid, action, detail) VALUES (?, ?, ?)").bind(uid ?? null, action, detail).run();
}
__name(audit, "audit");
function requireRole(user, role, msg) {
  if (!user) return unauthorized();
  if (!hasRole(user, role)) return forbidden(msg);
  return null;
}
__name(requireRole, "requireRole");
var src_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
    if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);
    try {
      const res = await route(request, env, url);
      if (res.headers.get("Content-Type")?.includes("application/json")) {
        const newRes = new Response(res.body, res);
        for (const [k, v] of Object.entries(CORS)) newRes.headers.set(k, v);
        return newRes;
      }
      return res;
    } catch (err) {
      return json({ error: "\u670D\u52A1\u5668\u9519\u8BEF: " + err.message }, 500, CORS);
    }
  }
};
async function route(request, env, url) {
  const { pathname } = url;
  const method = request.method;
  const user = await getAuth(request, env);
  if (method === "GET" && pathname === "/api/me") {
    return json(user ? { uid: user.uid, username: user.username, role: user.role } : null);
  }
  if (method === "POST" && pathname === "/api/register") {
    const body = await readBody(request);
    const username = (body?.username || "").trim();
    const password = body?.password || "";
    if (!USER_RE.test(username)) return badRequest("\u7528\u6237\u540D\u9700 2-32 \u4F4D\u4E2D\u6587\u3001\u5B57\u6BCD\u3001\u6570\u5B57\u6216\u4E0B\u5212\u7EBF");
    if (password.length < 6 || password.length > 72) return badRequest("\u5BC6\u7801\u957F\u5EA6\u9700 6-72 \u4F4D");
    const exists = await env.DB.prepare("SELECT 1 FROM users WHERE username = ?").bind(username).first();
    if (exists) return json({ error: "\u7528\u6237\u540D\u5DF2\u5B58\u5728" }, 409);
    const count = await env.DB.prepare("SELECT COUNT(*) AS c FROM users").first();
    const isFirst = count.c === 0;
    const salt = randomHex(16);
    const passHash = await hashPassword(password, salt);
    const status = isFirst ? "active" : "pending";
    const role = isFirst ? "super" : "user";
    try {
      const res = await env.DB.prepare(
        "INSERT INTO users (username, pass_hash, salt, role, status) VALUES (?, ?, ?, ?, ?)"
      ).bind(username, passHash, salt, role, status).run();
      await audit(env, res.meta.last_row_id, "register", username);
    } catch {
      return json({ error: "\u7528\u6237\u540D\u5DF2\u5B58\u5728" }, 409);
    }
    return json({ ok: true, status, isFirst }, 201);
  }
  if (method === "POST" && pathname === "/api/login") {
    const body = await readBody(request);
    const username = (body?.username || "").trim();
    const password = body?.password || "";
    const row = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
    if (!row || !await verifyPassword(password, row.salt, row.pass_hash)) {
      return json({ error: "\u7528\u6237\u540D\u6216\u5BC6\u7801\u9519\u8BEF" }, 401);
    }
    if (row.status === "pending") return json({ error: "\u8D26\u6237\u5C1A\u672A\u901A\u8FC7\u5BA1\u6838\uFF0C\u8BF7\u8054\u7CFB\u7BA1\u7406\u5458" }, 403);
    if (row.status === "banned") return json({ error: "\u8D26\u6237\u5DF2\u88AB\u5C01\u7981" }, 403);
    const token = randomHex(32);
    await env.DB.prepare("INSERT INTO sessions (token, uid, expires_at) VALUES (?, ?, ?)").bind(
      token,
      row.uid,
      Math.floor(Date.now() / 1e3) + 60 * 60 * 24 * 30
    ).run();
    await env.DB.prepare("UPDATE users SET last_login = datetime('now') WHERE uid = ?").bind(row.uid).run();
    await audit(env, row.uid, "login", username);
    return json({ ok: true, uid: row.uid, username: row.username, role: row.role }, 200, {
      "Set-Cookie": `session=${token}; HttpOnly; Path=/; Max-Age=2592000; SameSite=Lax`
    });
  }
  if (method === "POST" && pathname === "/api/logout") {
    const token = (request.headers.get("Cookie") || "").match(/session=([^;]+)/)?.[1];
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token = ?").bind(token).run();
    return json({ ok: true }, 200, { "Set-Cookie": "session=; HttpOnly; Path=/; Max-Age=0" });
  }
  if (method === "GET" && pathname === "/api/data") {
    const rows = await env.DB.prepare(
      "SELECT name, updated_at, updated_by FROM data ORDER BY updated_at DESC"
    ).all();
    return json(rows.results, 200, CORS);
  }
  if (method === "GET" && pathname.startsWith("/api/data/")) {
    const name = decodeURIComponent(pathname.slice("/api/data/".length));
    if (!NAME_RE.test(name)) return badRequest("\u6570\u636E\u540D\u79F0\u4E0D\u5408\u6CD5");
    const row = await env.DB.prepare("SELECT value, updated_at FROM data WHERE name = ?").bind(name).first();
    if (!row) return notFound("\u6570\u636E\u4E0D\u5B58\u5728");
    return new Response(row.value, {
      headers: { "Content-Type": "application/json; charset=utf-8", "X-Updated-At": row.updated_at, ...CORS }
    });
  }
  if (method === "PUT" && pathname.startsWith("/api/data/")) {
    const guard = requireRole(user, "admin");
    if (guard) return guard;
    const name = decodeURIComponent(pathname.slice("/api/data/".length));
    if (!NAME_RE.test(name)) return badRequest("\u6570\u636E\u540D\u79F0\u4E0D\u5408\u6CD5");
    const body = await request.text();
    try {
      JSON.parse(body);
    } catch {
      return badRequest("\u8BF7\u6C42\u4F53\u5FC5\u987B\u662F\u5408\u6CD5 JSON");
    }
    await env.DB.prepare(
      `INSERT INTO data (name, value, updated_by, updated_at) VALUES (?, ?, ?, datetime('now'))
       ON CONFLICT(name) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = datetime('now')`
    ).bind(name, body, user.uid).run();
    await audit(env, user.uid, "data:put", name);
    return json({ ok: true });
  }
  if (method === "POST" && pathname === "/api/data/rename") {
    const guard = requireRole(user, "admin");
    if (guard) return guard;
    const body = await readBody(request);
    const from = String(body?.from || "");
    const to = String(body?.to || "");
    if (!NAME_RE.test(from)) return badRequest("\u539F\u540D\u79F0\u4E0D\u5408\u6CD5");
    if (!NAME_RE.test(to)) return badRequest("\u65B0\u540D\u79F0\u4E0D\u5408\u6CD5");
    if (RESERVED.has(to)) return badRequest("\u8BE5\u540D\u79F0\u4E3A\u7CFB\u7EDF\u4FDD\u7559\u5B57");
    if (from === to) return json({ ok: true, renamed: false });
    const exists = await env.DB.prepare("SELECT 1 AS x FROM data WHERE name = ?").bind(to).first();
    if (exists) return badRequest("\u76EE\u6807\u540D\u79F0\u300C" + to + "\u300D\u5DF2\u5B58\u5728");
    const old = await env.DB.prepare("SELECT 1 AS x FROM data WHERE name = ?").bind(from).first();
    if (!old) return notFound("\u6570\u636E\u300C" + from + "\u300D\u4E0D\u5B58\u5728");
    await env.DB.prepare("UPDATE data SET name = ?, updated_by = ?, updated_at = datetime('now') WHERE name = ?").bind(to, user.uid, from).run();
    await audit(env, user.uid, "data:rename", from + " -> " + to);
    return json({ ok: true, renamed: true, name: to });
  }
  if (method === "DELETE" && pathname.startsWith("/api/data/")) {
    const guard = requireRole(user, "admin");
    if (guard) return guard;
    const name = decodeURIComponent(pathname.slice("/api/data/".length));
    if (!NAME_RE.test(name)) return badRequest("\u6570\u636E\u540D\u79F0\u4E0D\u5408\u6CD5");
    await env.DB.prepare("DELETE FROM data WHERE name = ?").bind(name).run();
    await audit(env, user.uid, "data:delete", name);
    return json({ ok: true });
  }
  if (method === "GET" && pathname === "/api/admin/users") {
    const guard = requireRole(user, "admin", "\u9700\u8981\u7BA1\u7406\u5458\u6743\u9650");
    if (guard) return guard;
    const rows = await env.DB.prepare(
      "SELECT uid, username, role, status, created_at, last_login FROM users ORDER BY uid"
    ).all();
    return json(rows.results);
  }
  if (method === "POST" && pathname === "/api/admin/approve") {
    const guard = requireRole(user, "admin", "\u9700\u8981\u7BA1\u7406\u5458\u6743\u9650");
    if (guard) return guard;
    const body = await readBody(request);
    const uid = Number(body?.uid);
    if (!Number.isInteger(uid)) return badRequest("uid \u65E0\u6548");
    await env.DB.prepare("UPDATE users SET status = 'active' WHERE uid = ? AND status = 'pending'").bind(uid).run();
    await audit(env, user.uid, "user:approve", String(uid));
    return json({ ok: true });
  }
  if (method === "POST" && pathname === "/api/admin/ban") {
    const guard = requireRole(user, "super", "\u9700\u8981\u8D85\u7EA7\u7BA1\u7406\u5458\u6743\u9650");
    if (guard) return guard;
    const body = await readBody(request);
    const uid = Number(body?.uid);
    if (!Number.isInteger(uid)) return badRequest("uid \u65E0\u6548");
    if (uid === user.uid) return badRequest("\u4E0D\u80FD\u5C01\u7981\u81EA\u5DF1");
    if (uid === 1) return badRequest("\u4E0D\u80FD\u5C01\u7981 uid=1 \u8D85\u7EA7\u7BA1\u7406\u5458");
    const target = await env.DB.prepare("SELECT status FROM users WHERE uid = ?").bind(uid).first();
    if (!target) return notFound("\u7528\u6237\u4E0D\u5B58\u5728");
    const next = target.status === "banned" ? "active" : "banned";
    await env.DB.prepare("UPDATE users SET status = ? WHERE uid = ?").bind(next, uid).run();
    if (next === "banned") await env.DB.prepare("DELETE FROM sessions WHERE uid = ?").bind(uid).run();
    await audit(env, user.uid, "user:" + next, String(uid));
    return json({ ok: true, status: next });
  }
  if (method === "POST" && pathname === "/api/admin/setrole") {
    const guard = requireRole(user, "super", "\u9700\u8981\u8D85\u7EA7\u7BA1\u7406\u5458\u6743\u9650");
    if (guard) return guard;
    const body = await readBody(request);
    const uid = Number(body?.uid);
    const role = body?.role;
    if (!Number.isInteger(uid)) return badRequest("uid \u65E0\u6548");
    if (!["user", "admin", "super"].includes(role)) return badRequest("\u89D2\u8272\u4E0D\u5408\u6CD5");
    if (uid === user.uid) return badRequest("\u4E0D\u80FD\u4FEE\u6539\u81EA\u5DF1\u7684\u89D2\u8272");
    if (uid === 1 && role !== "super") return badRequest("uid=1 \u5FC5\u987B\u4FDD\u6301\u8D85\u7EA7\u7BA1\u7406\u5458");
    const target = await env.DB.prepare("SELECT 1 FROM users WHERE uid = ?").bind(uid).first();
    if (!target) return notFound("\u7528\u6237\u4E0D\u5B58\u5728");
    await env.DB.prepare("UPDATE users SET role = ? WHERE uid = ?").bind(role, uid).run();
    await audit(env, user.uid, "user:role", `${uid}=${role}`);
    return json({ ok: true });
  }
  if (method === "POST" && pathname === "/api/admin/query") {
    const guard = requireRole(user, "super", "\u9700\u8981\u8D85\u7EA7\u7BA1\u7406\u5458\u6743\u9650");
    if (guard) return guard;
    const body = await readBody(request);
    const sql = (body?.sql || "").trim();
    if (!sql) return badRequest("SQL \u4E0D\u80FD\u4E3A\u7A7A");
    if (sql.length > 1e4) return badRequest("SQL \u8FC7\u957F");
    try {
      const stmt = env.DB.prepare(sql);
      const isQuery = /^\s*(select|pragma|with|explain|values)/i.test(sql);
      if (isQuery) {
        const res2 = await stmt.all();
        await audit(env, user.uid, "sql:query", sql.slice(0, 500));
        return json({ ok: true, columns: res2.columns, rows: res2.results });
      }
      const res = await stmt.run();
      await audit(env, user.uid, "sql:exec", sql.slice(0, 500));
      return json({ ok: true, meta: res.meta, results: res.results ?? [] });
    } catch (err) {
      return json({ error: "SQL \u9519\u8BEF: " + err.message }, 400);
    }
  }
  if (method === "GET" && pathname === "/api/admin/audit") {
    const guard = requireRole(user, "super", "\u9700\u8981\u8D85\u7EA7\u7BA1\u7406\u5458\u6743\u9650");
    if (guard) return guard;
    const rows = await env.DB.prepare(
      "SELECT a.id, a.uid, u.username, a.action, a.detail, a.created_at FROM audit a LEFT JOIN users u ON u.uid = a.uid ORDER BY a.id DESC LIMIT 200"
    ).all();
    return json(rows.results);
  }
  if (method === "GET") {
    const rest = pathname.slice("/api/".length);
    if (rest && !rest.includes("/") && NAME_RE.test(rest) && !RESERVED.has(rest)) {
      const res = await readDoc(env, decodeURIComponent(rest));
      if (res) return res;
      return notFound("\u6570\u636E\u4E0D\u5B58\u5728");
    }
  }
  return notFound("\u63A5\u53E3\u4E0D\u5B58\u5728");
}
__name(route, "route");

// node_modules/.pnpm/wrangler@4.147.0/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// node_modules/.pnpm/wrangler@4.147.0/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    const body = JSON.stringify(error);
    const headers = {
      "Content-Type": "application/json",
      "MF-Experimental-Error-Stack": "true"
    };
    const encoded = encodeURIComponent(body);
    if (encoded.length <= 8192) {
      headers["MF-Experimental-Error-Stack-Payload"] = encoded;
    }
    return new Response(body, { status: 500, headers });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-UAApkv/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = src_default;

// node_modules/.pnpm/wrangler@4.147.0/node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-UAApkv/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  scheduledTime;
  cron;
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=index.js.map
