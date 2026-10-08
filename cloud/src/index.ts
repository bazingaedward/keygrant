// keygrant cloud API — phase 1: GitHub sign-in, sessions, devices.
// Design: docs/design/cloud-mvp.md. The server never sees secret values;
// in this phase it holds identities, hashed tokens and device public keys.

export interface Env {
  DB: D1Database;
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  GITHUB_API: string;
}

const ACCESS_TTL = 15 * 60;
const REFRESH_TTL = 30 * 24 * 60 * 60;
const MAX_BODY_BYTES = 64 * 1024;

class HttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

const now = () => Math.floor(Date.now() / 1000);

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  const body = await request.text();
  if (body.length > MAX_BODY_BYTES) throw new HttpError(413, "too_large", "request body too large");
  try {
    const data = JSON.parse(body);
    if (data && typeof data === "object" && !Array.isArray(data)) return data;
  } catch {}
  throw new HttpError(400, "bad_json", "body must be a JSON object");
}

function requireString(body: Record<string, unknown>, key: string, max = 512): string {
  const v = body[key];
  if (typeof v !== "string" || v.length === 0 || v.length > max) {
    throw new HttpError(400, "bad_request", `${key} must be a non-empty string`);
  }
  return v;
}

function randomToken(prefix: string): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const b64 = btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return prefix + b64;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------- GitHub ----------

// Confirms the token was issued to *our* OAuth App (not just any valid
// GitHub token), returns the GitHub user, then revokes the token: we only
// need it once, and never accept it again.
async function verifyGithubToken(env: Env, token: string): Promise<{ id: number; login: string }> {
  const url = `${env.GITHUB_API}/applications/${env.GITHUB_CLIENT_ID}/token`;
  const headers = {
    authorization: "Basic " + btoa(`${env.GITHUB_CLIENT_ID}:${env.GITHUB_CLIENT_SECRET}`),
    accept: "application/vnd.github+json",
    "content-type": "application/json",
    "user-agent": "keygrant-cloud",
  };
  const body = JSON.stringify({ access_token: token });
  const res = await fetch(url, { method: "POST", headers, body });
  if (res.status === 404 || res.status === 422) {
    throw new HttpError(401, "invalid_github_token", "GitHub token is not valid for this app");
  }
  if (!res.ok) throw new HttpError(502, "github_unavailable", `GitHub returned ${res.status}`);
  const data = (await res.json()) as { user?: { id?: unknown; login?: unknown } };
  const id = data.user?.id;
  const login = data.user?.login;
  if (typeof id !== "number" || typeof login !== "string") {
    throw new HttpError(502, "github_unexpected", "unexpected GitHub response");
  }
  await fetch(url, { method: "DELETE", headers, body }).catch(() => undefined);
  return { id, login };
}

// ---------- sessions & tokens ----------

async function issueTokens(env: Env, sessionId: string) {
  const access = randomToken("kga_");
  const refresh = randomToken("kgr_");
  const t = now();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO access_tokens (hash, session_id, expires_at) VALUES (?, ?, ?)")
      .bind(await sha256Hex(access), sessionId, t + ACCESS_TTL),
    env.DB.prepare("INSERT INTO refresh_tokens (hash, session_id, expires_at) VALUES (?, ?, ?)")
      .bind(await sha256Hex(refresh), sessionId, t + REFRESH_TTL),
  ]);
  return { access_token: access, refresh_token: refresh, expires_in: ACCESS_TTL };
}

async function revokeSession(env: Env, sessionId: string) {
  const t = now();
  await env.DB.batch([
    env.DB.prepare("UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").bind(t, sessionId),
    env.DB.prepare("DELETE FROM access_tokens WHERE session_id = ?").bind(sessionId),
  ]);
}

interface Auth { userId: string; sessionId: string; login: string }

async function authenticate(request: Request, env: Env): Promise<Auth> {
  const header = request.headers.get("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token.startsWith("kga_")) throw new HttpError(401, "unauthorized", "missing access token");
  const row = await env.DB.prepare(
    `SELECT s.id AS session_id, s.user_id, u.github_login
       FROM access_tokens a
       JOIN sessions s ON s.id = a.session_id
       JOIN users u ON u.id = s.user_id
      WHERE a.hash = ? AND a.expires_at > ? AND s.revoked_at IS NULL`,
  ).bind(await sha256Hex(token), now()).first<{ session_id: string; user_id: string; github_login: string }>();
  if (!row) throw new HttpError(401, "unauthorized", "invalid or expired access token");
  return { userId: row.user_id, sessionId: row.session_id, login: row.github_login };
}

// ---------- handlers ----------

async function loginWithGithub(request: Request, env: Env): Promise<Response> {
  const body = await readJson(request);
  const gh = await verifyGithubToken(env, requireString(body, "github_token"));
  const t = now();
  const user = await env.DB.prepare(
    `INSERT INTO users (id, github_id, github_login, created_at) VALUES (?, ?, ?, ?)
     ON CONFLICT (github_id) DO UPDATE SET github_login = excluded.github_login
     RETURNING id`,
  ).bind(crypto.randomUUID(), gh.id, gh.login, t).first<{ id: string }>();
  const sessionId = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO sessions (id, user_id, created_at) VALUES (?, ?, ?)")
    .bind(sessionId, user!.id, t).run();
  const tokens = await issueTokens(env, sessionId);
  return json({ ...tokens, user: { id: user!.id, login: gh.login } });
}

// Refresh tokens are single-use. Presenting one twice means it leaked, so
// the whole session (token family) is revoked.
async function refresh(request: Request, env: Env): Promise<Response> {
  const token = requireString(await readJson(request), "refresh_token");
  const hash = await sha256Hex(token);
  const row = await env.DB.prepare(
    `SELECT r.session_id, r.expires_at, r.used_at, s.revoked_at
       FROM refresh_tokens r JOIN sessions s ON s.id = r.session_id WHERE r.hash = ?`,
  ).bind(hash).first<{ session_id: string; expires_at: number; used_at: number | null; revoked_at: number | null }>();
  if (!row || row.revoked_at !== null || row.expires_at <= now()) {
    throw new HttpError(401, "invalid_refresh_token", "refresh token is invalid or expired");
  }
  const claimed = await env.DB.prepare(
    "UPDATE refresh_tokens SET used_at = ? WHERE hash = ? AND used_at IS NULL",
  ).bind(now(), hash).run();
  if (row.used_at !== null || claimed.meta.changes !== 1) {
    await revokeSession(env, row.session_id);
    throw new HttpError(401, "refresh_token_reused", "refresh token reuse detected; session revoked");
  }
  return json(await issueTokens(env, row.session_id));
}

async function logout(auth: Auth, env: Env): Promise<Response> {
  await revokeSession(env, auth.sessionId);
  return json({ ok: true });
}

async function me(auth: Auth): Promise<Response> {
  return json({ user: { id: auth.userId, login: auth.login } });
}

function decodePublicKey(value: string): void {
  let raw: string;
  try {
    raw = atob(value);
  } catch {
    throw new HttpError(400, "bad_public_key", "public_key must be base64");
  }
  if (raw.length !== 32) throw new HttpError(400, "bad_public_key", "public_key must be 32 bytes (X25519)");
}

async function registerDevice(request: Request, auth: Auth, env: Env): Promise<Response> {
  const body = await readJson(request);
  const name = requireString(body, "name", 100);
  const publicKey = requireString(body, "public_key", 64);
  decodePublicKey(publicKey);
  const existing = await env.DB.prepare(
    "SELECT id, revoked_at FROM devices WHERE user_id = ? AND public_key = ?",
  ).bind(auth.userId, publicKey).first<{ id: string; revoked_at: number | null }>();
  if (existing?.revoked_at) throw new HttpError(409, "device_revoked", "this device key was revoked; generate a new one");
  const id = existing?.id ?? crypto.randomUUID();
  if (!existing) {
    await env.DB.prepare(
      "INSERT INTO devices (id, user_id, name, public_key, created_at) VALUES (?, ?, ?, ?, ?)",
    ).bind(id, auth.userId, name, publicKey, now()).run();
  }
  await env.DB.prepare("UPDATE sessions SET device_id = ? WHERE id = ?").bind(id, auth.sessionId).run();
  return json({ id }, existing ? 200 : 201);
}

async function listDevices(auth: Auth, env: Env): Promise<Response> {
  const { results } = await env.DB.prepare(
    `SELECT id, name, public_key, created_at FROM devices
      WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at`,
  ).bind(auth.userId).all();
  return json({ devices: results });
}

async function removeDevice(id: string, auth: Auth, env: Env): Promise<Response> {
  const res = await env.DB.prepare(
    "UPDATE devices SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
  ).bind(now(), id, auth.userId).run();
  if (res.meta.changes !== 1) throw new HttpError(404, "not_found", "no such device");
  const { results } = await env.DB.prepare("SELECT id FROM sessions WHERE device_id = ? AND revoked_at IS NULL")
    .bind(id).all<{ id: string }>();
  for (const s of results) await revokeSession(env, s.id);
  return json({ ok: true });
}

// ---------- router ----------

async function route(request: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(request.url);
  const method = request.method;

  if (method === "POST" && pathname === "/v1/auth/github") return loginWithGithub(request, env);
  if (method === "POST" && pathname === "/v1/auth/refresh") return refresh(request, env);

  const auth = await authenticate(request, env);
  if (method === "POST" && pathname === "/v1/auth/logout") return logout(auth, env);
  if (method === "GET" && pathname === "/v1/me") return me(auth);
  if (method === "POST" && pathname === "/v1/devices") return registerDevice(request, auth, env);
  if (method === "GET" && pathname === "/v1/devices") return listDevices(auth, env);
  const device = pathname.match(/^\/v1\/devices\/([0-9a-f-]{36})$/);
  if (method === "DELETE" && device) return removeDevice(device[1], auth, env);
  throw new HttpError(404, "not_found", "no such endpoint");
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      return await route(request, env);
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.code, message: err.message }, err.status);
      console.error("unhandled error", err instanceof Error ? err.message : "unknown");
      return json({ error: "internal", message: "internal error" }, 500);
    }
  },
} satisfies ExportedHandler<Env>;
