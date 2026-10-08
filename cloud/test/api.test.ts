import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const BASE = "https://api.keygrant.test";
const KEY_A = btoa(String.fromCharCode(...new Uint8Array(32).fill(1)));
const KEY_B = btoa(String.fromCharCode(...new Uint8Array(32).fill(2)));

async function call(method: string, path: string, opts: { token?: string; body?: unknown } = {}) {
  const headers: Record<string, string> = {};
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  if (opts.body !== undefined) headers["content-type"] = "application/json";
  const res = await SELF.fetch(BASE + path, {
    method,
    headers,
    body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
  });
  return { status: res.status, body: (await res.json()) as any };
}

const login = (github_token: string) => call("POST", "/v1/auth/github", { body: { github_token } });

describe("GitHub sign-in", () => {
  it("rejects a token not issued to our OAuth App", async () => {
    const res = await login("ghp_some_other_apps_token");
    expect(res.status).toBe(401);
    expect(res.body.error).toBe("invalid_github_token");
  });

  it("issues our own tokens and identifies the user", async () => {
    const res = await login("gho_alice");
    expect(res.status).toBe(200);
    expect(res.body.access_token).toMatch(/^kga_/);
    expect(res.body.refresh_token).toMatch(/^kgr_/);
    const me = await call("GET", "/v1/me", { token: res.body.access_token });
    expect(me.body.user.login).toBe("alice");
  });

  it("maps repeat sign-ins to the same user", async () => {
    const a = await login("gho_alice");
    const b = await login("gho_alice");
    expect(a.body.user.id).toBe(b.body.user.id);
  });

  it("does not accept the GitHub token as our access token", async () => {
    const res = await call("GET", "/v1/me", { token: "gho_alice" });
    expect(res.status).toBe(401);
  });
});

describe("refresh tokens", () => {
  it("rotate: the new access token works", async () => {
    const { body } = await login("gho_alice");
    const r = await call("POST", "/v1/auth/refresh", { body: { refresh_token: body.refresh_token } });
    expect(r.status).toBe(200);
    expect(r.body.refresh_token).not.toBe(body.refresh_token);
    expect((await call("GET", "/v1/me", { token: r.body.access_token })).status).toBe(200);
  });

  it("reuse revokes the whole session", async () => {
    const { body } = await login("gho_alice");
    const first = await call("POST", "/v1/auth/refresh", { body: { refresh_token: body.refresh_token } });
    const replay = await call("POST", "/v1/auth/refresh", { body: { refresh_token: body.refresh_token } });
    expect(replay.status).toBe(401);
    expect(replay.body.error).toBe("refresh_token_reused");
    expect((await call("GET", "/v1/me", { token: first.body.access_token })).status).toBe(401);
    const next = await call("POST", "/v1/auth/refresh", { body: { refresh_token: first.body.refresh_token } });
    expect(next.status).toBe(401);
  });

  it("logout voids access and refresh tokens", async () => {
    const { body } = await login("gho_alice");
    expect((await call("POST", "/v1/auth/logout", { token: body.access_token })).status).toBe(200);
    expect((await call("GET", "/v1/me", { token: body.access_token })).status).toBe(401);
    const r = await call("POST", "/v1/auth/refresh", { body: { refresh_token: body.refresh_token } });
    expect(r.status).toBe(401);
  });
});

describe("devices", () => {
  it("registers, lists and is idempotent per public key", async () => {
    const { body } = await login("gho_bob");
    const t = body.access_token;
    const first = await call("POST", "/v1/devices", { token: t, body: { name: "laptop", public_key: KEY_A } });
    expect(first.status).toBe(201);
    const again = await call("POST", "/v1/devices", { token: t, body: { name: "laptop", public_key: KEY_A } });
    expect(again.body.id).toBe(first.body.id);
    const list = await call("GET", "/v1/devices", { token: t });
    expect(list.body.devices.map((d: any) => d.public_key)).toEqual([KEY_A]);
  });

  it("rejects malformed public keys", async () => {
    const { body } = await login("gho_bob");
    const res = await call("POST", "/v1/devices", {
      token: body.access_token,
      body: { name: "x", public_key: btoa("too short") },
    });
    expect(res.status).toBe(400);
  });

  it("removing a device revokes its sessions and its key", async () => {
    const laptop = (await login("gho_bob")).body.access_token;
    const phone = (await login("gho_bob")).body.access_token;
    const dev = await call("POST", "/v1/devices", { token: phone, body: { name: "phone", public_key: KEY_B } });
    const del = await call("DELETE", `/v1/devices/${dev.body.id}`, { token: laptop });
    expect(del.status).toBe(200);
    expect((await call("GET", "/v1/me", { token: phone })).status).toBe(401);
    expect((await call("GET", "/v1/me", { token: laptop })).status).toBe(200);
    const reuse = await call("POST", "/v1/devices", { token: laptop, body: { name: "phone", public_key: KEY_B } });
    expect(reuse.status).toBe(409);
  });

  it("users cannot see or remove each other's devices", async () => {
    const bob = (await login("gho_bob")).body.access_token;
    const alice = (await login("gho_alice")).body.access_token;
    const dev = await call("POST", "/v1/devices", { token: bob, body: { name: "b", public_key: KEY_A } });
    expect((await call("GET", "/v1/devices", { token: alice })).body.devices).toEqual([]);
    expect((await call("DELETE", `/v1/devices/${dev.body.id}`, { token: alice })).status).toBe(404);
  });
});

describe("hardening", () => {
  it("rejects oversized bodies", async () => {
    const res = await login("x".repeat(70 * 1024));
    expect(res.status).toBe(413);
  });

  it("requires auth for everything but sign-in and refresh", async () => {
    expect((await call("GET", "/v1/devices")).status).toBe(401);
  });
});
