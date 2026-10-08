import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

const CLIENT_ID = "test-client";
const CLIENT_SECRET = "test-secret";

// Stand-in for api.github.com's "check a token" endpoint. Only tokens listed
// here were "issued to our app"; anything else is unknown to GitHub.
const GITHUB_USERS: Record<string, { id: number; login: string }> = {
  gho_alice: { id: 1001, login: "alice" },
  gho_bob: { id: 1002, login: "bob" },
};

async function githubStub(request: Request): Promise<Response> {
  const url = new URL(request.url);
  if (url.hostname !== "github.test" || url.pathname !== `/applications/${CLIENT_ID}/token`) {
    return new Response("unexpected outbound request", { status: 599 });
  }
  if (request.headers.get("authorization") !== "Basic " + btoa(`${CLIENT_ID}:${CLIENT_SECRET}`)) {
    return new Response("bad client credentials", { status: 401 });
  }
  if (request.method === "DELETE") return new Response(null, { status: 204 });
  const { access_token } = (await request.json()) as { access_token: string };
  const user = GITHUB_USERS[access_token];
  return user ? Response.json({ token: access_token, user }) : new Response("not found", { status: 404 });
}

export default defineConfig(async () => {
  const migrations = await readD1Migrations("./migrations");
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.toml" },
        miniflare: {
          bindings: {
            GITHUB_CLIENT_ID: CLIENT_ID,
            GITHUB_CLIENT_SECRET: CLIENT_SECRET,
            GITHUB_API: "https://github.test",
            TEST_MIGRATIONS: migrations,
          },
          outboundService: githubStub,
        },
      }),
    ],
    test: { setupFiles: ["./test/apply-migrations.ts"] },
  };
});
