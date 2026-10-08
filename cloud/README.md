# keygrant cloud API

Cloudflare Worker + D1. Design: [`docs/design/cloud-mvp.md`](../docs/design/cloud-mvp.md).

## Develop

```bash
npm install --legacy-peer-deps   # npm 10.9 mis-resolves vitest's optional peers
npm test                          # runs against local D1 in Miniflare; GitHub is stubbed
npm run typecheck
```

## First deploy

1. Create a GitHub OAuth App (owner `bazingaedward`), tick **Enable Device
   Flow**, and put its client ID in `wrangler.toml` (`GITHUB_CLIENT_ID`) and
   in `keygrant_cloud.py` (`GITHUB_CLIENT_ID`).
2. `npx wrangler login`
3. `npx wrangler d1 create keygrant` and copy the `database_id` into `wrangler.toml`.
4. `npx wrangler d1 migrations apply keygrant --remote`
5. `npx wrangler secret put GITHUB_CLIENT_SECRET`
6. `npx wrangler deploy`, then attach the custom domain `api.keygrant.app`.
