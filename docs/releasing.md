# Releasing keygrant

Releases run in GitHub Actions ([`.github/workflows/release.yml`](../.github/workflows/release.yml)),
triggered by pushing a tag `vX.Y.Z`. Nothing is uploaded from a laptop. The
MCP Registry trusts the workflow's GitHub OIDC identity; PyPI gets the upload
token from the `PYPI_API_TOKEN` repo secret (Trusted Publishing needs the
publisher registered on pypi.org first — see the optional setup below).

```
verify ─ test ─ build ─ pypi (needs approval) ─ pypi-live ┬─ mcp-registry
                                                          └─ plugin-pins (opens a PR)
```

| Job | What it does |
|---|---|
| verify | Tag `vX.Y.Z` equals the version in `pyproject.toml`, `keygrant_mcp.py` serverInfo and both `server.json` fields; the tagged commit is on `master`; PyPI does not have `X.Y.Z` yet |
| test | [`ci.yml`](../.github/workflows/ci.yml): pytest on Ubuntu and Windows, Python 3.10 and 3.13, plus Ubuntu under a `zh_CN.GBK` locale (the Chinese-Windows encoding bugs of 0.1.8/0.1.9) |
| build | `uv build`, then [`scripts/check_dist.py`](../scripts/check_dist.py): the wheel holds only `keygrant.py`, `keygrant_mcp.py`, `keygrant_cloud.py` + dist-info with the right `Version:`, no vault/cloud/.env/token files; `twine check` |
| pypi | Uploads with the `PYPI_API_TOKEN` secret. Runs in the `pypi` environment; protect it with a required reviewer to make it wait for approval |
| pypi-live | Polls `https://pypi.org/pypi/keygrant/X.Y.Z/json` until 200, installs `keygrant==X.Y.Z` from PyPI and checks the MCP server answers `initialize` with version `X.Y.Z` |
| mcp-registry | `mcp-publisher login github-oidc` + `publish` (reads `server.json`), then checks the registry lists `X.Y.Z` as latest |
| plugin-pins | Runs `scripts/bump_version.py --pins X.Y.Z` on `master` and opens a PR. Only after PyPI is live, because the plugin pins `keygrant==X.Y.Z` and the Claude plugin directory picks up `master` |

A version can be uploaded to PyPI and to the registry only once. If a job after
`pypi` fails, re-run that job from the Actions page; do not re-tag.

## Each release

1. Bump the package version (four places in three files) and check:
   ```bash
   python scripts/bump_version.py X.Y.Z
   python -m pytest tests/ -q
   ```
2. Commit (`Release X.Y.Z: <one line>`, body lists the changes and their
   commits) and get it onto `master`.
3. Tag that commit and push the tag:
   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
4. Actions → the *Release* run → **Review deployments** → approve `pypi`.
5. When the run is green, review the *Plugin: pin keygrant==X.Y.Z* PR, run
   `claude plugin validate ./plugin --strict` and `claude plugin validate . --strict`
   on its branch, and merge. (PRs opened with `GITHUB_TOKEN` don't trigger CI.)
6. Add the changelog entry on the site (keygrant-cloud,
   `site/src/components/Changelog.astro`, en/zh/ja).

## One-time setup (by hand, as the repo owner)

1. **PyPI upload token as a repo secret.** The same token keygrant stores as
   `UV_PUBLISH_TOKEN`; agents are blocked from secret-store writes, so run it
   yourself (PowerShell, value never touches the command line or the clipboard):
   ```powershell
   keygrant exec UV_PUBLISH_TOKEN -- "C:\Program Files\Git\bin\bash.exe" -c 'printf %s "$UV_PUBLISH_TOKEN" | gh secret set PYPI_API_TOKEN -R bazingaedward/keygrant'
   ```
   *Preferred upgrade, once the PyPI web login is recovered (2026-10-21: password
   lost, account `kaixiang-qiu`):* register a trusted publisher at
   https://pypi.org/manage/project/keygrant/settings/publishing/ → *Add a new
   publisher* → GitHub — Owner `bazingaedward`, Repository `keygrant`, Workflow
   name `release.yml`, Environment name `pypi` — then put back the `pypi` job's
   `permissions: id-token: write`, drop its `password:` input, delete the
   `PYPI_API_TOKEN` secret and the PyPI API token, and `keygrant rm UV_PUBLISH_TOKEN`.
2. **GitHub environment `pypi`.** Repo → Settings → Environments → *New environment* `pypi`:
   - *Required reviewers*: `bazingaedward` (this is the approval in step 4).
   - *Deployment branches and tags* → *Selected branches and tags* → add tag rule `v*`.
3. **Let the workflow open PRs.** Settings → Actions → General → *Workflow permissions*:
   tick *Allow GitHub Actions to create and approve pull requests*
   (keep the default token permission at read; the jobs ask for what they need).
4. **Optional: protect release tags.** Settings → Rules → Rulesets → new tag
   ruleset for `v*`, restrict creation/deletion/update to admins.

The MCP Registry needs no setup: `login github-oidc` proves the run belongs to a
repo owned by `bazingaedward`, which owns the `io.github.bazingaedward/*`
namespace. The `<!-- mcp-name: io.github.bazingaedward/keygrant -->` line in
README.md must stay; the registry uses it to match the PyPI package.

`MCP_PUBLISHER_VERSION` / `MCP_PUBLISHER_SHA256` at the top of `release.yml`
pin mcp-publisher; to upgrade, take the sha256 of `mcp-publisher_linux_amd64.tar.gz`
from that release's `registry_<ver>_checksums.txt`.
