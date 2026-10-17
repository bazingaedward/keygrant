"""Check built distributions before they go to PyPI (a version can only be uploaded once).

    python scripts/check_dist.py dist 0.1.10

The wheel must hold exactly the three modules plus dist-info, with the expected
Version; neither the wheel nor the sdist may carry vaults, cloud state, .env or tokens.
"""
import sys
import tarfile
import zipfile
from pathlib import Path

MODULES = {"keygrant.py", "keygrant_mcp.py", "keygrant_cloud.py"}
FORBIDDEN = ("vault.json", "cloud.json", ".env", "token", ".keygrant/", "grants.json", "audit.log")


def main(dist: str, version: str) -> int:
    errors = []
    wheels = list(Path(dist).glob("keygrant-*.whl"))
    sdists = list(Path(dist).glob("keygrant-*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        sys.exit(f"error: expected one wheel and one sdist in {dist}, found {wheels + sdists}")
    wheel, sdist = wheels[0], sdists[0]

    with zipfile.ZipFile(wheel) as z:
        names = z.namelist()
        info = f"keygrant-{version}.dist-info/"
        extra = [n for n in names if n not in MODULES and not n.startswith(info)]
        if extra:
            errors.append(f"{wheel.name}: unexpected files {extra}")
        if missing := MODULES - set(names):
            errors.append(f"{wheel.name}: missing {sorted(missing)}")
        meta = z.read(info + "METADATA").decode() if info + "METADATA" in names else ""
        if f"Version: {version}" not in meta.splitlines():
            errors.append(f"{wheel.name}: METADATA does not say Version: {version}")
    with tarfile.open(sdist) as t:
        names += t.getnames()

    for n in names:
        if any(f in n.lower() for f in FORBIDDEN):
            errors.append(f"forbidden file in distribution: {n}")

    for e in errors:
        print(f"error: {e}", file=sys.stderr)
    if not errors:
        print(f"ok: {wheel.name} = {sorted(n for n in names if n in MODULES)} + dist-info; {sdist.name}")
    return 1 if errors else 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__.strip())
    sys.exit(main(*sys.argv[1:]))
