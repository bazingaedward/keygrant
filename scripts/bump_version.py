"""Bump, or check, every place the keygrant version is written down.

    python scripts/bump_version.py 0.1.10           # package: pyproject, MCP serverInfo, server.json
    python scripts/bump_version.py --pins 0.1.10    # plugin pins + README uvx examples
    python scripts/bump_version.py --check 0.1.10   # exit 1 unless the package locations say 0.1.10

The package and the pins move separately on purpose: the plugin pins
`keygrant==<ver>`, so they may only change once that version is live on PyPI
(the release workflow does it after publishing).
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VER = r"\d+\.\d+\.\d+(?:[-.]?(?:a|b|rc|post|dev)\d*)?"

# (file, pattern, expected number of matches); group 2 is the version
PACKAGE = [
    ("pyproject.toml", rf'^(version = ")({VER})(")', 1),
    ("keygrant_mcp.py", rf'("serverInfo": \{{"name": "keygrant", "version": ")({VER})(")', 1),
    ("server.json", rf'^(\s*"version": ")({VER})(")', 2),
]
PINS = [
    ("plugin/.claude-plugin/plugin.json", rf'^(\s*"version": ")({VER})(")', 1),
    ("plugin/.mcp.json", rf"(keygrant==)({VER})()", 1),
    ("plugin/skills/keygrant/SKILL.md", rf"(keygrant==)({VER})()", None),
    ("plugin/README.md", rf"(keygrant==)({VER})()", None),
    ("plugin/README.md", rf"(^  version )({VER})(, from PyPI)", 1),
    ("README.md", rf"(keygrant==)({VER})()", None),
]


def read(rel: str) -> str:
    # newline="" keeps CRLF files CRLF
    with open(ROOT / rel, encoding="utf-8", newline="") as f:
        return f.read()


def found(rel: str, pattern: str, count: int | None) -> list[str]:
    versions = [m.group(2) for m in re.finditer(pattern, read(rel), re.M)]
    if not versions or (count is not None and len(versions) != count):
        sys.exit(f"error: {rel}: expected {count or 'some'} match(es) of {pattern!r}, found {len(versions)}")
    return versions


def bump(targets, new: str) -> None:
    for rel, pattern, count in targets:
        old = found(rel, pattern, count)
        text = re.sub(pattern, lambda m: m.group(1) + new + m.group(3), read(rel), flags=re.M)
        with open(ROOT / rel, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        print(f"{rel}: {', '.join(sorted(set(old)))} -> {new}")


def check(targets, want: str) -> int:
    bad = 0
    for rel, pattern, count in targets:
        for v in found(rel, pattern, count):
            if v != want:
                print(f"error: {rel} says {v}, expected {want}", file=sys.stderr)
                bad += 1
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    flags = {a for a in argv if a.startswith("--")}
    args = [a for a in argv if not a.startswith("--")]
    if len(args) != 1 or not re.fullmatch(VER, args[0]) or flags - {"--pins", "--check"}:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    targets = PINS if "--pins" in flags else PACKAGE
    if "--check" in flags:
        return check(targets, args[0])
    bump(targets, args[0])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
