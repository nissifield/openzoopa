# SPDX-License-Identifier: Apache-2.0
# Derived from nissifield/snes2DHD (same author), relicensed Apache-2.0.
"""Task-card parsing and protected-path rules for openzoopa CI."""
import re
from typing import NamedTuple

# Identical to the patterns in .github/CODEOWNERS, in file order (a test keeps
# them in sync). PRs from non-maintainers never touch these.
PROTECTED = (
    "/crates/zoopa-crypto/",
    "/crates/zoopa-spa/",
    "/crates/zoopa-tunnel/",
    "/crates/zoopa-policy/",
    "/crates/zoopa-pki/",
    "/crates/zoopa-token/",
    "/crates/zoopa-idp/",
    "/crates/zoopa-pra/",
    "/proto/",
    "/crates/zoopa-proto/",
    "/crates/zoopa-netstack/",
    "/crates/zoopa-client-ffi/",
    "/crates/zoopa-posture/",
    "/docs/rfcs/",
    "/docs/adr/",
    "/docs/DESIGN.md",
    "/docs/design-*.md",
    "/docs/threat-model.md",
    "**/LICENSE*",
    "/LICENSING.md",
    "/third_party/",
    "/MAINTAINERS.md",
    "/SECURITY.md",
    "/CODE_OF_CONDUCT.md",
    "/CONTRIBUTING.md",
    "/README.md",
    "/.github/",
    "**/.claude/",
    "/.agents/",
    "**/AGENTS.md",
    "**/AGENTS*.md",
    "**/GEMINI.md",
    "**/CLAUDE.md",
    "**/CLAUDE.local.md",
    "**/.mcp.json",
    "/tools/",
    "/tests/ci/",
    "/tests/review/",
    "/tests/golden/",
    "/tests/e2e/",
    "/fuzz/",
    "/xtask/",
    "**/.cargo/",
    "/supply-chain/",
    "**/deny.toml",
    "**/Cargo.toml",
    "**/Cargo.lock",
    "**/build.rs",
    "**/rust-toolchain",
    "**/rust-toolchain.toml",
    "**/clippy.toml",
    "**/.clippy.toml",
    "**/rustfmt.toml",
    "**/.rustfmt.toml",
    "**/rust-analyzer.toml",
    "/deploy/",
    "/.config/",
    "/.devcontainer/",
    "/.vscode/",
    "/.envrc",
    "/flake.nix",
    "**/Makefile",
    "**/justfile",
    "/.pre-commit-config.yaml",
    "**/Dockerfile*",
    "**/package.json",
    "**/package-lock.json",
    "**/pnpm-lock.yaml",
    "**/yarn.lock",
    "**/.npmrc",
    "**/.gitattributes",
    "**/.gitmodules",
    "**/.lfsconfig",
    "**/CODEOWNERS",
    "**/.*",
)

# DESIGN 6.3 crates and the wire format: these need two human maintainers.
SENSITIVE = (
    "/crates/zoopa-crypto/",
    "/crates/zoopa-spa/",
    "/crates/zoopa-tunnel/",
    "/crates/zoopa-policy/",
    "/crates/zoopa-pki/",
    "/crates/zoopa-token/",
    "/crates/zoopa-idp/",
    "/crates/zoopa-pra/",
    "/proto/",
    "/crates/zoopa-proto/",
)


class Card(NamedTuple):
    number: int
    labels: list[str]
    allow: list[str]
    deny: list[str]


def _glob_rx(pattern: str) -> str:
    pat = re.escape(pattern)
    pat = pat.replace(r"\*\*/", r"(?:.*/)?")  # **/ also matches zero directories
    return pat.replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", "[^/]")


def glob_match(pattern: str, path: str) -> bool:
    """fnmatch-style match where `*` stays within a directory and `**` crosses them."""
    return re.fullmatch(_glob_rx(pattern), path, re.S) is not None  # re.S: a newline in a path must not dodge `.*`


def _codeowners_match(pattern: str, path: str) -> bool:
    """CODEOWNERS semantics, case-insensitive. A leading `/` anchors at the root;
    `**/x` and a slash-free `x` match at any depth; a match also covers
    everything under it (fails closed for file patterns)."""
    pat = pattern.lower()
    if pat.startswith("**/"):
        pat, anywhere = pat[3:], True
    else:
        anywhere = "/" not in pat.rstrip("/")  # slash-free: any depth
    prefix = "(?:.*/)?" if anywhere else ""
    return re.fullmatch(prefix + _glob_rx(pat.strip("/")) + "(?:/.*)?", path.lower(), re.S) is not None


def is_protected(path: str) -> bool:
    return any(_codeowners_match(p, path) for p in PROTECTED)


def is_sensitive(path: str) -> bool:
    return any(_codeowners_match(p, path) for p in SENSITIVE)


def _section(body: str, title: str) -> list[str]:
    lines = []
    in_section = False
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("###"):
            in_section = stripped == f"### {title}"
        elif in_section and stripped:
            # GitHub issue forms render an empty optional field as "_No response_".
            if stripped != "_No response_":
                lines.append(stripped)
    return lines


def parse_card(number: int, labels: list[str], body: str) -> Card:
    return Card(number, list(labels),
                _section(body, "Files you may touch"),
                _section(body, "Files you must not touch"))
