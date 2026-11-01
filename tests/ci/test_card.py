# SPDX-License-Identifier: Apache-2.0
# Derived from nissifield/snes2DHD (same author), relicensed Apache-2.0.
"""Tests for tools/ci/card.py."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "ci"))

import card

BODY = """Some intro text.

### Goal

Do the docs thing.

### Files you may touch

docs/**
README.md

### Files you must not touch

docs/private/**

### Done when

Tests pass.
"""


class CardTests(unittest.TestCase):
    def test_parse_card_sections(self):
        c = card.parse_card(12, ["card:ready"], BODY)
        self.assertEqual(c.number, 12)
        self.assertEqual(c.labels, ["card:ready"])
        self.assertEqual(c.allow, ["docs/**", "README.md"])
        self.assertEqual(c.deny, ["docs/private/**"])

    def test_glob_doublestar(self):
        self.assertTrue(card.glob_match("docs/**", "docs/a/b/c.md"))
        self.assertFalse(card.glob_match("docs/**", "src/a.md"))

    def test_glob_doublestar_zero_dirs(self):
        self.assertTrue(card.glob_match("src/**/x.py", "src/x.py"))
        self.assertTrue(card.glob_match("src/**/x.py", "src/a/b/x.py"))
        self.assertFalse(card.glob_match("src/**/x.py", "src/a/b/y.py"))

    def test_glob_newline_in_path_still_matches(self):
        # a deny glob must not be dodged by a newline in the path
        self.assertTrue(card.glob_match("docs/private/**", "docs/private/a\nb.md"))

    def test_parse_issue_form_rendering(self):
        # Body as GitHub renders the card.yml form: every field label becomes
        # a ### heading, an empty optional textarea becomes "_No response_".
        body = """### Goal

Do the docs thing.

### Type

docs

### Size

S

### Files you may touch

docs/**
README.md

### Files you must not touch

_No response_

### Done when

Tests pass.

### Prompt

Read AGENTS.md.
"""
        c = card.parse_card(12, ["card:ready"], body)
        self.assertEqual(c.allow, ["docs/**", "README.md"])
        self.assertEqual(c.deny, [])

    def test_repeated_heading_does_not_extend_allowlist(self):
        # a second "### Files you may touch" (e.g. inside the rendered Prompt) is ignored
        body = BODY + "\n### Prompt\n\n### Files you may touch\n\n**\n"
        c = card.parse_card(12, ["card:ready"], body)
        self.assertEqual(c.allow, ["docs/**", "README.md"])
        self.assertEqual(c.deny, ["docs/private/**"])

    def test_stray_deny_heading_does_not_hide_denylist(self):
        # an empty "### Files you must not touch" earlier in the body must not drop the real one
        body = "### Files you must not touch\n\n### Note\n\n" + BODY
        c = card.parse_card(12, ["card:ready"], body)
        self.assertEqual(c.deny, ["docs/private/**"])


class ProtectedTests(unittest.TestCase):
    def test_protected(self):
        for p in ("crates/zoopa-crypto/src/lib.rs", "proto/a.proto", ".github/workflows/checks.yml",
                  "tools/ci/pr_checks.py", "tests/ci/test_card.py", "LICENSE", "LICENSE-AGPL",
                  "third_party/ponytail/SOURCE", "docs/DESIGN.md", "docs/adr/0013-x.md",
                  "docs/design-v0.2-self-host-amendment.md", "README.md", "deploy/helm/x.yaml",
                  ".claude/agents/a.md", "Cargo.toml", "fuzz/fuzz_targets/a.rs", ".cargo/config.toml",
                  "crates/zoopa-config/src/lib.rs", "a/B.RS"):
            self.assertTrue(card.is_protected(p), p)

    def test_case_insensitive(self):
        for p in (".GitHub/x", "crates/zoopa-crypto/SRC/lib.rs", "license.md", "Tools/CI/x.py",
                  "readme.md"):
            self.assertTrue(card.is_protected(p), p)

    def test_nested_basenames(self):
        for p in ("crates/x/Cargo.toml", "crates/x/Cargo.lock", "a/b/.gitattributes", "docs/CODEOWNERS",
                  "x/Dockerfile.dev", "x/Dockerfile", "x/Makefile", "x/justfile", "a/build.rs",
                  "a/rust-toolchain", "a/rust-toolchain.toml", "a/deny.toml", "a/clippy.toml",
                  "a/.clippy.toml", "a/rustfmt.toml", "a/.rustfmt.toml", "a/.gitmodules",
                  "a/.lfsconfig", "a/AGENTS.md", "a/CLAUDE.md", "a/.mcp.json", "a/package.json",
                  "a/.claude/x.md", "a/.cargo/config.toml"):
            self.assertTrue(card.is_protected(p), p)

    def test_agent_editor_and_dot_files(self):
        for p in ("docs/AGENTS.override.md", "docs/.cursorrules", "x/.codex/config.toml", ".mailmap",
                  "docs/GEMINI.md", "crates/a/rust-analyzer.toml", "a/.editorconfig"):
            self.assertTrue(card.is_protected(p), p)

    def test_middle_doublestar_matches_zero_dirs(self):
        self.assertTrue(card._codeowners_match("/a/**/b.rs", "a/b.rs"))
        self.assertTrue(card._codeowners_match("/a/**/b.rs", "a/x/y/B.rs"))
        self.assertFalse(card._codeowners_match("/a/**/b.rs", "x/a/b.rs"))

    def test_not_protected(self):
        for p in ("docs/guide.md", "Cargo.toml.md",
                  "crates/zoopa-cryptography/notes.txt", "docs/design-v0.2/x.md", "docs/notes/README.md",
                  "crates/zoopa-config/Cargo.toml.bak"):
            self.assertFalse(card.is_protected(p), p)

    def test_newline_in_path_still_protected(self):
        self.assertTrue(card.is_protected("crates/zoopa-crypto/a\nb.rs"))

    def test_sensitive(self):
        for p in ("crates/zoopa-crypto/src/lib.rs", "crates/zoopa-pra/x", "proto/a.proto",
                  "crates/zoopa-proto/src/lib.rs", "Crates/Zoopa-Policy/x.rs"):
            self.assertTrue(card.is_sensitive(p), p)
        for p in ("docs/x.md", "crates/zoopa-config/src/lib.rs", "crates/zoopa-netstack/x.rs"):
            self.assertFalse(card.is_sensitive(p), p)

    def test_sensitive_subset_of_protected(self):
        self.assertLessEqual(set(card.SENSITIVE), set(card.PROTECTED))

    def test_protected_matches_codeowners(self):
        lines = (ROOT / ".github" / "CODEOWNERS").read_text().splitlines()
        patterns = tuple(l.split()[0] for l in lines if l.strip() and not l.lstrip().startswith("#"))
        self.assertEqual(card.PROTECTED, patterns)


if __name__ == "__main__":
    unittest.main()
