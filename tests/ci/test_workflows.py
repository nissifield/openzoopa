# SPDX-License-Identifier: Apache-2.0
"""Static checks on .github/workflows/*.yml, without a YAML parser (stdlib only).

The `checks` job runs on pull_request_target, so its workflow must stay a
data-only reader of the PR; the other rules keep every workflow pinned and
free of injection sinks.
"""
import re
import tempfile
import unittest
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github" / "workflows"
FILES = sorted([*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")])
USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)\s*(?:#.*)?$")
PINNED_RE = re.compile(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}")
FORBIDDEN = ("actions/cache", "upload-artifact", "download-artifact", "workflow_run", "cargo", "rustup")
RUN_RE = re.compile(r"^(\s*)(?:-\s+)?run:\s*(.*)$")
SINK_RE = re.compile(r"\$\{\{|github\.event\.pull_request\.(?:title|body|head\.ref)|github\.head_ref")


def code_lines(path):
    """(number, line) without full-line comments."""
    return [(n, l) for n, l in enumerate(path.read_text().splitlines(), 1)
            if not l.lstrip().startswith("#")]


def run_blocks(path):
    """(number, text) of every `run:` value, single-line or block scalar."""
    lines = path.read_text().splitlines()
    out = []
    for i, line in enumerate(lines):
        m = RUN_RE.match(line)
        if not m:
            continue
        key_col = len(line) - len(line.lstrip()) + (2 if line.lstrip().startswith("- ") else 0)
        text = [m[2]]
        if re.fullmatch(r"[|>][+-]?\d*\s*(?:#.*)?", m[2]):
            text = []
            for nxt in lines[i + 1:]:
                if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= key_col:
                    break
                text.append(nxt)
        out.append((i + 1, "\n".join(text)))
    return out


class WorkflowTests(unittest.TestCase):
    def test_workflows_exist(self):
        self.assertTrue(FILES)

    def test_every_action_pinned_by_full_sha(self):
        for f in FILES:
            for n, line in code_lines(f):
                m = USES_RE.match(line)
                if "uses:" in line:
                    self.assertTrue(m and PINNED_RE.fullmatch(m[1]), f"{f.name}:{n}: {line.strip()}")

    def test_forbidden_features_absent_from_checks(self):
        # other workflows (the later Rust CI) may use cargo; the pull_request_target gate never does
        for n, line in code_lines(WORKFLOWS / "checks.yml"):
            for word in FORBIDDEN:
                self.assertNotIn(word, line.lower(), f"checks.yml:{n}")

    def test_no_expressions_or_untrusted_fields_in_run(self):
        # values reach scripts through env:, never through ${{ }} in run:
        for f in FILES:
            for n, text in run_blocks(f):
                self.assertIsNone(SINK_RE.search(text), f"{f.name}:{n}: {text.strip()}")

    def test_run_block_detection(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d, "w.yml")
            f.write_text("jobs:\n  a:\n    steps:\n      - run: |\n          echo ${{ x }}\n          y\n"
                         "        env:\n          K: ${{ v }}\n      - run: echo hi\n")
            blocks = run_blocks(f)
        self.assertEqual(len(blocks), 2)
        self.assertIn("${{ x }}", blocks[0][1])
        self.assertNotIn("K:", blocks[0][1])

    def test_exactly_one_checks_job(self):
        keys = names = 0
        for f in FILES:
            for _, line in code_lines(f):
                keys += bool(re.fullmatch(r"  checks:\s*", line))
                names += bool(re.fullmatch(r"    name:\s*[\"']?checks[\"']?\s*", line))
        self.assertEqual((keys, names), (1, 1))

    def test_checks_workflow_shape(self):
        text = "\n".join(l for _, l in code_lines(WORKFLOWS / "checks.yml"))
        self.assertIn("pull_request_target:", text)
        self.assertIn("runs-on: ubuntu-24.04", text)
        self.assertEqual(text.count("persist-credentials: false"), text.count("actions/checkout@"))
        self.assertEqual(text.count("actions/checkout@"), 1)
        for bad in ("git checkout", "git switch", "git worktree", "git clone"):
            self.assertNotIn(bad, text)
        # no `ref:` input: the checkout is the base branch, never the PR
        self.assertIsNone(re.search(r"^\s*ref:", text, re.M))
        self.assertIn("path: _base", text)
        self.assertIsNone(re.search(r"^\s*repository:", text, re.M))
        self.assertIsNone(re.search(r":\s*write\b", text))  # read-only token
        self.assertIn("timeout-minutes:", text)


if __name__ == "__main__":
    unittest.main()
