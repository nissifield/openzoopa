# SPDX-License-Identifier: Apache-2.0
# Derived from nissifield/snes2DHD (same author), relicensed Apache-2.0.
"""Tests for tools/ci/pr_checks.py. DCO and main() run against real temp git repos + a stub fetch."""
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "ci"))

import card
import pr_checks

CARD_BODY = "### Files you may touch\n\ndocs/**\n\n" \
            "### Files you must not touch\n\ndocs/private/**\n"
ENV = {"GITHUB_API_URL": "https://api.test", "GITHUB_REPOSITORY": "o/r",
       "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
PR_URL = "https://api.test/repos/o/r/pulls/7"
ISSUE_URL = "https://api.test/repos/o/r/issues/12"
ME = ("Test User", "test@example.com")


def make_card(allow=("docs/**",), deny=("docs/private/**",)):
    body = "### Files you may touch\n\n" + "\n".join(allow) + \
           "\n\n### Files you must not touch\n\n" + "\n".join(deny) + "\n"
    return card.parse_card(12, ["card:ready"], body)


class PathTests(unittest.TestCase):
    def test_allow_glob_doublestar(self):
        c = make_card()
        self.assertEqual(pr_checks.check_paths([("A", "docs/a/b/c.md", None)], c), [])
        self.assertTrue(pr_checks.check_paths([("A", "src/x.py", None)], c))

    def test_path_with_space(self):
        c = make_card(allow=("docs/my dir/**",), deny=())
        self.assertEqual(
            pr_checks.check_paths([("A", "docs/my dir/file name.md", None)], c), [])

    def test_rename_into_allowlist_ok(self):
        c = make_card()
        self.assertEqual(pr_checks.check_paths([("R", "docs/new.md", "docs/old.md")], c), [])

    def test_rename_from_outside_allowlist_fails(self):
        self.assertTrue(pr_checks.check_paths([("R", "docs/new.md", "src/old.py")], make_card()))

    def test_rename_out_of_denied(self):
        self.assertTrue(pr_checks.check_paths([("R", "notes.md", "docs/private/x.md")], make_card()))

    def test_delete_outside_allowlist_fails(self):
        c = make_card()
        self.assertEqual(pr_checks.check_paths([("D", "docs/gone.md", None)], c), [])
        self.assertTrue(pr_checks.check_paths([("D", "src/gone.py", None)], c))

    def test_delete_denied_fails(self):
        errors = pr_checks.check_paths([("D", "docs/private/x.md", None)], make_card())
        self.assertTrue(any("denied" in e for e in errors))

    def test_protected_path_flagged(self):
        c = make_card(allow=("**",), deny=())
        errors = pr_checks.check_paths([("M", "tools/ci/pr_checks.py", None)], c)
        self.assertEqual(errors, ["protected: tools/ci/pr_checks.py needs a maintainer"])

    def test_rename_out_of_protected_path_fails(self):
        errors = pr_checks.check_paths([("R", "docs/x", "tools/x")], make_card())
        self.assertEqual(errors, ["protected: tools/x needs a maintainer", "outside allowlist: tools/x"])

    def test_deny_is_case_insensitive_allow_is_not(self):
        c = make_card()
        errors = pr_checks.check_paths([("A", "docs/PRIVATE/x.md", None)], c)
        self.assertEqual(errors, ["denied by card: docs/PRIVATE/x.md"])
        self.assertEqual(pr_checks.check_paths([("A", "DOCS/x.md", None)], c), ["outside allowlist: DOCS/x.md"])

    def test_sensitive_path_needs_two_maintainers(self):
        c = make_card(allow=("**",), deny=())
        errors = pr_checks.check_paths([("M", "crates/zoopa-crypto/src/lib.rs", None)], c)
        self.assertEqual(len(errors), 1)
        self.assertIn("needs two human maintainers (DESIGN 6.3)", errors[0])

    def test_body_closing_reference(self):
        self.assertEqual(pr_checks.check_pr_body("Closes #12\n"), [])
        self.assertEqual(len(pr_checks.check_pr_body("Closes #\u0661\u0662")), 1)  # non-ASCII digits
        for kw in ("fixes #12", "Resolved #12", "CLOSE #12", "Fixes: #12"):
            self.assertEqual(pr_checks.check_pr_body(f"{kw}\n"), [], kw)
        for bad in ("no reference", "Closes #12\nand fixes #99", "Closes o/r#12",
                    "fixes https://github.com/o/r/issues/12"):
            self.assertEqual(len(pr_checks.check_pr_body(bad)), 1, bad)

    def test_labels(self):
        self.assertEqual(pr_checks.check_labels(["card:ready"]), [])
        self.assertTrue(pr_checks.check_labels(["card:draft"]))
        self.assertTrue(pr_checks.check_labels(["card:claimed"]))

    def test_card_trust(self):
        maint = {"alice"}
        issue = {"state": "open", "user": {"login": "Alice"}, "assignees": [{"login": "Bob"}]}
        self.assertEqual(pr_checks.check_card_trust(issue, maint, "bob"), [])
        for bad in ({**issue, "state": "closed"},
                    {**issue, "user": {"login": "bob"}},
                    {**issue, "user": None},
                    {**issue, "pull_request": {}}):
            self.assertTrue(pr_checks.check_card_trust(bad, maint, "bob"), bad)
        for bad in ({**issue, "assignees": []}, {**issue, "assignees": [{"login": "carol"}]},
                    {k: v for k, v in issue.items() if k != "assignees"}):
            self.assertEqual(pr_checks.check_card_trust(bad, maint, "bob"),
                             ["card is not assigned to the PR author"])

    def test_maintainers_parsing(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "M.md")
            p.write_text("# Maintainers\n\n<!-- a comment -->\n  Alice  \nbob-1\n-bad\nnot a login\n")
            self.assertEqual(pr_checks.maintainers(p), {"alice", "bob-1"})

    def test_maintainers_ignores_multiline_html_comments(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, "M.md")
            p.write_text("# Maintainers\n<!-- notes\nmallory\n-->\nalice\n")
            self.assertEqual(pr_checks.maintainers(p), {"alice"})

    def test_real_maintainers_md(self):
        self.assertEqual(pr_checks.maintainers(pr_checks.MAINTAINERS_MD), {"nissifield"})

    def test_q_escapes_newlines_and_controls(self):
        q = pr_checks._q("a\n::error::b\x1b[0m ")
        self.assertNotIn("\n", q)
        self.assertTrue(q.isascii() and q.isprintable())


class RepoTests(unittest.TestCase):
    """A real git repo in a temp dir: base commit in setUp, head via helpers."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, ENV)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.repo = Path(self.tmp.name) / "pr"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.write_files({"README.md": "hi\n"})
        self.base = self.commit("base", sign=False)

    def git(self, *args, who=ME, input=None):
        return subprocess.run(
            ["git", "-C", str(self.repo), "-c", f"user.name={who[0]}", "-c", f"user.email={who[1]}",
             "-c", "commit.gpgsign=false", *args],
            check=True, capture_output=True, text=True, input=input).stdout.strip()

    def write_files(self, files):
        for name, content in files.items():
            p = self.repo / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content if isinstance(content, bytes) else content.encode())

    def commit(self, msg="c", who=ME, sign=True, trailers=()):
        """Commit everything. sign adds the author's own Signed-off-by."""
        lines = ([f"Signed-off-by: {who[0]} <{who[1]}>"] if sign else []) + list(trailers)
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-F", "-", who=who,
                 input=msg + ("\n\n" + "\n".join(lines) if lines else "") + "\n")
        return self.git("rev-parse", "HEAD")

    def dco(self, head=None):
        return pr_checks.check_dco(str(self.repo), self.base, head or self.git("rev-parse", "HEAD"))


class DcoTests(RepoTests):
    def test_signed_ok(self):
        self.write_files({"a": "1"})
        self.commit()
        self.assertEqual(self.dco(), [])

    def test_no_commits_ok(self):
        self.assertEqual(self.dco(), [])

    def test_missing_signoff(self):
        self.write_files({"a": "1"})
        self.commit(sign=False)
        errors = self.dco()
        self.assertEqual(len(errors), 1)
        self.assertIn("Signed-off-by: Test User <test@example.com>", errors[0])
        self.assertIn(f"git rebase --signoff {self.base}", errors[0])
        self.assertIn("git push --force-with-lease", errors[0])

    def test_signoff_in_middle_paragraph_not_a_trailer(self):
        self.write_files({"a": "1"})
        self.commit("subject\n\nSigned-off-by: Test User <test@example.com>\n\nmore text", sign=False)
        self.assertEqual(len(self.dco()), 1)

    def test_email_mismatch(self):
        self.write_files({"a": "1"})
        self.commit(sign=False, trailers=["Signed-off-by: Test User <other@example.com>"])
        errors = self.dco()
        self.assertEqual(len(errors), 1)
        self.assertIn("Signed-off-by: Test User <test@example.com>", errors[0])

    def test_email_case_insensitive(self):
        self.write_files({"a": "1"})
        self.commit(who=("Test User", "Test@Example.COM"), sign=False,
                    trailers=["Signed-off-by: Test User <test@example.com>"])
        self.assertEqual(self.dco(), [])

    def test_noreply_ok(self):
        self.write_files({"a": "1"})
        self.commit(who=("Dev", "123+dev@users.noreply.github.com"))
        self.assertEqual(self.dco(), [])

    def test_ai_signoff_rejected(self):
        for ai in ("agent@localhost", "noreply@anthropic.com", "x[bot]@users.noreply.github.com",
                   "NoReply@OpenAI.com", "Claude@LOCALHOST", "noreply@anthropic.com.",
                   "198982749+Copilot@users.noreply.github.com"):
            with self.subTest(ai=ai):
                self.write_files({"a": ai})
                self.commit(trailers=[f"Signed-off-by: Claude <{ai}>"])
                errors = self.dco()
                self.assertEqual(len(errors), 1, errors)
                self.assertIn("AI or bot identity", errors[0])
                self.assertIn("drop that line", errors[0])
                self.assertIn("Signed-off-by: Test User <test@example.com>", errors[0])
                self.git("reset", "-q", "--hard", self.base)

    def test_bot_author_cannot_pass(self):
        self.write_files({"a": "1"})
        who = ("x[bot]", "x[bot]@users.noreply.github.com")
        self.commit(who=who)
        self.assertTrue(self.dco())

    def test_ai_coauthor_accepted(self):
        self.write_files({"a": "1"})
        self.commit(trailers=["Co-authored-by: Claude Sonnet 5.5 <noreply@anthropic.com>",
                              "Assisted-by: Claude Sonnet 5.5"])
        self.assertEqual(self.dco(), [])

    def test_human_coauthor_needs_signoff(self):
        self.write_files({"a": "1"})
        self.commit(trailers=["Co-authored-by: Bob <bob@example.com>"])
        errors = self.dco()
        self.assertEqual(len(errors), 1)
        self.assertIn("Signed-off-by: Bob <bob@example.com>", errors[0])

    def test_human_coauthor_with_signoff_ok(self):
        self.write_files({"a": "1"})
        self.commit(trailers=["Co-authored-by: Bob <bob@example.com>",
                              "Signed-off-by: Bob <BOB@example.com>"])
        self.assertEqual(self.dco(), [])

    def test_one_error_per_bad_commit(self):
        self.write_files({"a": "1"})
        self.commit()
        self.write_files({"a": "2"})
        bad = self.commit(sign=False)
        self.write_files({"a": "3"})
        self.commit()
        errors = self.dco()
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith(bad[:12]))

    def test_merge_commit_without_signoff(self):
        self.git("checkout", "-q", "-b", "side")
        self.write_files({"side": "1"})
        self.commit()
        self.git("checkout", "-q", "-b", "topic", self.base)
        self.write_files({"topic": "1"})
        self.commit()
        self.git("merge", "-q", "--no-ff", "-m", "Merge side", "side")
        merge = self.git("rev-parse", "HEAD")
        errors = self.dco()
        self.assertEqual(len(errors), 1)
        self.assertTrue(errors[0].startswith(merge[:12]))


class ChangesFromGitTests(RepoTests):
    def test_changes_from_git_statuses(self):
        self.write_files({"mod.md": "v1\n", "del.md": "bye\n", "ren.md": "same\n"})
        self.base = self.commit("base2")
        self.write_files({"mod.md": "v2\n", "new.md": "new\n"})
        (self.repo / "del.md").unlink()
        self.git("mv", "ren.md", "renamed.md")
        head = self.commit("head")
        changes = pr_checks.changes_from_git(str(self.repo), self.base, head)
        self.assertEqual(sorted(changes), sorted([
            ("M", "mod.md", None),
            ("D", "del.md", None),
            ("A", "new.md", None),
            ("R", "renamed.md", "ren.md"),
        ]))

    def test_changes_from_git_type_change_unsupported(self):
        self.write_files({"link.md": "was a file\n"})
        self.base = self.commit("base2")
        (self.repo / "link.md").unlink()
        (self.repo / "link.md").symlink_to("README.md")
        head = self.commit("head")
        with self.assertRaisesRegex(ValueError, "unsupported status T: link.md"):
            pr_checks.changes_from_git(str(self.repo), self.base, head)

    def test_three_dot_ignores_base_changes(self):
        self.git("checkout", "-qb", "feature")
        self.write_files({"docs/x.md": "branch\n"})
        head = self.commit("head")
        self.git("checkout", "-q", "main")
        self.write_files({"README.md": "main moved on\n"})
        self.commit("main2")
        changes = pr_checks.changes_from_git(str(self.repo), self.base, head)
        self.assertEqual(changes, [("A", "docs/x.md", None)])


class MainTests(RepoTests):
    def setUp(self):
        super().setUp()
        maint = Path(self.tmp.name) / "MAINTAINERS.md"
        maint.write_text("# Maintainers\n\nalice\n")
        patcher = mock.patch.object(pr_checks, "MAINTAINERS_MD", maint)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_main(self, *, login="bob", body="Closes #12\n", labels=("card:ready",), state="open",
                 issue_login="alice", is_pr=False, head=None, event_head=None, fetched_body=None,
                 head_repo="o/r", assignees=None):
        """Point refs/pr/head at HEAD (or `head`) and run the gate; returns (rc, output lines
        after the stop-commands line). assignees defaults to the PR author."""
        assigned = [login] if assignees is None else assignees
        head = head or self.git("rev-parse", "HEAD")
        self.git("update-ref", "refs/pr/head", head)
        event = {"pull_request": {"number": 7, "base": {"sha": self.base},
                                  "head": {"sha": event_head or head}}}
        event_path = Path(self.tmp.name) / "event.json"
        event_path.write_text(json.dumps(event))
        issue = {"labels": [{"name": n} for n in labels], "body": CARD_BODY,
                 "state": state, "user": {"login": issue_login},
                 "assignees": [{"login": a} for a in assigned]}
        if is_pr:
            issue["pull_request"] = {}
        payload = {PR_URL: {"body": body if fetched_body is None else fetched_body,
                            "user": {"login": login},
                            "base": {"repo": {"full_name": "o/r"}},
                            "head": {"repo": head_repo and {"full_name": head_repo}}},
                   ISSUE_URL: issue}
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = pr_checks.main(str(event_path), str(self.repo), fetch=payload.__getitem__)
        self.stop_line, *rest = buf.getvalue().splitlines()
        self.assertRegex(self.stop_line, r"^::stop-commands::[0-9a-f]{32}$")
        return rc, rest

    def add(self, files, **kw):
        self.write_files(files)
        self.commit(**kw)

    # maintainer PRs: DCO only (the stub has no issue URL, so any issue fetch would raise)
    def test_maintainer_gets_dco_only(self):
        self.add({".github/workflows/x.yml": "a: 1\n", "crates/zoopa-crypto/src/lib.rs": "unsafe {}\n",
                  "bin": b"\xff\x00"})
        self.assertEqual(self.run_main(login="Alice", body="")[0], 0)

    def test_maintainer_still_needs_dco(self):
        self.add({"docs/x.md": "hi\n"}, sign=False)
        rc, out = self.run_main(login="alice")
        self.assertEqual(rc, 1)
        self.assertIn("no Signed-off-by", out[0])

    def test_maintainer_by_commit_email_does_not_count(self):
        self.add({".github/x.yml": "a: 1\n"}, who=("alice", "alice@users.noreply.github.com"))
        self.assertEqual(self.run_main(login="mallory", body="")[0], 1)

    # outsider PRs
    def test_outsider_happy_path(self):
        self.add({"docs/x.md": "hello\n"})
        self.assertEqual(self.run_main(), (0, []))

    def test_outsider_without_card_fails(self):
        self.add({"docs/x.md": "hello\n"})
        rc, out = self.run_main(body="no reference")
        self.assertEqual(rc, 1)
        self.assertIn("exactly one issue-closing reference", out[0])

    def test_outsider_body_comes_from_live_pr(self):
        self.add({"docs/x.md": "hello\n"})
        self.assertEqual(self.run_main(body="no reference", fetched_body="Closes #12")[0], 0)
        self.assertEqual(self.run_main(body="Closes #12", fetched_body="")[0], 1)

    def test_outsider_needs_dco(self):
        self.add({"docs/x.md": "hello\n"}, sign=False)
        self.assertEqual(self.run_main()[0], 1)

    def test_card_trust_failures(self):
        self.add({"docs/x.md": "hello\n"})
        for kw in ({"issue_login": "mallory"}, {"labels": ("card:draft",)}, {"state": "closed"},
                   {"is_pr": True}):
            with self.subTest(kw=kw):
                self.assertEqual(self.run_main(**kw)[0], 1)

    def test_card_must_be_assigned_to_pr_author(self):
        self.add({"docs/x.md": "hello\n"})
        for assignees in ([], ["carol"]):
            rc, out = self.run_main(assignees=assignees)
            self.assertEqual((rc, out), (1, ["- card is not assigned to the PR author"]))

    def test_maintainer_with_fork_head_is_an_outsider(self):
        self.add({".github/x.yml": "a: 1\n"})
        for head_repo in ("evil/r", None):
            with self.subTest(head_repo=head_repo):
                rc, out = self.run_main(login="alice", body="", head_repo=head_repo)
                self.assertEqual(rc, 1)
                self.assertIn("- expected exactly one issue-closing reference, found 0", out)
        self.assertEqual(self.run_main(login="alice", body="", head_repo="O/R")[0], 0)

    def test_stop_commands_token_is_first_output_and_random(self):
        self.add({"docs/x.md": "hello\n"})
        tokens = set()
        for _ in range(2):
            self.run_main()  # asserts the first line is ::stop-commands::<32 hex>
            tokens.add(self.stop_line)
        self.assertEqual(len(tokens), 2)

    def test_disallowed_and_denied_files_fail(self):
        for path in ("src/x.py", "docs/private/x.md"):
            with self.subTest(path=path):
                self.add({path: "x\n"})
                rc, out = self.run_main()
                self.assertEqual(rc, 1)
                want = "outside allowlist: " if path == "src/x.py" else "denied by card: "
                self.assertEqual(out, [f"- {want}{path}"])
                self.git("reset", "-q", "--hard", self.base)

    def test_protected_path_fails(self):
        self.write_files({"CONTRIBUTING.md": "x\n"})
        self.commit()
        rc, out = self.run_main()
        self.assertEqual(rc, 1)
        self.assertTrue(any("protected: CONTRIBUTING.md" in l for l in out))

    def test_sensitive_path_fails_with_two_maintainers_message(self):
        self.add({"crates/zoopa-policy/src/lib.rs": "x\n"})
        rc, out = self.run_main()
        self.assertEqual(rc, 1)
        self.assertTrue(any("needs two human maintainers" in l for l in out), out)

    def test_symlink_fails(self):
        (self.repo / "docs").mkdir()
        (self.repo / "docs" / "link.md").symlink_to("../README.md")
        self.commit()
        rc, out = self.run_main()
        self.assertEqual(rc, 1)
        self.assertTrue(any("not a regular file: docs/link.md" in l for l in out), out)

    def test_gitlink_fails(self):
        self.git("update-index", "--add", "--cacheinfo", f"160000,{self.base},docs/lib")
        self.git("commit", "-q", "-m", "head\n\nSigned-off-by: Test User <test@example.com>")
        rc, out = self.run_main()
        self.assertEqual(rc, 1)
        self.assertTrue(any("not a regular file: docs/lib" in l for l in out), out)

    def test_binary_and_nul_files_fail(self):
        for name, data in (("x.bin", b"\xff\xfe\x01"), ("y.md", b"text\x00more")):
            with self.subTest(name=name):
                self.add({f"docs/{name}": data})
                rc, out = self.run_main()
                self.assertEqual(rc, 1)
                self.assertTrue(any(f"binary file needs a maintainer: docs/{name}" in l for l in out), out)
                self.git("reset", "-q", "--hard", self.base)

    def test_added_unsafe_fails(self):
        for content in ("unsafe { x }\n", "#![allow(unsafe_code)]\n", "++ unsafe\n", "a\n-- b unsafe fn\n",
                        "#[path = \"../crates/x.rs\"]\nmod x;\n", "#![ path=\"x.rs\" ]\n", "include!(\"x.rs\");\n",
                        "#[no_mangle]\n", "#[export_name = \"f\"]\n", "#[link_section = \".s\"]\n",
                        "global_asm!(\"nop\");\n"):
            with self.subTest(content=content):
                self.add({"docs/x.md": content})
                rc, out = self.run_main()
                self.assertEqual(rc, 1)
                self.assertTrue(any("added `unsafe` needs a maintainer" in l for l in out), out)
                self.git("reset", "-q", "--hard", self.base)

    def test_rename_cannot_hide_unsafe(self):
        self.add({"docs/a.md": "unsafe { x }\n"})
        self.base = self.git("rev-parse", "HEAD")
        self.git("mv", "docs/a.md", "docs/b.md")
        self.commit()
        rc, out = self.run_main()
        self.assertEqual(rc, 1)
        self.assertTrue(any("added `unsafe` needs a maintainer: " in l for l in out), out)

    def test_removed_unsafe_code_lint_fails(self):
        self.add({"docs/lib.md": "#![forbid(unsafe_code)]\nfn main() {}\n"})
        self.base = self.git("rev-parse", "HEAD")
        self.add({"docs/lib.md": "fn main() {}\n"})
        rc, out = self.run_main()
        self.assertEqual(rc, 1)
        self.assertEqual(out, ["- removed `unsafe_code` lint needs a maintainer: a/docs/lib.md b/docs/lib.md"])

    def test_include_str_and_plain_words_not_flagged(self):
        self.add({"docs/x.md": "include_str!(\"a\") safe path = 1 unsafety\n"})
        self.assertEqual(self.run_main(), (0, []))

    def test_dot_git_component_any_case_rejected(self):
        blob = self.git("hash-object", "-w", "--stdin", input="x\n")
        readme = self.git("rev-parse", f"{self.base}:README.md")
        inner = self.git("mktree", input=f"100644 blob {blob}\t.GIT\n")
        top = self.git("mktree", input=f"100644 blob {readme}\tREADME.md\n040000 tree {inner}\tdocs\n")
        head = self.git("commit-tree", top, "-p", self.base, "-m", "x\n\nSigned-off-by: Test User <test@example.com>")
        rc, out = self.run_main(head=head)
        self.assertEqual(rc, 1)
        self.assertTrue(any("unsafe path: docs/.GIT" in l for l in out), out)

    def test_existing_unsafe_not_flagged(self):
        self.add({"docs/x.md": "unsafe old\nline\n"})
        self.base = self.git("rev-parse", "HEAD")
        self.add({"docs/x.md": "unsafe old\nchanged\n"})
        self.assertEqual(self.run_main(), (0, []))

    def test_head_mismatch_fails(self):
        self.add({"docs/x.md": "hello\n"})
        rc, out = self.run_main(event_head=self.base)
        self.assertEqual(rc, 1)
        self.assertIn("not the event's head", out[0])

    def test_missing_head_ref_fails_closed(self):
        self.add({"docs/x.md": "hello\n"})
        self.run_main()
        self.git("update-ref", "-d", "refs/pr/head")
        with self.assertRaises(subprocess.CalledProcessError), contextlib.redirect_stdout(io.StringIO()):
            pr_checks.main(str(Path(self.tmp.name) / "event.json"), str(self.repo), fetch=lambda u: {})

    def test_attributes_cannot_hide_content(self):
        # a PR .gitattributes marking files -diff must not hide an added unsafe line
        self.add({".gitattributes": "docs/* -diff\n", "docs/x.md": "unsafe {}\n"})
        self.assertEqual(self.run_main()[0], 1)

    def test_output_cannot_start_a_workflow_command(self):
        evil = "docs/a\n::error::pwned\n.md"
        self.add({evil: "x\n", "src/b\n::warning::x": "y\n"})
        rc, out = self.run_main()
        self.assertEqual(rc, 1)
        self.assertTrue(out)
        for line in out:
            self.assertTrue(line.startswith(("- ", "  ")), line)
            self.assertFalse(line.lstrip().startswith("::"), line)


if __name__ == "__main__":
    unittest.main()
