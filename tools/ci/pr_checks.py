# SPDX-License-Identifier: Apache-2.0
# Derived from nissifield/snes2DHD (same author), relicensed Apache-2.0.
"""PR checks: DCO, card link, allowlist, protected paths, blobs, no added unsafe.

CI runs this from a checkout of the base branch, against a bare repo that only
holds the fetched PR head. Everything about the PR is read from git objects
(ls-tree, cat-file, diff); the PR is never checked out. Anything the PR
controls (paths, names, emails) is printed only through _q.
"""
import json
import os
import re
import secrets
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import card

MAINTAINERS_MD = Path(__file__).resolve().parents[2] / "MAINTAINERS.md"  # base branch copy
LOGIN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
# GitHub closing keywords, with an optional colon. The reference may be #N,
# owner/repo#N, or a full issue URL; prefix/url set means it is not a plain
# in-repo #N reference.
CLOSES_RE = re.compile(
    r"\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?):?[ \t]+"
    r"(?:(?P<prefix>[\w.-]+/[\w.-]+)#"
    r"|https://github\.com/(?P<url>[\w.-]+/[\w.-]+)/issues/"
    r"|#)"
    r"(?P<num>[0-9]+)",
    re.IGNORECASE)
# Keywords and attributes that enable or hide unsafe code, plus `#[path]` and
# `include!`, which pull in files the allowlist never sees. The real control is
# forbid(unsafe_code) in every crate root outside the three allowed crates.
UNSAFE_RE = re.compile(r"\b(?:unsafe|unsafe_code|no_mangle|export_name|link_section|global_asm)\b"
                       r"|#\s*!?\[\s*path\s*=|\binclude!")
SIGNOFF_RE = re.compile(r"[^<>]*<([^<>\s]+)>")  # exactly one <email>
AI_EMAILS = ("noreply@anthropic.com", "noreply@openai.com")
AI_SUFFIXES = ("[bot]@users.noreply.github.com", "+copilot@users.noreply.github.com", "@localhost")
REGULAR_MODES = ("100644", "100755")


def _q(s: str) -> str:
    """Untrusted text, escaped: no newline or control char survives, so no log
    line can start with attacker text. That alone is not enough: the runner also
    parses legacy `##[cmd]` anywhere in a line, so main() prints
    `::stop-commands::<random token>` before any other output."""
    return s.encode("unicode_escape").decode("ascii")


def _plain(s: str) -> str:
    """Untrusted text for a copy-paste fix line: keeps unicode, drops control chars."""
    return "".join(c if c.isprintable() else "?" for c in s)


def maintainers(path: Path) -> set[str]:
    """Lower-cased logins: every stripped line that is only a GitHub login
    (HTML comments, which may span lines, are ignored)."""
    text = re.sub(r"<!--.*?-->", "", Path(path).read_text(), flags=re.S)
    lines = (l.strip() for l in text.splitlines())
    return {l.lower() for l in lines if LOGIN_RE.fullmatch(l)}


def _is_ai(email: str) -> bool:
    e = email.lower().rstrip(".")
    return e in AI_EMAILS or e.endswith(AI_SUFFIXES)


def _git(git_dir: str, *args: str, raw: bool = False) -> str | bytes:
    # no global or in-tree attributes (attr.tree = the empty tree), so a PR's
    # .gitattributes can't change what we read; surrogateescape keeps odd path bytes
    out = subprocess.run(["git", "-c", "core.attributesFile=/dev/null",
                          "-c", "attr.tree=4b825dc642cb6eb9a060e54bf8d69288fbee4904",
                          "-C", git_dir, *args],
                         check=True, capture_output=True).stdout
    return out if raw else out.decode("utf-8", "surrogateescape")


def _trailers(git_dir: str, sha: str, key: str) -> list[str]:
    # %x00 separator: values are C strings, so a value can't fake a second one
    out = _git(git_dir, "log", "-1", f"--format=%(trailers:key={key},valueonly,unfold,separator=%x00)", sha)
    return out.removesuffix("\n").split("\0") if out != "\n" else []


def check_dco(git_dir: str, base_sha: str, head_sha: str) -> list[str]:
    errors = []
    for sha in _git(git_dir, "rev-list", f"{base_sha}..{head_sha}").split():
        who = f"{sha[:12]}: "
        name, _, email = _git(git_dir, "log", "-1", "--format=%an%x00%ae", sha).removesuffix("\n").partition("\0")
        fix = (f"\n  expected line: Signed-off-by: {_plain(name)} <{_plain(email)}>"
               f"\n  fix: git rebase --signoff {base_sha}, then git push --force-with-lease")
        signed = _trailers(git_dir, sha, "Signed-off-by")
        emails = [m[1].lower() for v in signed if (m := SIGNOFF_RE.fullmatch(v))]
        for v in signed:
            if any(_is_ai(e) for e in re.findall(r"<([^<>]*)>", v)):
                errors.append(f"{who}AI or bot identity in Signed-off-by: {_q(v)}"
                              "\n  fix: drop that line and sign off as the human author" + fix)
        if email.lower() not in emails:
            errors.append(f"{who}no Signed-off-by matches the author email {_q(email)}" + fix)
        for v in _trailers(git_dir, sha, "Co-authored-by"):
            co = re.findall(r"<([^<>]*)>", v)
            if not co or any(not _is_ai(e) and e.lower() not in emails for e in co):
                errors.append(f"{who}Co-authored-by {_q(v)} has no matching Signed-off-by"
                              f"\n  expected line: Signed-off-by: {_plain(v)}"
                              "\n  fix: the co-author signs off, or drop the Co-authored-by line")
    return errors


def check_pr_body(body: str) -> list[str]:
    closes = list(CLOSES_RE.finditer(body))
    if len(closes) != 1:
        return [f"expected exactly one issue-closing reference, found {len(closes)}"]
    if closes[0].group("prefix") or closes[0].group("url"):
        return [f"closing reference must be #N in this repo, not {_q(closes[0].group(0))}"]
    return []


def check_labels(labels: list[str]) -> list[str]:
    if "card:ready" not in labels:
        return ["linked issue is not labelled card:ready"]
    return []


def check_card_trust(issue: dict, maint: set[str], author: str) -> list[str]:
    login = ((issue.get("user") or {}).get("login") or "").lower()
    assignees = {(a.get("login") or "").lower() for a in issue.get("assignees") or []}
    if "pull_request" in issue:
        return ["linked issue is a pull request, not a card"]
    if issue.get("state") != "open" or login not in maint:
        return ["card not open or not authored by a maintainer"]
    if author.lower() not in assignees:
        return ["card is not assigned to the PR author"]
    return []


def check_paths(changes: list[tuple[str, str, str | None]], c: card.Card) -> list[str]:
    errors = []
    for status, path, old_path in changes:
        # R/C judge both paths: a rename is a delete of the old path plus an
        # add of the new one. Deny applies to every status.
        for p in [path] + ([old_path] if old_path else []):
            if card.is_sensitive(p):
                errors.append(f"{_q(p)}: needs two human maintainers (DESIGN 6.3)")
            elif card.is_protected(p):
                errors.append(f"protected: {_q(p)} needs a maintainer")
            if not any(card.glob_match(g, p) for g in c.allow):
                errors.append(f"outside allowlist: {_q(p)}")
            elif any(card.glob_match(g.lower(), p.lower()) for g in c.deny):  # deny is case-insensitive
                errors.append(f"denied by card: {_q(p)}")
    return errors


def changes_from_git(git_dir: str, base_sha: str,
                     head_sha: str) -> list[tuple[str, str, str | None]]:
    """(status, path, old_path) per change; R/C carry the old path too.
    Three-dot diffs against the merge base, so main moving on after the
    branch point doesn't add its own changes to the list."""
    out = _git(git_dir, "diff", "-z", "--name-status", "-M", "--no-textconv", "--no-ext-diff",
               f"{base_sha}...{head_sha}")
    fields = out.split("\0")
    changes = []
    i = 0
    while i < len(fields) and fields[i]:
        status = fields[i]
        i += 1
        code = status[0]
        if code in "RC":  # R100/C100: similarity score ignored
            old_path, path = fields[i], fields[i + 1]
            i += 2
            changes.append((code, path, old_path))
        elif code in "AMD":
            changes.append((code, fields[i], None))
            i += 1
        else:
            path = fields[i] if i < len(fields) else ""
            raise ValueError(f"unsupported status {_q(status)}: {_q(path)}")
    return changes


def check_files(git_dir: str, head_sha: str,
                changes: list[tuple[str, str, str | None]]) -> list[str]:
    """Every non-deleted path must be a regular file in head's tree (no
    symlinks, gitlinks) holding UTF-8 text without NUL. Blobs are read with
    cat-file; nothing is written to disk."""
    tree = {}
    for entry in _git(git_dir, "ls-tree", "-r", "-z", head_sha).split("\0"):
        if entry:
            meta, path = entry.split("\t", 1)
            mode, _, sha = meta.split(" ")
            tree[path] = (mode, sha)
    errors = []
    for status, path, _ in changes:
        if status == "D":
            continue
        # crafted trees can hold ".." entries, which the allowlist globs match
        if path.startswith("/") or {"", ".", "..", ".git"} & set(path.lower().split("/")):
            errors.append(f"unsafe path: {_q(path)}")
        elif path not in tree:
            errors.append(f"missing from head: {_q(path)}")
        elif tree[path][0] not in REGULAR_MODES:
            errors.append(f"not a regular file: {_q(path)}")
        else:
            blob = _git(git_dir, "cat-file", "blob", tree[path][1], raw=True)
            try:
                blob.decode("utf-8")
            except UnicodeDecodeError:
                blob = b"\0"
            if b"\0" in blob:
                errors.append(f"binary file needs a maintainer: {_q(path)}")
    return errors


def check_unsafe(git_dir: str, base_sha: str, head_sha: str) -> list[str]:
    """Added lines (and removed `unsafe_code` lints) in every file: include!
    can pull in any extension. --no-renames: a renamed file's lines count as added."""
    diff = _git(git_dir, "diff", "-U0", "--no-renames", "-a", "--no-textconv", "--no-ext-diff", "--no-color",
                f"{base_sha}...{head_sha}")
    path, hunk = "?", False
    errors = []
    for line in diff.split("\n"):
        # content lines start with + - space or \, so `diff --git` is always a header
        if line.startswith("diff --git "):
            path, hunk = line.removeprefix("diff --git "), False
        elif line.startswith("@@ "):
            hunk = True
        elif hunk and line.startswith("+") and UNSAFE_RE.search(line):
            errors.append(f"added `unsafe` needs a maintainer: {_q(path)}")
        elif hunk and line.startswith("-") and "unsafe_code" in line:
            errors.append(f"removed `unsafe_code` lint needs a maintainer: {_q(path)}")
    return list(dict.fromkeys(errors))  # one error per file and kind


def _fetch(url: str) -> dict:
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.load(resp)


def main(event_path: str, git_dir: str,
         fetch: Callable[[str], dict] | None = None) -> int:
    print(f"::stop-commands::{secrets.token_hex(16)}", flush=True)  # see _q
    if fetch is None:
        fetch = _fetch
    event = json.loads(Path(event_path).read_text())
    pr = event["pull_request"]
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    repo = f"{api}/repos/{os.environ['GITHUB_REPOSITORY']}"
    head_sha, base_sha = pr["head"]["sha"], pr["base"]["sha"]

    fetched = _git(git_dir, "rev-parse", "refs/pr/head").strip()
    if fetched != head_sha:
        errors = [f"fetched PR head is {_q(fetched)}, not the event's head {_q(head_sha)}"]
    else:
        errors = check_dco(git_dir, base_sha, head_sha)
        live = fetch(f"{repo}/pulls/{pr['number']}")
        maint = maintainers(MAINTAINERS_MD)
        # the login comes from the live PR, never from commit emails; the DCO-only
        # path also needs a head in this repo, so a fork can't borrow the identity
        author = (live.get("user") or {}).get("login") or ""
        same_repo = _repo_name(live, "head") is not None and _repo_name(live, "head") == _repo_name(live, "base")
        if author.lower() not in maint or not same_repo:
            errors += _check_outsider(git_dir, base_sha, head_sha, live, maint, author, fetch, repo)

    for error in errors:
        print(f"- {error}")
    return 1 if errors else 0


def _repo_name(live: dict, side: str) -> str | None:
    full = ((live.get(side) or {}).get("repo") or {}).get("full_name")  # repo is null once a fork is deleted
    return full.lower() if full else None


def _check_outsider(git_dir, base_sha, head_sha, live, maint, author, fetch, repo) -> list[str]:
    body = live.get("body") or ""
    errors = check_pr_body(body)
    if errors:
        return errors
    number = int(CLOSES_RE.search(body).group("num"))
    issue = fetch(f"{repo}/issues/{number}")
    labels = [l["name"] for l in issue.get("labels", [])]
    errors = check_card_trust(issue, maint, author) + check_labels(labels)
    c = card.parse_card(number, labels, issue.get("body") or "")
    try:
        changes = changes_from_git(git_dir, base_sha, head_sha)
    except (ValueError, subprocess.CalledProcessError) as e:
        return errors + [str(e)]
    return (errors + check_paths(changes, c) + check_files(git_dir, head_sha, changes)
            + check_unsafe(git_dir, base_sha, head_sha))


if __name__ == "__main__":
    git_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    raise SystemExit(main(os.environ["GITHUB_EVENT_PATH"], git_dir))
