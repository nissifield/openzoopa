#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Derived from nissifield/snes2DHD (same author), relicensed Apache-2.0.
# Apply openzoopa repo settings (docs/adr/0013-contribution-model.md). Idempotent;
# run by a repo admin with `gh` logged in. Not run by CI.
set -euo pipefail
R="${1:-nissifield/openzoopa}"
cd "$(dirname "$0")/../.."

# expect ENDPOINT JQ_EXPR MESSAGE: read the setting back; exit 1 unless JQ_EXPR is true.
expect() {
  if [ "$(gh api "$1" --jq "$2")" != "true" ]; then
    echo "settings mismatch: $3" >&2
    exit 1
  fi
}

# Labels first: the issue forms apply them.
python3 -I -c 'import json; [print(l["name"], l["color"], l["description"], sep="\t") for l in json.load(open(".github/labels.json"))]' |
while IFS=$'\t' read -r name color desc; do
  gh label create "$name" --repo "$R" --color "$color" --description "$desc" --force
done

# Squash only; COMMIT_MESSAGES (not PR_BODY) keeps Signed-off-by lines on main.
gh api -X PATCH "repos/$R" --silent \
  -F has_discussions=true -F has_wiki=false -F has_projects=false \
  -F allow_auto_merge=false -F delete_branch_on_merge=true \
  -F allow_squash_merge=true -F allow_merge_commit=false -F allow_rebase_merge=false \
  -f squash_merge_commit_title=PR_TITLE -f squash_merge_commit_message=COMMIT_MESSAGES \
  -F web_commit_signoff_required=true \
  -f description="Self-hosted Zero Trust Network Access (ZTNA) in Rust. Design phase: no release, not audited."
gh api -X PATCH "repos/$R" --silent --input - <<'JSON'
{"security_and_analysis": {"secret_scanning": {"status": "enabled"},
                           "secret_scanning_push_protection": {"status": "enabled"}}}
JSON
gh api -X PUT "repos/$R/private-vulnerability-reporting" --silent
gh api -X PUT "repos/$R/topics" --silent --input - <<'JSON'
{"names": ["zero-trust", "ztna", "rust", "quic", "rustls", "self-hosted", "network-security"]}
JSON

# Actions: GitHub-owned actions only, pinned by full SHA (checks.yml already is),
# read-only default token, workflows can't approve PRs, and fork `pull_request`
# workflows wait for approval for every outside contributor (the
# pull_request_target `checks` gate only reads PR data).
gh api -X PUT "repos/$R/actions/permissions" --silent --input - <<'JSON'
{"enabled": true, "allowed_actions": "selected", "sha_pinning_required": true}
JSON
gh api -X PUT "repos/$R/actions/permissions/selected-actions" --silent --input - <<'JSON'
{"github_owned_allowed": true, "verified_allowed": false, "patterns_allowed": []}
JSON
gh api -X PUT "repos/$R/actions/permissions/workflow" --silent --input - <<'JSON'
{"default_workflow_permissions": "read", "can_approve_pull_request_reviews": false}
JSON
gh api -X PUT "repos/$R/actions/permissions/fork-pr-contributor-approval" --silent --input - <<'JSON'
{"approval_policy": "all_external_contributors"}
JSON
expect "repos/$R/actions/permissions" '.allowed_actions == "selected"' \
  "allowed_actions is not 'selected'"
expect "repos/$R/actions/permissions" '.sha_pinning_required == true' \
  "SHA pinning is not required; set it by hand in Settings, Actions, General, then re-run"
expect "repos/$R/actions/permissions/selected-actions" '.github_owned_allowed == true' \
  "GitHub-owned actions are not allowed"
expect "repos/$R/actions/permissions/fork-pr-contributor-approval" \
  '.approval_policy == "all_external_contributors"' "fork PR approval is not 'all_external_contributors'"

# From 2026-12-02 GitHub blocks pull_request_target workflows by default on public
# repos. Allow that event for checks.yml only (allowed_events is an allowlist).
# shortcut: unverified whether a path-scoped policy overrides the default; the
# readback fails safe and the closing message asks for a fork-PR liveness check.
POLICY_FAIL="the pull_request_target policy for checks.yml is not set; add it by hand in Settings, Actions, Policies, then re-run"
policy=$(cat <<'JSON'
{"name": "allow-checks-prt", "enforcement": "active",
 "conditions": {"workflow_path": {"include": [".github/workflows/checks.yml"], "exclude": []}},
 "rules": [{"type": "restrict_action_events", "parameters": {"allowed_events": ["pull_request_target"]}}]}
JSON
)
pid=$(gh api --paginate "repos/$R/actions/policies" --jq '(.policies? // .)[]|select(.name=="allow-checks-prt").id') ||
  { echo "settings mismatch: $POLICY_FAIL" >&2; exit 1; }
if [ -n "$pid" ]; then
  printf '%s' "$policy" | gh api -X PUT "repos/$R/actions/policies/$pid" --silent --input - ||
    { echo "settings mismatch: $POLICY_FAIL" >&2; exit 1; }
else
  printf '%s' "$policy" | gh api -X POST "repos/$R/actions/policies" --silent --input - ||
    { echo "settings mismatch: $POLICY_FAIL" >&2; exit 1; }
fi
# The list endpoint omits conditions and rules: read the single policy back.
pid=$(gh api --paginate "repos/$R/actions/policies" --jq '(.policies? // .)[]|select(.name=="allow-checks-prt").id') ||
  { echo "settings mismatch: $POLICY_FAIL" >&2; exit 1; }
[ "$(printf '%s\n' "$pid" | grep -c .)" -eq 1 ] || { echo "settings mismatch: $POLICY_FAIL" >&2; exit 1; }
expect "repos/$R/actions/policies/$pid" \
  '.enforcement=="active" and .conditions.workflow_path.include==[".github/workflows/checks.yml"] and any(.rules[]; .type=="restrict_action_events" and .parameters.allowed_events==["pull_request_target"])' \
  "$POLICY_FAIL"

# Order matters: a required check that no workflow on main reports stays
# pending forever and blocks every merge. Refuse until checks.yml is on main.
if ! gh api "repos/$R/contents/.github/workflows/checks.yml?ref=main" --silent >/dev/null 2>&1; then
  echo "refusing to protect main: .github/workflows/checks.yml is not on $R main yet." >&2
  echo "merge the checks gate first (gh pr merge --squash --admin), then re-run." >&2
  exit 1
fi

# Branch protection. app_id 15368 = GitHub Actions, so only the real workflow
# can satisfy `checks`. One maintainer: any review count above 0, code-owner
# reviews or last-push approval would block the maintainer's own PRs without --admin, and
# enforce_admins=false keeps the admin merge as the fix for a broken gate.
# When MAINTAINERS.md lists 2 humans, flip to: dismiss_stale_reviews true,
# require_code_owner_reviews true, require_last_push_approval true,
# required_approving_review_count 1.
gh api -X PUT "repos/$R/branches/main/protection" --silent --input - <<'JSON'
{
  "required_status_checks": {"strict": false, "checks": [{"context": "checks", "app_id": 15368}]},
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": false,
    "require_code_owner_reviews": false,
    "require_last_push_approval": false,
    "required_approving_review_count": 0
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
expect "repos/$R/branches/main/protection" \
  '.required_status_checks.checks[0].app_id == 15368' "the required check is not from GitHub Actions (app 15368)"

cat <<MSG
applied to $R. By hand:
- Discussions: keep the categories Announcements, Q&A and Ideas.
- Account: 2FA recovery codes saved, and a second passkey.
- Optional: set the web-commit email to your noreply address (Settings, Emails).
- Dependabot alerts: enable once Cargo.lock exists.
- Confirm with read-only calls: gh api repos/$R, repos/$R/actions/permissions,
  repos/$R/branches/main/protection.
- After 2026-12-02, open a test fork PR and confirm \`checks\` runs; check the policy
  insights for blocked checks.yml runs.
- Before merging an outside PR, verify the required check came from this workflow (a fork's
  pull_request job can also be named \`checks\`); this must print true:
  gh pr checks N -R $R --json name,event,state --jq '[.[]|select(.name=="checks")]|length==1 and .[0].event=="pull_request_target" and .[0].state=="SUCCESS"'
  (the gh field values are unverified: confirm them once on a real PR.)
- Merge outside PRs with: gh pr merge N --squash --match-head-commit <full 40-char reviewed sha>
MSG
