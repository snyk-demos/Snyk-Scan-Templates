#!/usr/bin/env bash
# Write the scan report to the run summary and, optionally, one sticky PR
# comment that is edited in place on later pushes.
# Env: TITLE FILE EXIT_CODE MARKER PR_COMMENT GH_TOKEN GH_REPO
#      ERROR_MESSAGE ERROR_HINT (from classify.py)
set -euo pipefail

if [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ]; then
  RENDER_REF=$(jq -r '.pull_request.head.sha // empty' "$GITHUB_EVENT_PATH")
fi
RENDER_REF="${RENDER_REF:-${GITHUB_SHA:-}}"

RENDER_TITLE="$TITLE" RENDER_FILE="$FILE" RENDER_JSON="${FILE%.sarif}.json" \
  RENDER_EXIT="$EXIT_CODE" RENDER_OUT=report.md RENDER_REF="$RENDER_REF" \
  python3 "$(dirname "$0")/render.py"
cat report.md >> "$GITHUB_STEP_SUMMARY"

[ "${PR_COMMENT}" = "true" ] || exit 0

# On pull_request events the ref name is "N/merge", useless for a head lookup,
# so read the PR number from the event payload instead.
if [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ]; then
  pr=$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH")
else
  pr=$(gh pr list --head "$GITHUB_REF_NAME" --state open --json number --jq '.[0].number // empty')
fi
if [ -z "$pr" ]; then
  echo "::notice::No open PR for this ref. Run summary only."
  exit 0
fi

MARK="<!-- ${MARKER} -->"
# Byte-safe truncation: a raw cut can tear an emoji into invalid UTF-8.
{ echo "$MARK"
  python3 -c "import sys; sys.stdout.write(open('report.md','rb').read()[:60000].decode('utf-8','ignore'))"
} > comment.md

# --paginate so the sticky comment is found on PRs with over 100 comments.
id=$(gh api --paginate "repos/${GH_REPO}/issues/${pr}/comments" \
       --jq ".[] | select((.body // \"\") | startswith(\"$MARK\")) | .id" | head -n1)
if [ -n "$id" ]; then
  gh api -X PATCH "repos/${GH_REPO}/issues/comments/${id}" -F body=@comment.md > /dev/null
else
  gh api "repos/${GH_REPO}/issues/${pr}/comments" -F body=@comment.md > /dev/null
fi
