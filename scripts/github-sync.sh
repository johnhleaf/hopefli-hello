#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DIR:-/opt/hopefli-intranet}"
source "$APP_DIR/shared/.env"
[[ -n "${GITHUB_REPO:-}" ]] || { echo "Sätt GITHUB_REPO i $APP_DIR/shared/.env, ex git@github.com:org/hopefli-intranet.git"; exit 1; }
BRANCH="${GITHUB_BRANCH:-main}"
cd "$APP_DIR/current"
command -v git >/dev/null || { echo "git saknas"; exit 1; }
if [[ ! -d .git ]]; then git init; git remote add origin "$GITHUB_REPO"; else git remote set-url origin "$GITHUB_REPO"; fi
python -m compileall -q app
VERSION=$(cat VERSION)
git add -A
git diff --cached --quiet && { echo "Inga ändringar att synka."; exit 0; }
git commit -m "Release $VERSION"
git branch -M "$BRANCH"
git push -u origin "$BRANCH"
echo "Synkat release $VERSION till $GITHUB_REPO ($BRANCH)."
