#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${APP_DIR:-/opt/hopefli-intranet}"
INBOX="$APP_DIR/shared/update-inbox"
STATUS="$INBOX/status.json"
LOCK="$INBOX/.worker.lock"
mkdir -p "$INBOX"
exec 9>"$LOCK"
flock -n 9 || exit 0

write_status(){
  local state="$1" kind="$2" message="$3" extra="${4:-}"
  python3 - "$STATUS" "$state" "$kind" "$message" "$extra" <<'PY'
import json,sys,datetime,os
p,state,kind,msg,extra=sys.argv[1:]
data={"state":state,"kind":kind,"message":msg,"updated_at":datetime.datetime.now(datetime.timezone.utc).isoformat()}
if extra:
    try:data.update(json.loads(extra))
    except Exception:pass
tmp=p+".tmp"
with open(tmp,"w",encoding="utf-8") as f: json.dump(data,f,ensure_ascii=False,indent=2)
os.replace(tmp,p)
PY
  chmod 664 "$STATUS" || true
}

safe_tar(){
  python3 - "$1" <<'PY'
import sys,tarfile
p=sys.argv[1]
with tarfile.open(p,"r:gz") as t:
    names=t.getnames()
    for n in names:
        if n.startswith('/') or '..' in n.split('/'):
            raise SystemExit("unsafe archive path")
    roots={n.split('/')[0] for n in names if n}
    if len(roots)!=1: raise SystemExit("archive must contain one root directory")
    root=next(iter(roots))
    required={f"{root}/VERSION",f"{root}/docker-compose.yml",f"{root}/update.sh"}
    if not required.issubset(set(names)):
        raise SystemExit("archive missing required files")
PY
}

process_update(){
  local job="$1" archive
  archive=$(python3 - "$job" <<'PY'
import json,sys,os
j=json.load(open(sys.argv[1]))
print(os.path.basename(j["archive"]))
PY
)
  local path="$INBOX/$archive"
  [[ -f "$path" ]] || { write_status error update "Uppladdningsfilen saknas."; return 1; }
  write_status running update "Verifierar och installerar uppdateringen..."
  safe_tar "$path"
  if "$APP_DIR/current/update.sh" "$path" >"$INBOX/last-update.log" 2>&1; then
    local ver
    ver=$(curl -fsS "http://127.0.0.1:${APP_PORT:-8097}/health" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("version","ok"))' 2>/dev/null || echo ok)
    write_status success update "Uppdateringen installerades." "{\"version\":\"$ver\"}"
    rm -f "$path"
  else
    tail -n 30 "$INBOX/last-update.log" > "$INBOX/last-update-tail.log" || true
    write_status error update "Uppdateringen misslyckades. Se serverloggen för detaljer."
    return 1
  fi
}

process_github(){
  local job="$1"
  local cfg="$APP_DIR/shared/hello-config/github.json"
  [[ -f "$cfg" ]] || { write_status error github "GitHub är inte konfigurerat."; return 1; }
  local repo branch token
  repo=$(python3 - "$cfg" <<'PY'
import json,sys; print(json.load(open(sys.argv[1]))["repo"])
PY
)
  branch=$(python3 - "$cfg" <<'PY'
import json,sys; print(json.load(open(sys.argv[1])).get("branch","main"))
PY
)
  token=$(python3 - "$cfg" <<'PY'
import json,sys; print(json.load(open(sys.argv[1]))["token"])
PY
)
  [[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { write_status error github "Ogiltigt repository-format."; return 1; }
  [[ "$branch" =~ ^[A-Za-z0-9._/-]+$ ]] || { write_status error github "Ogiltigt branchnamn."; return 1; }
  write_status running github "Synkar aktuell Hello-release till GitHub..."
  local tmp askpass
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  askpass="$tmp/askpass.sh"
  cat >"$askpass" <<'ASK'
#!/bin/sh
case "$1" in
  *Username*) echo "x-access-token" ;;
  *) echo "$GITHUB_TOKEN" ;;
esac
ASK
  chmod 700 "$askpass"
  export GIT_ASKPASS="$askpass" GITHUB_TOKEN="$token" GIT_TERMINAL_PROMPT=0
  if ! git clone "https://github.com/$repo.git" "$tmp/repo" >"$INBOX/last-github.log" 2>&1; then
    write_status error github "Kunde inte klona GitHub-repot. Kontrollera repo och token."
    return 1
  fi
  git -C "$tmp/repo" config user.name "Hopefli Hello"
  git -C "$tmp/repo" config user.email "hello@hopefli.se"
  if git -C "$tmp/repo" show-ref --verify --quiet "refs/remotes/origin/$branch"; then
    git -C "$tmp/repo" checkout -B "$branch" "origin/$branch" >>"$INBOX/last-github.log" 2>&1
  else
    git -C "$tmp/repo" checkout -B "$branch" >>"$INBOX/last-github.log" 2>&1
  fi
  git -C "$tmp/repo" rm -r --ignore-unmatch . >>"$INBOX/last-github.log" 2>&1 || true
  cp -a "$APP_DIR/current/." "$tmp/repo/"
  find "$tmp/repo" -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
  find "$tmp/repo" -type f -name '*.pyc' -delete 2>/dev/null || true
  git -C "$tmp/repo" add -A
  if git -C "$tmp/repo" diff --cached --quiet; then
    write_status success github "GitHub är redan synkat med aktuell release."
    return 0
  fi
  local ver
  ver=$(cat "$APP_DIR/current/VERSION" 2>/dev/null || echo unknown)
  git -C "$tmp/repo" commit -m "Sync Hopefli Hello v$ver" >>"$INBOX/last-github.log" 2>&1
  if git -C "$tmp/repo" push -u origin "$branch" >>"$INBOX/last-github.log" 2>&1; then
    local sha
    sha=$(git -C "$tmp/repo" rev-parse --short HEAD)
    write_status success github "GitHub-synk klar." "{\"commit\":\"$sha\",\"repo\":\"$repo\",\"branch\":\"$branch\"}"
  else
    write_status error github "GitHub-synken misslyckades. Kontrollera tokenbehörigheter och repository."
    return 1
  fi
}

shopt -s nullglob
for job in "$INBOX"/*.job; do
  kind=$(python3 - "$job" <<'PY'
import json,sys; print(json.load(open(sys.argv[1])).get("kind",""))
PY
)
  mv "$job" "$job.running"
  case "$kind" in
    update) process_update "$job.running" || true ;;
    github) process_github "$job.running" || true ;;
    *) write_status error unknown "Okänd worker-order." ;;
  esac
  rm -f "$job.running"
done
