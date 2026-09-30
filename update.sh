#!/usr/bin/env bash
set -euo pipefail
ARCHIVE="${1:-}"
APP_DIR="${APP_DIR:-/opt/hopefli-intranet}"
[[ -n "$ARCHIVE" && -f "$ARCHIVE" ]] || { echo "Användning: sudo $0 /sökväg/hopefli-hello-vX.Y.Z.tar.gz"; exit 1; }
[[ $EUID -eq 0 ]] || { echo "Kör med sudo."; exit 1; }
command -v docker >/dev/null || { echo "Docker saknas."; exit 1; }
command -v curl >/dev/null || { echo "curl saknas."; exit 1; }
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

tar -xzf "$ARCHIVE" -C "$TMP"
ROOT=$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -n1)
[[ -f "$ROOT/VERSION" && -f "$ROOT/docker-compose.yml" ]] || { echo "Ogiltigt releasepaket."; exit 1; }
find "$ROOT" -type d -exec chmod 755 {} +
find "$ROOT" -type f -exec chmod 644 {} +
chmod 755 "$ROOT/install.sh" "$ROOT/update.sh" "$ROOT/scripts/hello-worker.sh" "$ROOT/scripts/github-sync.sh" 2>/dev/null || true
VERSION=$(cat "$ROOT/VERSION")
REL="$APP_DIR/releases/$VERSION"
[[ ! -e "$REL" ]] || { echo "Version $VERSION finns redan."; exit 1; }

# Testa koden innan aktivering.
docker build -t "hopefli-hello-test:$VERSION" "$ROOT" >/dev/null
docker run --rm -e PYTHONPYCACHEPREFIX=/tmp/pycache "hopefli-hello-test:$VERSION" python -m compileall -q /app/app

TS=$(date +%Y%m%d-%H%M%S)
PREV=$(readlink -f "$APP_DIR/current" || true)
mkdir -p "$APP_DIR/backups" "$APP_DIR/shared/hello-config" "$APP_DIR/shared/update-inbox"
tar -czf "$APP_DIR/backups/pre-update-$TS-config.tar.gz" -C "$APP_DIR" shared/.env shared/hello-config docker-compose.yml 2>/dev/null || true
cp -a "$ROOT" "$REL"
ln -sfn "$REL" "$APP_DIR/current"
cp "$REL/docker-compose.yml" "$APP_DIR/docker-compose.yml"

# Webbadministration: appen behöver skriva konfig/jobbfiler, men inte Docker-socket.
chown 10001:10001 "$APP_DIR/shared/hello-config" "$APP_DIR/shared/update-inbox"
chmod 700 "$APP_DIR/shared/hello-config"
chmod 750 "$APP_DIR/shared/update-inbox"

# Installera/uppdatera den privilegierade host-workern.
install -m 0755 "$REL/scripts/hello-worker.sh" /usr/local/sbin/hopefli-hello-worker
install -m 0644 "$REL/scripts/hopefli-hello-worker.service" /etc/systemd/system/hopefli-hello-worker.service
install -m 0644 "$REL/scripts/hopefli-hello-worker.path" /etc/systemd/system/hopefli-hello-worker.path
systemctl daemon-reload
systemctl enable --now hopefli-hello-worker.path >/dev/null

cd "$APP_DIR"
set -a; source "$APP_DIR/shared/.env"; set +a
if docker compose build app && docker compose up -d && sleep 3 && curl -fsS "http://127.0.0.1:${APP_PORT:-8097}/health" >/dev/null; then
  echo "Uppdaterad till $VERSION."
  echo "Webbuppdateringar är aktiverade: https://hello.hopefli.se/admin/system"
else
  echo "Uppdateringen misslyckades – återställer föregående release."
  if [[ -n "$PREV" && -d "$PREV" ]]; then
    ln -sfn "$PREV" "$APP_DIR/current"
    cp "$PREV/docker-compose.yml" "$APP_DIR/docker-compose.yml" 2>/dev/null || true
    docker compose build app || true
    docker compose up -d || true
  fi
  exit 1
fi
