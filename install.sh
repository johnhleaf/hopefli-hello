#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/hopefli-intranet}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="$(cat "$SRC_DIR/VERSION")"
REL="$APP_DIR/releases/$VERSION"

if [[ $EUID -ne 0 ]]; then echo "Kör med sudo: sudo ./install.sh"; exit 1; fi
command -v docker >/dev/null || { echo "Docker saknas."; exit 1; }
docker compose version >/dev/null || { echo "Docker Compose-plugin saknas."; exit 1; }

mkdir -p "$APP_DIR/releases" "$APP_DIR/shared/postgres" "$APP_DIR/shared/redis" "$APP_DIR/shared/hello-config" "$APP_DIR/shared/update-inbox" "$APP_DIR/backups"
if [[ -e "$REL" ]]; then echo "Release $VERSION finns redan i $REL"; exit 1; fi
cp -a "$SRC_DIR" "$REL"
rm -rf "$REL/.git" || true

if [[ ! -f "$APP_DIR/shared/.env" ]]; then
  cp "$REL/.env.example" "$APP_DIR/shared/.env"
  SECRET=$(openssl rand -hex 32)
  DBPASS=$(openssl rand -hex 24)
  sed -i "s/SECRET_KEY=CHANGE_ME_GENERATED/SECRET_KEY=$SECRET/" "$APP_DIR/shared/.env"
  sed -i "s/CHANGE_ME_DB_PASSWORD/$DBPASS/" "$APP_DIR/shared/.env"
  echo "POSTGRES_PASSWORD=$DBPASS" >> "$APP_DIR/shared/.env"
fi

ln -sfn "$REL" "$APP_DIR/current"
cp "$REL/docker-compose.yml" "$APP_DIR/docker-compose.yml"
chown 10001:10001 "$APP_DIR/shared/hello-config" "$APP_DIR/shared/update-inbox"
chmod 700 "$APP_DIR/shared/hello-config"
chmod 750 "$APP_DIR/shared/update-inbox"
install -m 0755 "$REL/scripts/hello-worker.sh" /usr/local/sbin/hopefli-hello-worker
install -m 0644 "$REL/scripts/hopefli-hello-worker.service" /etc/systemd/system/hopefli-hello-worker.service
install -m 0644 "$REL/scripts/hopefli-hello-worker.path" /etc/systemd/system/hopefli-hello-worker.path
systemctl daemon-reload
systemctl enable --now hopefli-hello-worker.path >/dev/null
cd "$APP_DIR"
set -a; source "$APP_DIR/shared/.env"; set +a
docker compose build app
docker compose up -d
sleep 3
if curl -fsS "http://127.0.0.1:${APP_PORT:-8097}/health" >/dev/null; then
  echo
  echo "Hopefli Hello $VERSION är installerat."
  echo "URL: ${APP_BASE_URL:-https://intra.hopefli.se}"
  echo "Lokal port: ${APP_PORT:-8097}"
  echo "Nästa steg: redigera $APP_DIR/shared/.env och sätt HOPEFLI_SSO_CLIENT_SECRET."
  echo "CMS redirect URI ska vara: ${HOPEFLI_SSO_REDIRECT_URI:-https://intra.hopefli.se/auth/callback}"
else
  echo "Healthcheck misslyckades. Kör: cd $APP_DIR && docker compose logs app --tail=100"
  exit 1
fi
