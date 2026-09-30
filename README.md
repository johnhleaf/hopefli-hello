# Hopefli Hello v0.1.6

Canonical product/SSO name: **Hello**.

CMS OIDC client:
- Name: `Hopefli Hello`
- Client ID: `hopefli-hello`
- System: `Hello`
- Redirect URI: `https://hello.hopefli.se/auth/callback`
- Groups: `hello-admin`, `hello-user`

Migration compatibility remains for legacy `intranet`, `hopefli-intranet` and `intranet-admin` claims.
The existing install root `/opt/hopefli-intranet` and database name are intentionally retained during migration to avoid breaking the installed instance.

## v0.1.7
- Fixar SSO-bootstrap där korrekt `active/access` felaktigt rapporterades som nekad åtkomst när lagring av `sso.json` gav Linux `PermissionError`.
- Separat intern `SSOAuthorizationError` används nu för claim-nekanden.
- SSO-konfiguration sparas i en dedikerad skrivbar katalog `shared/hello-config/` som ägs av appens UID 10001.

## v0.1.8 – webbaserade uppdateringar och GitHub

Admin kan från `/admin/system` ladda upp `.tar.gz`-releaser, testa/spara en fine-grained GitHub-token och köa synk av aktuell release. Privilegierade host-åtgärder körs av `hopefli-hello-worker.path/.service`; webbcontainern får inte Docker-socketen.

GitHub-konfiguration lagras i `/opt/hopefli-intranet/shared/hello-config/github.json`. Token återges aldrig i klartext i UI.
