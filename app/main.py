import base64
import hashlib
import json
import logging
import os
import secrets
import tarfile
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import requests
from authlib.jose import JsonWebKey, jwt
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from redis import Redis
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, create_engine, desc
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

Base = declarative_base()
logger = logging.getLogger("hopefli-hello")


class ShadowUser(Base):
    __tablename__ = "shadow_users"
    id = Column(Integer, primary_key=True)
    cms_sub = Column(String(255), unique=True, nullable=False, index=True)
    name = Column(String(255), nullable=False)
    email = Column(String(255), nullable=True)
    role = Column(String(32), nullable=False, default="user")
    groups_json = Column(Text, nullable=False, default="[]")
    active = Column(Boolean, nullable=False, default=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class NewsItem(Base):
    __tablename__ = "news_items"
    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    important = Column(Boolean, nullable=False, default=False)
    published_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


SSO_CONFIG_PATH = Path(os.environ.get("SSO_CONFIG_PATH", "/config/sso.json"))


class SSOAuthorizationError(Exception):
    """Expected authorization denial from validated CMS claims."""



def _read_sso_file() -> dict:
    try:
        if SSO_CONFIG_PATH.exists():
            data = json.loads(SSO_CONFIG_PATH.read_text())
            return data if isinstance(data, dict) else {}
    except Exception:
        logger.exception("Could not read SSO config file")
    return {}


def _sso_value(name: str, default=None):
    file_cfg = _read_sso_file()
    mapping = {
        "HOPEFLI_SSO_ISSUER": "issuer",
        "HOPEFLI_SSO_CLIENT_ID": "client_id",
        "HOPEFLI_SSO_CLIENT_SECRET": "client_secret",
        "HOPEFLI_SSO_REDIRECT_URI": "redirect_uri",
    }
    key = mapping.get(name)
    if key and file_cfg.get(key):
        return file_cfg[key]
    return os.environ.get(name, default)


def _write_sso_file(config: dict):
    SSO_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = SSO_CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(SSO_CONFIG_PATH)


def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
        SESSION_TYPE="redis",
        SESSION_REDIS=Redis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0")),
        SESSION_COOKIE_NAME=os.environ.get("SESSION_COOKIE_NAME", "hopefli_hello_session"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=os.environ.get("APP_ENV", "production") == "production",
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=int(os.environ.get("SESSION_LIFETIME_HOURS", "10"))),
        MAX_CONTENT_LENGTH=128 * 1024 * 1024,
    )
    Session(app)

    db_url = os.environ.get("DATABASE_URL", "sqlite:////tmp/hopefli-hello.db")
    engine = create_engine(db_url, pool_pre_ping=True)
    DB = scoped_session(sessionmaker(bind=engine, expire_on_commit=False))
    Base.metadata.create_all(engine)

    app.extensions["db_session"] = DB
    app.teardown_appcontext(lambda exc=None: DB.remove())

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; script-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://cms.hopefli.se")
        return resp

    def current_user():
        return session.get("user")

    def login_required(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user():
                return redirect(url_for("login", next=request.path))
            return fn(*args, **kwargs)
        return wrapper

    def admin_required(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user().get("role") != "admin":
                abort(403)
            return fn(*args, **kwargs)
        return wrapper

    def discovery(issuer_override=None):
        issuer = (issuer_override or _sso_value("HOPEFLI_SSO_ISSUER", "https://cms.hopefli.se")).rstrip("/")
        r = requests.get(f"{issuer}/.well-known/openid-configuration", timeout=8)
        r.raise_for_status()
        return r.json()

    def sso_configured():
        secret = _sso_value("HOPEFLI_SSO_CLIENT_SECRET", "")
        return bool(secret and secret != "CHANGE_ME")

    def fixed_sso_bootstrap_values():
        base = os.environ.get("APP_BASE_URL", "https://hello.hopefli.se").rstrip("/")
        # v0.1.0 shipped with the working name intra.hopefli.se. Hello is the chosen public name.
        if base in {"", "https://intra.hopefli.se"}:
            base = "https://hello.hopefli.se"
        return {
            "issuer": "https://cms.hopefli.se",
            "client_id": "hopefli-hello",
            "redirect_uri": f"{base}/auth/callback",
        }

    @app.context_processor
    def globals_():
        version_path = Path("/app/VERSION")
        version = version_path.read_text().strip() if version_path.exists() else "dev"
        return {"me": current_user(), "app_version": version}

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "hopefli-hello", "version": Path("/app/VERSION").read_text().strip() if Path("/app/VERSION").exists() else "dev"})

    @app.get("/")
    @login_required
    def home():
        now = datetime.now()
        h = now.hour
        greeting = "Godmorgon" if 5 <= h < 12 else "God eftermiddag" if 12 <= h < 18 else "God kväll" if 18 <= h < 23 else "God natt"
        quotes = [
            "Vi skapar upplevelser som förenar – på riktigt.",
            "Bra saker händer när människor möts.",
            "Energi smittar. Gör något bra av den.",
            "Det är detaljerna som gör helheten minnesvärd.",
        ]
        quote = quotes[now.toordinal() % len(quotes)]
        news = DB.query(NewsItem).order_by(desc(NewsItem.important), desc(NewsItem.published_at)).limit(3).all()
        return render_template("home.html", greeting=greeting, quote=quote, now=now, news=news)

    @app.get("/login")
    def login():
        if current_user():
            return redirect(url_for("home"))
        return render_template("login.html", sso_ready=sso_configured())

    @app.route("/ssoconf", methods=["GET", "POST"])
    def ssoconf():
        if sso_configured():
            abort(404)
        fixed = fixed_sso_bootstrap_values()
        if request.method == "POST":
            secret = request.form.get("client_secret", "").strip()
            csrf = request.form.get("csrf", "")
            if not secret or len(secret) < 8:
                flash("Ange CMS-klientens Client Secret.", "error")
                return redirect(url_for("ssoconf"))
            if not session.get("ssoconf_csrf") or not secrets.compare_digest(csrf, session.get("ssoconf_csrf")):
                abort(400)
            try:
                meta = discovery(fixed["issuer"])
                if meta.get("issuer", "").rstrip("/") != fixed["issuer"]:
                    raise ValueError("issuer mismatch")
            except Exception:
                logger.exception("SSO bootstrap discovery failed")
                flash("CMS SSO discovery kunde inte verifieras.", "error")
                return redirect(url_for("ssoconf"))

            state = secrets.token_urlsafe(32)
            nonce = secrets.token_urlsafe(32)
            verifier = secrets.token_urlsafe(64)
            challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
            session["ssoconf_flow"] = {
                "state": state,
                "nonce": nonce,
                "verifier": verifier,
                "client_secret": secret,
                "created": datetime.now(timezone.utc).timestamp(),
            }
            params = {
                "response_type": "code",
                "client_id": fixed["client_id"],
                "redirect_uri": fixed["redirect_uri"],
                "scope": "openid profile email groups",
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
            from urllib.parse import urlencode
            return redirect(meta["authorization_endpoint"] + "?" + urlencode(params))

        csrf = secrets.token_urlsafe(32)
        session["ssoconf_csrf"] = csrf
        return render_template("ssoconf.html", fixed=fixed, csrf=csrf)

    def complete_ssoconf_callback():
        if sso_configured():
            abort(404)
        fixed = fixed_sso_bootstrap_values()
        flow = session.get("ssoconf_flow") or {}
        if not flow or request.args.get("state") != flow.get("state"):
            logger.warning("SSO bootstrap failed: invalid_state")
            flash("Konfigurationstestet kunde inte verifieras. Försök igen.", "error")
            return redirect(url_for("ssoconf"))
        if request.args.get("error"):
            logger.warning("SSO bootstrap provider error=%s", request.args.get("error"))
            flash("CMS nekade eller avbröt inloggningen.", "error")
            return redirect(url_for("ssoconf"))
        code = request.args.get("code")
        if not code:
            flash("CMS returnerade ingen authorization code.", "error")
            return redirect(url_for("ssoconf"))
        try:
            meta = discovery(fixed["issuer"])
            tr = requests.post(
                meta["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": fixed["redirect_uri"],
                    "client_id": fixed["client_id"],
                    "code_verifier": flow["verifier"],
                },
                auth=(fixed["client_id"], flow["client_secret"]),
                timeout=10,
            )
            tr.raise_for_status()
            token_data = tr.json()
            id_token = token_data.get("id_token")
            if not id_token:
                raise ValueError("missing id_token")
            jwks = requests.get(meta["jwks_uri"], timeout=8)
            jwks.raise_for_status()
            key_set = JsonWebKey.import_key_set(jwks.json())
            claims = jwt.decode(
                id_token,
                key_set,
                claims_options={
                    "iss": {"essential": True, "value": meta["issuer"]},
                    "aud": {"essential": True, "value": fixed["client_id"]},
                    "exp": {"essential": True},
                    "nonce": {"essential": True, "value": flow["nonce"]},
                },
            )
            claims.validate(leeway=30)
            data = dict(claims)
            at = token_data.get("access_token")
            if at and meta.get("userinfo_endpoint"):
                ur = requests.get(meta["userinfo_endpoint"], headers={"Authorization": f"Bearer {at}"}, timeout=8)
                if ur.ok:
                    # userinfo is the provider's current authorization view; let it
                    # override duplicated profile/access claims from the ID token.
                    data.update(ur.json())

            def _claim_true(value):
                # OIDC providers may return JSON booleans, integers or textual
                # representations. Normalize all of them consistently.
                if isinstance(value, bool):
                    return value
                if isinstance(value, (int, float)):
                    return value == 1
                return str(value or "").strip().lower() in {
                    "true", "1", "yes", "on", "active", "enabled"
                }

            role = str(data.get("role") or "").strip().lower()
            raw_groups = data.get("groups") or []
            if isinstance(raw_groups, str):
                raw_groups = [g.strip() for g in raw_groups.replace(",", " ").split() if g.strip()]
            groups = [str(g).strip().lower() for g in raw_groups]
            active_ok = _claim_true(data.get("active"))
            access_ok = _claim_true(data.get("access"))
            system_value = str(data.get("system") or "").strip().lower()

            # Store only non-secret authorization claims so setup failures can be
            # diagnosed from the browser without exposing tokens or credentials.
            safe = {
                "active": data.get("active"),
                "access": data.get("access"),
                "system": system_value or None,
                "role": data.get("role"),
                "groups": raw_groups,
            }
            session["ssoconf_last_claims"] = safe

            if not active_ok or not access_ok:
                raise SSOAuthorizationError("no_access")
            if system_value and system_value not in {"hello", "hopefli-hello", "hopefli hello", "intranet", "hopefli-intranet", "hopefli intranät"}:
                raise SSOAuthorizationError("wrong_system")
            if role != "admin" and "hello-admin" not in groups and "intranet-admin" not in groups:
                raise SSOAuthorizationError("admin_required")
            config = {
                "issuer": fixed["issuer"],
                "client_id": fixed["client_id"],
                "client_secret": flow["client_secret"],
                "redirect_uri": fixed["redirect_uri"],
                "configured_at": datetime.now(timezone.utc).isoformat(),
                "configured_by_sub": data.get("sub"),
            }
            _write_sso_file(config)
            logger.info("SSO bootstrap completed sub=%s", data.get("sub"))
            session.clear()
            flash("Hopefli SSO är nu anslutet. Logga in med Hopefli för att fortsätta.", "success")
            return redirect(url_for("login"))
        except SSOAuthorizationError as exc:
            logger.warning("SSO bootstrap denied reason=%s", str(exc))
            session.pop("ssoconf_flow", None)
            if str(exc) == "admin_required":
                safe = session.get("ssoconf_last_claims") or {}
                flash(
                    "CMS-inloggningen lyckades, men Hello fick inte adminrollen i claims. "
                    f"Mottaget: role={safe.get('role')!r}, groups={safe.get('groups')!r}, "
                    f"active={safe.get('active')!r}, access={safe.get('access')!r}, system={safe.get('system')!r}.",
                    "error",
                )
            else:
                safe = session.get("ssoconf_last_claims") or {}
                flash(
                    "CMS-inloggningen lyckades, men access/active godkändes inte av Hello. "
                    f"Mottaget: role={safe.get('role')!r}, groups={safe.get('groups')!r}, "
                    f"active={safe.get('active')!r}, access={safe.get('access')!r}, system={safe.get('system')!r}.",
                    "error",
                )
            return redirect(url_for("ssoconf"))
        except PermissionError:
            logger.exception("SSO bootstrap could not persist configuration")
            session.pop("ssoconf_flow", None)
            flash("CMS-inloggningen lyckades, men Hello kunde inte spara SSO-konfigurationen på servern. Kontrollera rättigheterna för Hello-konfigurationskatalogen.", "error")
            return redirect(url_for("ssoconf"))
        except Exception as exc:
            logger.exception("SSO bootstrap failed type=%s", exc.__class__.__name__)
            session.pop("ssoconf_flow", None)
            flash("Kopplingen kunde inte verifieras. Kontrollera Client Secret och CMS-klientens redirect URI.", "error")
            return redirect(url_for("ssoconf"))

    @app.get("/ssoconf/callback")
    def ssoconf_callback_legacy():
        # v0.1.1 used a second redirect URI. Keep the route non-functional so CMS
        # only needs the single registered /auth/callback URI from v0.1.2 onward.
        abort(404)

    @app.get("/auth/login")
    def auth_login():
        if not sso_configured():
            flash("Hopefli SSO är inte färdigkonfigurerat på servern.", "error")
            return redirect(url_for("login"))
        try:
            meta = discovery()
        except Exception:
            logger.exception("SSO discovery failed")
            flash("Hopefli-inloggningen kan inte nås just nu.", "error")
            return redirect(url_for("login"))

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        session.clear()
        session.permanent = True
        session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier, "created": datetime.now(timezone.utc).timestamp()}

        params = {
            "response_type": "code",
            "client_id": _sso_value("HOPEFLI_SSO_CLIENT_ID", "hopefli-hello"),
            "redirect_uri": _sso_value("HOPEFLI_SSO_REDIRECT_URI"),
            "scope": "openid profile email groups",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        from urllib.parse import urlencode
        return redirect(meta["authorization_endpoint"] + "?" + urlencode(params))

    @app.get("/auth/callback")
    def auth_callback():
        # During first-time SSO setup, the same registered callback URI is used
        # as for normal login. This supports CMS clients with one redirect URI.
        if session.get("ssoconf_flow"):
            return complete_ssoconf_callback()

        oidc_state = session.get("oidc") or {}
        if not oidc_state or request.args.get("state") != oidc_state.get("state"):
            logger.warning("OIDC login failed: invalid_state")
            flash("Inloggningen kunde inte verifieras. Försök igen.", "error")
            return redirect(url_for("login"))
        if request.args.get("error"):
            logger.warning("OIDC login failed: provider_error=%s", request.args.get("error"))
            flash("Inloggningen avbröts eller nekades.", "error")
            return redirect(url_for("login"))
        code = request.args.get("code")
        if not code:
            flash("Ogiltigt svar från Hopefli-inloggningen.", "error")
            return redirect(url_for("login"))

        try:
            meta = discovery()
            client_id = _sso_value("HOPEFLI_SSO_CLIENT_ID", "hopefli-hello")
            redirect_uri = _sso_value("HOPEFLI_SSO_REDIRECT_URI")
            token_response = requests.post(
                meta["token_endpoint"],
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "code_verifier": oidc_state["verifier"],
                },
                auth=(client_id, _sso_value("HOPEFLI_SSO_CLIENT_SECRET")),
                timeout=10,
            )
            token_response.raise_for_status()
            token_data = token_response.json()
            id_token = token_data.get("id_token")
            if not id_token:
                raise ValueError("missing id_token")

            jwks_resp = requests.get(meta["jwks_uri"], timeout=8)
            jwks_resp.raise_for_status()
            key_set = JsonWebKey.import_key_set(jwks_resp.json())
            claims = jwt.decode(
                id_token,
                key_set,
                claims_options={
                    "iss": {"essential": True, "value": meta["issuer"]},
                    "aud": {"essential": True, "value": client_id},
                    "exp": {"essential": True},
                    "nonce": {"essential": True, "value": oidc_state["nonce"]},
                },
            )
            claims.validate(leeway=30)
            data = dict(claims)

            access_token = token_data.get("access_token")
            if access_token and meta.get("userinfo_endpoint"):
                ur = requests.get(meta["userinfo_endpoint"], headers={"Authorization": f"Bearer {access_token}"}, timeout=8)
                if ur.ok:
                    data.update(ur.json())

            def _claim_true(value):
                # OIDC providers may return JSON booleans, integers or textual
                # representations. Normalize all of them consistently.
                if isinstance(value, bool):
                    return value
                if isinstance(value, (int, float)):
                    return value == 1
                return str(value or "").strip().lower() in {
                    "true", "1", "yes", "on", "active", "enabled"
                }

            if not _claim_true(data.get("active")) or not _claim_true(data.get("access")):
                raise SSOAuthorizationError("no_access")
            system_value = str(data.get("system") or "").strip().lower()
            if system_value and system_value not in {"intranet", "hopefli-intranet", "hopefli intranät", "hopefli hello", "hello"}:
                raise SSOAuthorizationError("wrong_system")
            role = str(data.get("role") or "user").strip().lower()
            raw_groups = data.get("groups") or []
            if isinstance(raw_groups, str):
                raw_groups = [g.strip() for g in raw_groups.replace(",", " ").split() if g.strip()]
            groups = [str(g).strip().lower() for g in raw_groups]
            if role not in {"admin", "user"}:
                role = "admin" if ("hello-admin" in groups or "intranet-admin" in groups) else "user"
            sub = data.get("sub")
            if not sub:
                raise ValueError("missing sub")

            user = DB.query(ShadowUser).filter_by(cms_sub=sub).one_or_none()
            if not user:
                user = ShadowUser(cms_sub=sub, name=data.get("name") or sub, email=data.get("email"), role=role)
                DB.add(user)
            user.name = data.get("name") or user.name
            user.email = data.get("email") or user.email
            user.role = role
            user.groups_json = json.dumps(groups)
            user.active = True
            user.last_login_at = datetime.now(timezone.utc)
            DB.commit()

            session.clear()  # regenerate server-side session identity after authentication
            session.permanent = True
            session["user"] = {"sub": sub, "name": user.name, "email": user.email, "role": role, "groups": groups}
            logger.info("SSO login success sub=%s role=%s", sub, role)
            return redirect(url_for("home"))
        except SSOAuthorizationError as exc:
            logger.warning("OIDC login denied type=%s", str(exc))
            session.clear()
            flash("Du har inte åtkomst till Hopefli Hello.", "error")
            return redirect(url_for("login"))
        except Exception as exc:
            logger.exception("OIDC login failed type=%s", exc.__class__.__name__)
            session.clear()
            flash("Inloggningen kunde inte slutföras. Försök igen eller kontakta administratör.", "error")
            return redirect(url_for("login"))

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.route("/auth/recovery", methods=["GET", "POST"])
    def recovery():
        if os.environ.get("BREAK_GLASS_ENABLED", "false").lower() != "true":
            abort(404)
        if request.method == "POST":
            expected_user = os.environ.get("BREAK_GLASS_USERNAME", "local-recovery")
            password_hash = os.environ.get("BREAK_GLASS_PASSWORD_HASH", "")
            if request.form.get("username") == expected_user and password_hash and check_password_hash(password_hash, request.form.get("password", "")):
                session.clear()
                session.permanent = True
                session["user"] = {"sub": "break-glass", "name": "Recovery Admin", "email": None, "role": "admin", "groups": ["hello-admin"]}
                logger.warning("Break-glass login success")
                return redirect(url_for("home"))
            logger.warning("Break-glass login failed")
            flash("Felaktiga återställningsuppgifter.", "error")
        return render_template("recovery.html")

    @app.get("/people")
    @login_required
    def people():
        users = DB.query(ShadowUser).filter_by(active=True).order_by(ShadowUser.name.asc()).all()
        return render_template("people.html", users=users)

    @app.get("/news")
    @login_required
    def news():
        items = DB.query(NewsItem).order_by(desc(NewsItem.published_at)).all()
        return render_template("news.html", items=items)

    @app.route("/admin", methods=["GET", "POST"])
    @admin_required
    def admin():
        if request.method == "POST":
            title = request.form.get("title", "").strip()
            body = request.form.get("body", "").strip()
            if title and body:
                DB.add(NewsItem(title=title, body=body, important=bool(request.form.get("important"))))
                DB.commit()
                flash("Nyheten publicerades.", "success")
            return redirect(url_for("admin"))
        status = {"connected": False, "issuer": _sso_value("HOPEFLI_SSO_ISSUER"), "client": _sso_value("HOPEFLI_SSO_CLIENT_ID", "hopefli-hello")}
        try:
            meta = discovery()
            status["connected"] = meta.get("issuer") == status["issuer"]
        except Exception:
            pass
        latest = DB.query(ShadowUser).filter(ShadowUser.last_login_at.isnot(None)).order_by(desc(ShadowUser.last_login_at)).first()
        return render_template("admin.html", status=status, latest=latest)

    def _github_config_path():
        return SSO_CONFIG_PATH.parent / "github.json"

    def _read_github_config():
        p = _github_config_path()
        try:
            if p.exists():
                data = json.loads(p.read_text())
                return data if isinstance(data, dict) else {}
        except Exception:
            logger.exception("Could not read GitHub config")
        return {}

    def _write_github_config(data):
        p = _github_config_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        os.chmod(tmp, 0o600)
        tmp.replace(p)

    def _admin_csrf_ok():
        expected = session.get("admin_system_csrf") or ""
        supplied = request.form.get("csrf", "")
        return bool(expected and supplied and secrets.compare_digest(expected, supplied))

    def _queue_job(kind, **payload):
        inbox = Path(os.environ.get("UPDATE_INBOX_PATH", "/updates"))
        inbox.mkdir(parents=True, exist_ok=True)
        job_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:10]}"
        data = {"kind": kind, "id": job_id, "created_at": datetime.now(timezone.utc).isoformat(), **payload}
        tmp = inbox / f".{job_id}.tmp"
        final = inbox / f"{job_id}.job"
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        tmp.replace(final)
        (inbox / "queue.trigger").write_text(datetime.now(timezone.utc).isoformat() + "\n")
        return job_id

    def _read_worker_status():
        p = Path(os.environ.get("UPDATE_INBOX_PATH", "/updates")) / "status.json"
        try:
            return json.loads(p.read_text()) if p.exists() else {}
        except Exception:
            return {"state": "error", "message": "Workerstatus kunde inte läsas."}

    def _safe_release_archive(path: Path):
        with tarfile.open(path, "r:gz") as tf:
            names = tf.getnames()
            if not names:
                raise ValueError("tomt paket")
            for name in names:
                parts = Path(name).parts
                if name.startswith("/") or ".." in parts:
                    raise ValueError("osäker sökväg i paketet")
            roots = {Path(n).parts[0] for n in names if Path(n).parts}
            if len(roots) != 1:
                raise ValueError("paketet måste ha en rotkatalog")
            root = next(iter(roots))
            required = {f"{root}/VERSION", f"{root}/docker-compose.yml", f"{root}/update.sh"}
            if not required.issubset(set(names)):
                raise ValueError("paketet saknar VERSION/docker-compose.yml/update.sh")
            version_member = tf.extractfile(f"{root}/VERSION")
            version = version_member.read(64).decode("utf-8", "replace").strip() if version_member else ""
            if not version or len(version) > 32:
                raise ValueError("ogiltig VERSION")
            return version

    @app.get("/admin/system")
    @admin_required
    def admin_system():
        csrf = secrets.token_urlsafe(32)
        session["admin_system_csrf"] = csrf
        cfg = _read_github_config()
        status = _read_worker_status()
        return render_template(
            "admin_system.html",
            csrf=csrf,
            github={
                "repo": cfg.get("repo", ""),
                "branch": cfg.get("branch", "main"),
                "configured": bool(cfg.get("token")),
                "token_hint": ("••••" + cfg.get("token", "")[-4:]) if cfg.get("token") else "Ej sparad",
            },
            worker=status,
        )

    @app.post("/admin/system/github/save")
    @admin_required
    def admin_github_save():
        if not _admin_csrf_ok(): abort(400)
        repo = request.form.get("repo", "").strip()
        branch = request.form.get("branch", "main").strip() or "main"
        token = request.form.get("token", "").strip()
        if "/" not in repo or len(repo.split("/")) != 2:
            flash("Repository ska anges som owner/repo.", "error")
            return redirect(url_for("admin_system"))
        old = _read_github_config()
        if not token:
            token = old.get("token", "")
        if not token:
            flash("Ange en fine-grained GitHub-token.", "error")
            return redirect(url_for("admin_system"))
        _write_github_config({"repo": repo, "branch": branch, "token": token, "updated_at": datetime.now(timezone.utc).isoformat()})
        logger.info("GitHub configuration updated by sub=%s repo=%s", current_user().get("sub"), repo)
        flash("GitHub-konfigurationen sparades. Token visas inte igen.", "success")
        return redirect(url_for("admin_system"))

    @app.post("/admin/system/github/test")
    @admin_required
    def admin_github_test():
        if not _admin_csrf_ok(): abort(400)
        cfg = _read_github_config()
        if not cfg.get("repo") or not cfg.get("token"):
            flash("Spara GitHub-konfigurationen först.", "error")
            return redirect(url_for("admin_system"))
        try:
            r = requests.get(
                f"https://api.github.com/repos/{cfg['repo']}",
                headers={
                    "Authorization": f"Bearer {cfg['token']}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
                push = (data.get("permissions") or {}).get("push")
                suffix = " Skrivåtkomst rapporteras." if push is True else " Repository kunde läsas; skrivåtkomst verifieras vid synk."
                flash(f"GitHub-anslutningen fungerar mot {cfg['repo']}." + suffix, "success")
            elif r.status_code in {401, 403}:
                flash("GitHub nekade token. Kontrollera token, repository access och behörigheter.", "error")
            elif r.status_code == 404:
                flash("Repository hittades inte för denna token. Kontrollera owner/repo och Repository access.", "error")
            else:
                flash(f"GitHub svarade med HTTP {r.status_code}.", "error")
        except Exception:
            logger.exception("GitHub connection test failed")
            flash("Kunde inte nå GitHub just nu.", "error")
        return redirect(url_for("admin_system"))

    @app.post("/admin/system/github/sync")
    @admin_required
    def admin_github_sync():
        if not _admin_csrf_ok(): abort(400)
        cfg = _read_github_config()
        if not cfg.get("repo") or not cfg.get("token"):
            flash("Konfigurera GitHub först.", "error")
            return redirect(url_for("admin_system"))
        job_id = _queue_job("github")
        logger.info("GitHub sync queued sub=%s job=%s", current_user().get("sub"), job_id)
        flash("GitHub-synk är köad. Status uppdateras på den här sidan.", "success")
        return redirect(url_for("admin_system"))

    @app.post("/admin/system/update")
    @admin_required
    def admin_upload_update():
        if not _admin_csrf_ok(): abort(400)
        uploaded = request.files.get("release")
        if not uploaded or not uploaded.filename:
            flash("Välj en .tar.gz-release.", "error")
            return redirect(url_for("admin_system"))
        if not uploaded.filename.lower().endswith(".tar.gz"):
            flash("Endast .tar.gz-paket accepteras.", "error")
            return redirect(url_for("admin_system"))
        inbox = Path(os.environ.get("UPDATE_INBOX_PATH", "/updates"))
        inbox.mkdir(parents=True, exist_ok=True)
        safe_name = secure_filename(uploaded.filename) or "hello-release.tar.gz"
        target = inbox / f"upload-{uuid.uuid4().hex[:12]}-{safe_name}"
        uploaded.save(target)
        try:
            version = _safe_release_archive(target)
        except Exception as exc:
            target.unlink(missing_ok=True)
            logger.warning("Rejected update archive: %s", str(exc))
            flash("Releasepaketet är ogiltigt eller osäkert.", "error")
            return redirect(url_for("admin_system"))
        current = Path("/app/VERSION").read_text().strip() if Path("/app/VERSION").exists() else "dev"
        if version == current:
            target.unlink(missing_ok=True)
            flash(f"Version {version} körs redan.", "error")
            return redirect(url_for("admin_system"))
        job_id = _queue_job("update", archive=target.name, version=version, original_name=uploaded.filename)
        logger.warning("Web update queued sub=%s version=%s job=%s", current_user().get("sub"), version, job_id)
        flash(f"Hello {version} är uppladdad och installationen är köad. Sidan kan starta om under uppdateringen.", "success")
        return redirect(url_for("admin_system"))

    return app
