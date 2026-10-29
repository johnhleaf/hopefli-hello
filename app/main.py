import base64
import hashlib
import json
import logging
import os
import re
import secrets
import tarfile
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from io import BytesIO
from pathlib import Path

import requests
from authlib.jose import JsonWebKey, jwt
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from flask_session import Session
from redis import Redis
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, create_engine, desc
from sqlalchemy.orm import declarative_base, scoped_session, sessionmaker
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import BadSignature, URLSafeSerializer

from .staff import StaffAuthExpired, StaffService, StaffUnavailable, employment_anniversaries, upcoming_birthdays
from .jobs import JobsAuthExpired, JobsService, JobsUnavailable

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


class HandbookCategory(Base):
    __tablename__ = "handbook_categories"
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    sort_order = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


class HandbookArticle(Base):
    __tablename__ = "handbook_articles"
    id = Column(Integer, primary_key=True)
    category_id = Column(Integer, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    published = Column(Boolean, nullable=False, default=True)
    sort_order = Column(Integer, nullable=False, default=0)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


SSO_CONFIG_PATH = Path(os.environ.get("SSO_CONFIG_PATH", "/config/sso.json"))
BRANDING_DIR = Path(os.environ.get("BRANDING_DIR", "/config/branding"))


HANDBOOK_STANDARD_PATH = Path(__file__).resolve().parent / "data" / "hopefli-handbook-standard.json"



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

    # Give a fresh installation a useful handbook structure without creating
    # placeholder policy text that could be mistaken for approved company policy.
    if DB.query(HandbookCategory).count() == 0:
        for idx, name in enumerate([
            "Anställning & vardag",
            "Ledighet & frånvaro",
            "Utlägg & resor",
            "IT & säkerhet",
        ], start=1):
            DB.add(HandbookCategory(name=name, sort_order=idx * 10))
        DB.commit()

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

    STAFF_CONFIG_PATH = SSO_CONFIG_PATH.parent / "staff.json"
    staff_photo_signer = URLSafeSerializer(app.config["SECRET_KEY"], salt="hopefli-hello-staff-photo")

    def _staff_config_defaults():
        return {
            "base_url": os.environ.get("CMS_STAFF_BASE_URL", "https://cms.hopefli.se"),
            "staff_path": os.environ.get("CMS_STAFF_API_PATH", "/api/internal/v1/staff"),
            "away_path": os.environ.get("CMS_STAFF_AWAY_API_PATH", "/api/internal/v1/staff/away-today"),
            "photo_path_template": os.environ.get("CMS_STAFF_PHOTO_PATH_TEMPLATE", "/api/internal/v1/staff/{id}/photo"),
        }

    def _read_staff_config():
        cfg = _staff_config_defaults()
        try:
            if STAFF_CONFIG_PATH.exists():
                saved = json.loads(STAFF_CONFIG_PATH.read_text())
                if isinstance(saved, dict):
                    for key in cfg:
                        if saved.get(key) not in (None, ""):
                            cfg[key] = saved[key]
        except Exception:
            logger.exception("Could not read staff API config")
        return cfg

    def _write_staff_config(data):
        STAFF_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = STAFF_CONFIG_PATH.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
        os.chmod(tmp, 0o600)
        tmp.replace(STAFF_CONFIG_PATH)

    def _staff_service():
        cfg = _read_staff_config()
        return StaffService(
            cfg["base_url"], app.config["SESSION_REDIS"], cfg["staff_path"], cfg["away_path"], cfg["photo_path_template"],
            cache_ttl=int(os.environ.get("CMS_STAFF_CACHE_SECONDS", "180")),
            stale_ttl=int(os.environ.get("CMS_STAFF_STALE_SECONDS", "86400")),
            timeout=int(os.environ.get("CMS_STAFF_TIMEOUT_SECONDS", "5")),
        )

    def _cms_access_token():
        token = session.get("cms_access_token")
        expires_at = session.get("cms_access_token_expires_at")
        try:
            if expires_at and datetime.now(timezone.utc).timestamp() >= float(expires_at) - 20:
                return None
        except Exception:
            pass
        return token

    def _with_photo_tokens(people):
        for person in people:
            if person.get("cms_id") and person.get("photo_available"):
                person["photo_token"] = staff_photo_signer.dumps({"id": person["cms_id"]})
            else:
                person["photo_token"] = None
        return people

    def _jobs_service():
        return JobsService(
            os.environ.get("CMS_JOBS_BASE_URL", "https://cms.hopefli.se"),
            app.config["SESSION_REDIS"],
            pipeline_path=os.environ.get("CMS_JOBS_PIPELINE_PATH", "/api/internal/v1/jobs/pipeline"),
            cache_ttl=int(os.environ.get("CMS_JOBS_CACHE_SECONDS", "180")),
            stale_ttl=int(os.environ.get("CMS_JOBS_STALE_SECONDS", "86400")),
            timeout=int(os.environ.get("CMS_JOBS_TIMEOUT_SECONDS", "5")),
        )

    def _jobs_dashboard_data():
        token = _cms_access_token()
        if not token:
            return {"items": [], "needs_reauth": True, "stale": False}
        try:
            items, meta = _jobs_service().pipeline(token)
            return {
                "items": items[:5],
                "needs_reauth": bool(meta.get("auth_expired")),
                "stale": bool(meta.get("stale")),
            }
        except JobsAuthExpired:
            return {"items": [], "needs_reauth": True, "stale": False}
        except JobsUnavailable:
            return {"items": [], "needs_reauth": False, "stale": False, "unavailable": True}
        except Exception:
            logger.exception("Dashboard jobs widget failed")
            return {"items": [], "needs_reauth": False, "stale": False, "unavailable": True}

    def _staff_dashboard_data():
        token = _cms_access_token()
        if not token:
            return {"people": [], "away": [], "birthdays": [], "anniversaries": [], "needs_reauth": True, "stale": False}
        try:
            people, pmeta = _staff_service().list_staff(token)
            try:
                away, ameta = _staff_service().away_today(token)
            except Exception:
                away, ameta = [], {"stale": False}
            by_id = {str(p.get("cms_id")): p for p in people if p.get("cms_id")}
            by_email = {(p.get("email") or "").lower(): p for p in people if p.get("email")}
            for item in away:
                match = by_id.get(str(item.get("cms_id"))) if item.get("cms_id") else None
                if not match and item.get("email"):
                    match = by_email.get(item.get("email").lower())
                if match and not item.get("name"):
                    item["name"] = match.get("name")
            return {
                "people": people,
                "away": away[:6],
                "birthdays": upcoming_birthdays(people),
                "anniversaries": employment_anniversaries(people),
                "needs_reauth": bool(pmeta.get("auth_expired")),
                "stale": bool(pmeta.get("stale") or ameta.get("stale")),
            }
        except StaffAuthExpired:
            return {"people": [], "away": [], "birthdays": [], "anniversaries": [], "needs_reauth": True, "stale": False}
        except StaffUnavailable:
            return {"people": [], "away": [], "birthdays": [], "anniversaries": [], "needs_reauth": False, "stale": False, "unavailable": True}
        except Exception:
            logger.exception("Dashboard staff widget failed")
            return {"people": [], "away": [], "birthdays": [], "anniversaries": [], "needs_reauth": False, "stale": False, "unavailable": True}

    @app.context_processor
    def globals_():
        version_path = Path("/app/VERSION")
        version = version_path.read_text().strip() if version_path.exists() else "dev"
        logo_exists = (BRANDING_DIR / "logo").exists()
        favicon_exists = (BRANDING_DIR / "favicon").exists()
        return {"me": current_user(), "app_version": version, "logo_exists": logo_exists, "favicon_exists": favicon_exists}

    @app.get("/branding/<kind>")
    def branding_asset(kind):
        if kind not in {"logo", "favicon"}: abort(404)
        p = BRANDING_DIR / kind
        if not p.exists(): abort(404)
        meta_path = BRANDING_DIR / "branding.json"
        mimetype = None
        try:
            meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
            mimetype = (meta.get(kind) or {}).get("mimetype")
        except Exception:
            pass
        return send_file(p, mimetype=mimetype or "application/octet-stream", conditional=True, max_age=3600)

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
        staff = {"people": [], "away": [], "birthdays": [], "anniversaries": [], "needs_reauth": False, "stale": False, "unavailable": True}
        jobs = {"items": [], "needs_reauth": False, "stale": False, "unavailable": True}
        try:
            staff = _staff_dashboard_data()
        except Exception:
            logger.exception("Home staff data preparation failed")
        try:
            jobs = _jobs_dashboard_data()
        except Exception:
            logger.exception("Home jobs data preparation failed")
        return render_template("home.html", greeting=greeting, quote=quote, now=now, news=news, staff=staff, jobs=jobs)

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
        next_url = request.args.get("next", "")
        if not next_url.startswith("/") or next_url.startswith("//"):
            next_url = ""
        session.clear()
        session.permanent = True
        session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier, "created": datetime.now(timezone.utc).timestamp(), "next": next_url}

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

            next_url = oidc_state.get("next") or ""
            session.clear()  # regenerate server-side session identity after authentication
            session.permanent = True
            session["user"] = {"sub": sub, "name": user.name, "email": user.email, "role": role, "groups": groups}
            # Flask-Session stores this server-side in Redis; it is never exposed to browser JavaScript.
            if access_token:
                session["cms_access_token"] = access_token
                try:
                    session["cms_access_token_expires_at"] = datetime.now(timezone.utc).timestamp() + int(token_data.get("expires_in") or 3600)
                except Exception:
                    session["cms_access_token_expires_at"] = datetime.now(timezone.utc).timestamp() + 3600
            logger.info("SSO login success sub=%s role=%s", sub, role)
            return redirect(next_url or url_for("home"))
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

    @app.get("/uppdrag")
    @login_required
    def jobs():
        status_filter = request.args.get("status", "all").strip().lower()
        if status_filter not in {"all", "confirmed", "ongoing"}:
            status_filter = "all"
        token = _cms_access_token()
        rows = []
        meta = {"stale": False}
        error = None
        needs_reauth = False
        if not token:
            needs_reauth = True
        else:
            try:
                rows, meta = _jobs_service().pipeline(token)
                if meta.get("auth_expired"):
                    needs_reauth = True
            except JobsAuthExpired:
                needs_reauth = True
            except JobsUnavailable:
                error = "CMS uppdragspipeline kan inte nås just nu."
            except Exception:
                logger.exception("Jobs pipeline failed")
                error = "Uppdragen kunde inte läsas just nu."
        if status_filter != "all":
            rows = [item for item in rows if item.get("status") == status_filter]
        return render_template("jobs.html", jobs=rows, status_filter=status_filter, jobs_meta=meta, jobs_error=error, needs_reauth=needs_reauth)

    @app.get("/personal")
    @login_required
    def people():
        query = request.args.get("q", "").strip()
        token = _cms_access_token()
        people_rows = []
        meta = {"stale": False}
        error = None
        needs_reauth = False
        if not token:
            needs_reauth = True
        else:
            try:
                people_rows, meta = _staff_service().list_staff(token)
                people_rows = _with_photo_tokens(people_rows)
                if meta.get("auth_expired"):
                    needs_reauth = True
            except StaffAuthExpired:
                needs_reauth = True
            except StaffUnavailable:
                error = "CMS personalkatalog kan inte nås just nu."
            except Exception:
                logger.exception("Staff directory failed")
                error = "Personalkatalogen kunde inte läsas just nu."
        if query:
            needle = query.casefold()
            people_rows = [p for p in people_rows if needle in " ".join(str(p.get(k) or "") for k in ("name", "email", "phone", "role")).casefold()]
        return render_template("people.html", users=people_rows, query=query, staff_meta=meta, staff_error=error, needs_reauth=needs_reauth)

    @app.get("/people")
    @login_required
    def people_legacy():
        return redirect(url_for("people"), code=301)

    @app.get("/personal/photo/<token>")
    @login_required
    def staff_photo(token):
        try:
            payload = staff_photo_signer.loads(token)
            cms_id = payload.get("id") if isinstance(payload, dict) else None
        except BadSignature:
            abort(404)
        if not cms_id:
            abort(404)
        access_token = _cms_access_token()
        if not access_token:
            abort(401)
        try:
            content, mimetype = _staff_service().photo(access_token, cms_id)
            if not content:
                abort(404)
            return send_file(BytesIO(content), mimetype=mimetype, max_age=3600)
        except StaffAuthExpired:
            abort(401)
        except Exception:
            logger.warning("Staff photo proxy failed", exc_info=True)
            abort(404)

    @app.get("/handbook")
    @login_required
    def handbook():
        categories = DB.query(HandbookCategory).order_by(HandbookCategory.sort_order.asc(), HandbookCategory.name.asc()).all()
        rows = []
        for cat in categories:
            articles = DB.query(HandbookArticle).filter_by(category_id=cat.id, published=True).order_by(HandbookArticle.sort_order.asc(), HandbookArticle.title.asc()).all()
            if articles:
                rows.append((cat, articles))
        uncategorized = DB.query(HandbookArticle).filter_by(category_id=0, published=True).order_by(HandbookArticle.sort_order.asc(), HandbookArticle.title.asc()).all()
        return render_template("handbook.html", categories=rows, uncategorized=uncategorized)

    @app.get("/handbook/<int:article_id>")
    @login_required
    def handbook_article(article_id):
        article = DB.get(HandbookArticle, article_id)
        if not article or (not article.published and current_user().get("role") != "admin"):
            abort(404)
        category = DB.get(HandbookCategory, article.category_id) if article.category_id else None
        return render_template("handbook_article.html", article=article, category=category)

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

    def _safe_worker_log_name(name):
        name = (name or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.log", name):
            return None
        return name

    def _read_worker_log(name, max_bytes=256000):
        safe = _safe_worker_log_name(name)
        if not safe:
            return ""
        inbox = Path(os.environ.get("UPDATE_INBOX_PATH", "/updates"))
        for p in (inbox / "logs" / safe, inbox / safe):
            try:
                if p.is_file():
                    data = p.read_bytes()
                    if len(data) > max_bytes:
                        data = data[-max_bytes:]
                        return "… tidigare loggrad(er) avkortade …\n" + data.decode("utf-8", "replace")
                    return data.decode("utf-8", "replace")
            except Exception:
                logger.exception("Could not read worker log %s", safe)
        return ""

    def _worker_log_history(limit=12):
        inbox = Path(os.environ.get("UPDATE_INBOX_PATH", "/updates"))
        rows = []
        try:
            logdir = inbox / "logs"
            if logdir.is_dir():
                for p in sorted(logdir.glob("*.log"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]:
                    rows.append({"name": p.name, "size": p.stat().st_size, "mtime": datetime.fromtimestamp(p.stat().st_mtime, timezone.utc).isoformat()})
        except Exception:
            logger.exception("Could not list worker logs")
        return rows

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
        log_name = status.get("log_file") or (
            "last-update.log" if status.get("kind") == "update" else
            "last-github.log" if status.get("kind") == "github" else
            "last-app.log" if status.get("kind") == "applog" else
            ""
        )
        worker_log = _read_worker_log(log_name) if log_name else ""
        return render_template(
            "admin_system.html",
            csrf=csrf,
            github={
                "repo": cfg.get("repo", ""),
                "branch": cfg.get("branch", "main"),
                "configured": bool(cfg.get("token")),
                "token_hint": ("••••" + cfg.get("token", "")[-4:]) if cfg.get("token") else "Ej sparad",
            },
            staff_api=_read_staff_config(),
            staff_diag=session.pop("staff_diag", None),
            worker=status, worker_log=worker_log, worker_log_name=log_name, worker_log_history=_worker_log_history(),
        )

    @app.get("/admin/system/log/<name>")
    @admin_required
    def admin_system_log(name):
        safe = _safe_worker_log_name(name)
        if not safe:
            abort(404)
        content = _read_worker_log(safe, max_bytes=2_000_000)
        if not content:
            abort(404)
        return app.response_class(content, mimetype="text/plain; charset=utf-8")

    @app.post("/admin/system/staff/save")
    @admin_required
    def admin_staff_save():
        if not _admin_csrf_ok(): abort(400)
        cfg = {
            "base_url": request.form.get("base_url", "").strip().rstrip("/"),
            "staff_path": request.form.get("staff_path", "").strip(),
            "away_path": request.form.get("away_path", "").strip(),
            "photo_path_template": request.form.get("photo_path_template", "").strip(),
        }
        if not cfg["base_url"].startswith("https://") or "{id}" not in cfg["photo_path_template"]:
            flash("Kontrollera CMS-basadress och bildendpoint. Bildendpoint måste innehålla {id}.", "error")
            return redirect(url_for("admin_system"))
        _write_staff_config(cfg)
        flash("CMS personalkatalog-konfigurationen sparades.", "success")
        return redirect(url_for("admin_system"))

    @app.post("/admin/system/staff/test")
    @admin_required
    def admin_staff_test():
        if not _admin_csrf_ok(): abort(400)
        token = _cms_access_token()
        if not token:
            flash("Din nuvarande Hello-session saknar en giltig CMS access token. Logga in med Hopefli igen och testa på nytt.", "error")
            return redirect(url_for("admin_system"))
        try:
            diag = _staff_service().diagnose_staff(token)
            session["staff_diag"] = diag
            flash(f"CMS personalkatalog fungerar. {diag['received']} post(er) mottagna, {diag['shown']} visas och {diag['filtered']} filtreras bort.", "success")
        except StaffAuthExpired:
            flash("CMS nekade access token (401/403). Logga in på nytt och kontrollera API-behörigheten för hopefli-hello.", "error")
        except Exception as exc:
            logger.warning("Staff API test failed type=%s", exc.__class__.__name__)
            flash("CMS personalkatalog kunde inte nås med den konfigurerade endpointen.", "error")
        return redirect(url_for("admin_system"))

    @app.post("/admin/system/app-log")
    @admin_required
    def admin_app_log():
        if not _admin_csrf_ok(): abort(400)
        job_id = _queue_job("applog")
        logger.info("Application log queued sub=%s job=%s", current_user().get("sub"), job_id)
        flash("Applikationsloggen är köad. Host-workern hämtar loggen nu; ladda om sidan om några sekunder.", "success")
        return redirect(url_for("admin_system"))

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

    @app.get("/admin/branding")
    @admin_required
    def admin_branding():
        csrf = secrets.token_urlsafe(32)
        session["admin_branding_csrf"] = csrf
        return render_template("admin_branding.html", csrf=csrf)

    @app.post("/admin/branding")
    @admin_required
    def admin_branding_save():
        expected = session.get("admin_branding_csrf") or ""
        if not expected or not secrets.compare_digest(expected, request.form.get("csrf", "")):
            abort(400)
        BRANDING_DIR.mkdir(parents=True, exist_ok=True)
        changed = False
        for field, target, allowed, max_bytes in [
            ("logo", "logo", {"image/png", "image/jpeg", "image/webp"}, 4*1024*1024),
            ("favicon", "favicon", {"image/png", "image/x-icon", "image/vnd.microsoft.icon", "image/webp"}, 1024*1024),
        ]:
            f = request.files.get(field)
            if f and f.filename:
                content = f.read(max_bytes + 1)
                if len(content) > max_bytes:
                    flash(f"{field.capitalize()} är för stor.", "error")
                    return redirect(url_for("admin_branding"))
                if f.mimetype not in allowed:
                    flash(f"Ogiltigt filformat för {field}.", "error")
                    return redirect(url_for("admin_branding"))
                out = BRANDING_DIR / target
                tmp = BRANDING_DIR / f".{target}.tmp"
                tmp.write_bytes(content)
                os.chmod(tmp, 0o644)
                tmp.replace(out)
                meta_path = BRANDING_DIR / "branding.json"
                try:
                    meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
                except Exception:
                    meta = {}
                meta[target] = {"mimetype": f.mimetype, "filename": secure_filename(f.filename)}
                meta_tmp = BRANDING_DIR / ".branding.json.tmp"
                meta_tmp.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n")
                os.chmod(meta_tmp, 0o600)
                meta_tmp.replace(meta_path)
                changed = True
        if request.form.get("remove_logo") == "1":
            (BRANDING_DIR / "logo").unlink(missing_ok=True); changed = True
        if request.form.get("remove_favicon") == "1":
            (BRANDING_DIR / "favicon").unlink(missing_ok=True); changed = True
        if changed:
            meta_path = BRANDING_DIR / "branding.json"
            if meta_path.exists():
                try:
                    meta = json.loads(meta_path.read_text())
                    if request.form.get("remove_logo") == "1": meta.pop("logo", None)
                    if request.form.get("remove_favicon") == "1": meta.pop("favicon", None)
                    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n")
                    os.chmod(meta_path, 0o600)
                except Exception:
                    logger.exception("Could not update branding metadata")
        flash("Brandingen uppdaterades." if changed else "Ingen fil valdes.", "success" if changed else "error")
        return redirect(url_for("admin_branding"))

    def _apply_handbook_payload(payload: dict) -> dict:
        if not isinstance(payload, dict) or payload.get("schema_version") != 1:
            raise ValueError("Ogiltigt handboksformat eller schema_version.")
        categories = payload.get("categories")
        if not isinstance(categories, list):
            raise ValueError("Handboken saknar categories-lista.")
        result = {"categories_created": 0, "categories_updated": 0, "articles_created": 0, "articles_updated": 0}
        for raw_cat in categories:
            if not isinstance(raw_cat, dict):
                continue
            name = str(raw_cat.get("name") or "").strip()[:120]
            if not name:
                continue
            cat = DB.query(HandbookCategory).filter(HandbookCategory.name == name).first()
            if cat is None:
                cat = HandbookCategory(name=name, sort_order=int(raw_cat.get("sort_order") or 0))
                DB.add(cat); DB.flush(); result["categories_created"] += 1
            else:
                cat.sort_order = int(raw_cat.get("sort_order") or cat.sort_order or 0)
                result["categories_updated"] += 1
            articles = raw_cat.get("articles") or []
            if not isinstance(articles, list):
                continue
            for raw_article in articles:
                if not isinstance(raw_article, dict):
                    continue
                title = str(raw_article.get("title") or "").strip()[:255]
                body = str(raw_article.get("body") or "").strip()
                if not title or not body:
                    continue
                article = DB.query(HandbookArticle).filter(HandbookArticle.category_id == cat.id, HandbookArticle.title == title).first()
                if article is None:
                    article = HandbookArticle(category_id=cat.id, title=title, body=body, published=bool(raw_article.get("published", True)), sort_order=int(raw_article.get("sort_order") or 0))
                    DB.add(article); result["articles_created"] += 1
                else:
                    article.body = body
                    article.published = bool(raw_article.get("published", True))
                    article.sort_order = int(raw_article.get("sort_order") or article.sort_order or 0)
                    article.updated_at = datetime.now(timezone.utc)
                    result["articles_updated"] += 1
        DB.commit()
        return result

    @app.post("/admin/handbook/import-standard")
    @admin_required
    def admin_handbook_import_standard():
        csrf = session.get("admin_handbook_csrf") or ""
        if not csrf or not secrets.compare_digest(csrf, request.form.get("csrf", "")): abort(400)
        try:
            payload = json.loads(HANDBOOK_STANDARD_PATH.read_text(encoding="utf-8"))
            result = _apply_handbook_payload(payload)
            flash(f"Hopefli-standarden är inlagd. {result['articles_created']} artiklar skapades och {result['articles_updated']} uppdaterades.", "success")
        except Exception:
            logger.exception("Could not import standard handbook")
            flash("Kunde inte lägga in standardhandboken. Se applikationsloggen.", "error")
        return redirect(url_for("admin_handbook"))

    @app.post("/admin/handbook/import-json")
    @admin_required
    def admin_handbook_import_json():
        csrf = session.get("admin_handbook_csrf") or ""
        if not csrf or not secrets.compare_digest(csrf, request.form.get("csrf", "")): abort(400)
        upload = request.files.get("handbook_file")
        if not upload or not upload.filename:
            flash("Välj en JSON-fil.", "error"); return redirect(url_for("admin_handbook"))
        try:
            raw = upload.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("Filen är för stor.")
            payload = json.loads(raw.decode("utf-8"))
            result = _apply_handbook_payload(payload)
            flash(f"Import klar. {result['articles_created']} artiklar skapades och {result['articles_updated']} uppdaterades.", "success")
        except Exception as exc:
            logger.warning("Handbook JSON import failed: %s", exc.__class__.__name__)
            flash("Importen misslyckades. Kontrollera att filen är en giltig Hopefli-handbok i JSON-format.", "error")
        return redirect(url_for("admin_handbook"))

    @app.get("/admin/handbook/export-json")
    @admin_required
    def admin_handbook_export_json():
        categories = DB.query(HandbookCategory).order_by(HandbookCategory.sort_order.asc(), HandbookCategory.name.asc()).all()
        payload = {"schema_version": 1, "name": "Hopefli Personalhandbok", "categories": []}
        for cat in categories:
            articles = DB.query(HandbookArticle).filter_by(category_id=cat.id).order_by(HandbookArticle.sort_order.asc(), HandbookArticle.title.asc()).all()
            payload["categories"].append({"name": cat.name, "sort_order": cat.sort_order, "articles": [{"title": a.title, "body": a.body, "published": bool(a.published), "sort_order": a.sort_order} for a in articles]})
        uncat = DB.query(HandbookArticle).filter_by(category_id=0).order_by(HandbookArticle.sort_order.asc(), HandbookArticle.title.asc()).all()
        if uncat:
            payload["categories"].append({"name": "Övrigt", "sort_order": 999, "articles": [{"title": a.title, "body": a.body, "published": bool(a.published), "sort_order": a.sort_order} for a in uncat]})
        buf = BytesIO((json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        return send_file(buf, mimetype="application/json", as_attachment=True, download_name="hopefli-personalhandbok.json")

    @app.route("/admin/handbook", methods=["GET", "POST"])
    @admin_required
    def admin_handbook():
        csrf = session.get("admin_handbook_csrf")
        if not csrf:
            csrf = secrets.token_urlsafe(32); session["admin_handbook_csrf"] = csrf
        if request.method == "POST":
            if not secrets.compare_digest(csrf, request.form.get("csrf", "")): abort(400)
            kind = request.form.get("kind")
            if kind == "category":
                name = request.form.get("name", "").strip()
                if name:
                    DB.add(HandbookCategory(name=name, sort_order=int(request.form.get("sort_order") or 0)))
                    DB.commit(); flash("Kategorin skapades.", "success")
            elif kind == "article":
                title = request.form.get("title", "").strip(); body = request.form.get("body", "").strip()
                if title and body:
                    DB.add(HandbookArticle(category_id=int(request.form.get("category_id") or 0), title=title, body=body, published=bool(request.form.get("published")), sort_order=int(request.form.get("sort_order") or 0)))
                    DB.commit(); flash("Artikeln sparades.", "success")
            return redirect(url_for("admin_handbook"))
        categories = DB.query(HandbookCategory).order_by(HandbookCategory.sort_order.asc(), HandbookCategory.name.asc()).all()
        articles = DB.query(HandbookArticle).order_by(HandbookArticle.sort_order.asc(), HandbookArticle.title.asc()).all()
        return render_template("admin_handbook.html", csrf=csrf, categories=categories, articles=articles)

    @app.route("/admin/handbook/article/<int:article_id>", methods=["GET", "POST"])
    @admin_required
    def admin_handbook_article(article_id):
        article = DB.get(HandbookArticle, article_id)
        if not article: abort(404)
        csrf = session.get("admin_handbook_csrf") or secrets.token_urlsafe(32); session["admin_handbook_csrf"] = csrf
        if request.method == "POST":
            if not secrets.compare_digest(csrf, request.form.get("csrf", "")): abort(400)
            if request.form.get("delete") == "1":
                DB.delete(article); DB.commit(); flash("Artikeln togs bort.", "success"); return redirect(url_for("admin_handbook"))
            article.title = request.form.get("title", "").strip() or article.title
            article.body = request.form.get("body", "").strip() or article.body
            article.category_id = int(request.form.get("category_id") or 0)
            article.published = bool(request.form.get("published"))
            article.sort_order = int(request.form.get("sort_order") or 0)
            article.updated_at = datetime.now(timezone.utc)
            DB.commit(); flash("Artikeln uppdaterades.", "success"); return redirect(url_for("admin_handbook"))
        categories = DB.query(HandbookCategory).order_by(HandbookCategory.sort_order.asc(), HandbookCategory.name.asc()).all()
        return render_template("admin_handbook_edit.html", csrf=csrf, categories=categories, article=article)

    @app.post("/admin/handbook/category/<int:category_id>/delete")
    @admin_required
    def admin_handbook_category_delete(category_id):
        csrf = session.get("admin_handbook_csrf") or ""
        if not csrf or not secrets.compare_digest(csrf, request.form.get("csrf", "")): abort(400)
        cat = DB.get(HandbookCategory, category_id)
        if not cat: abort(404)
        DB.query(HandbookArticle).filter_by(category_id=category_id).update({"category_id": 0})
        DB.delete(cat); DB.commit(); flash("Kategorin togs bort. Artiklarna ligger nu utan kategori.", "success")
        return redirect(url_for("admin_handbook"))

    return app
