import hashlib
import json
from datetime import date, datetime, timedelta
from urllib.parse import urlparse

import requests


SV_MONTHS = [
    "januari", "februari", "mars", "april", "maj", "juni",
    "juli", "augusti", "september", "oktober", "november", "december",
]


class StaffAuthExpired(Exception):
    pass


class StaffUnavailable(Exception):
    pass


def _first(data, *names, default=None):
    if not isinstance(data, dict):
        return default
    for name in names:
        if name in data and data.get(name) not in (None, ""):
            return data.get(name)
    return default


def _truthy(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "ja", "on", "enabled", "active"}


def parse_date(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    if not text:
        return None
    # ISO dates and ISO timestamps are the expected CMS format.
    try:
        return date.fromisoformat(text[:10])
    except Exception:
        return None


def format_date_sv(value, include_year=True):
    d = parse_date(value)
    if not d:
        return None
    return f"{d.day} {SV_MONTHS[d.month - 1]}" + (f" {d.year}" if include_year else "")


def _extract_rows(payload):
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("staff", "items", "employees", "people", "data", "results", "away", "away_today", "absences"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def normalize_person(raw):
    if not isinstance(raw, dict):
        return None
    visible = _first(raw, "show_in_hello", "visible_in_hello", "hello_visible", "show_in_intranet")
    if visible is not None and not _truthy(visible):
        return None

    cms_id = _first(raw, "id", "staff_id", "person_id", "user_id", "sub", "uuid")
    name = _first(raw, "name", "full_name", "display_name")
    if not name:
        first = _first(raw, "first_name", "given_name", default="") or ""
        last = _first(raw, "last_name", "family_name", default="") or ""
        name = f"{first} {last}".strip()
    if not name:
        return None

    birthday = _first(raw, "birthday", "birth_date", "date_of_birth")
    employment = _first(raw, "employment_start_date", "employment_date", "hire_date", "start_date")
    role = _first(raw, "role_function", "function", "job_title", "title", "position", "role", default="") or ""
    photo_hint = _first(raw, "has_photo", "photo_available", "profile_photo", "photo_url", "avatar_url")

    return {
        "cms_id": str(cms_id) if cms_id not in (None, "") else None,
        "name": str(name).strip(),
        "email": str(_first(raw, "email", "work_email", default="") or "").strip() or None,
        "phone": str(_first(raw, "phone", "phone_number", "mobile", "mobile_phone", default="") or "").strip() or None,
        "role": str(role).strip() or None,
        "birthday": str(birthday).strip() if birthday else None,
        "birthday_display": format_date_sv(birthday, include_year=False),
        "employment_start_date": str(employment).strip() if employment else None,
        "employment_display": format_date_sv(employment, include_year=True),
        "photo_available": _truthy(photo_hint, default=bool(photo_hint or _first(raw, "profile_image_url", "profile_photo_url"))),
        "raw_photo_url": str(_first(raw, "photo_url", "avatar_url", default="") or "").strip() or None,
    }


def normalize_staff(payload):
    people = []
    for raw in _extract_rows(payload):
        person = normalize_person(raw)
        if person:
            people.append(person)
    return sorted(people, key=lambda p: (p.get("name") or "").casefold())



def diagnose_staff_payload(payload):
    rows = _extract_rows(payload)
    details = []
    shown = 0
    filtered = 0
    for idx, raw in enumerate(rows, start=1):
        if not isinstance(raw, dict):
            filtered += 1
            details.append({"name": f"Post {idx}", "email": None, "status": "Filtrerad", "reason": "Ogiltigt dataformat", "photo": None})
            continue
        name = _first(raw, "name", "full_name", "display_name")
        if not name:
            first = _first(raw, "first_name", "given_name", default="") or ""
            last = _first(raw, "last_name", "family_name", default="") or ""
            name = f"{first} {last}".strip() or None
        email = str(_first(raw, "email", "work_email", default="") or "").strip() or None
        visible = _first(raw, "show_in_hello", "visible_in_hello", "hello_visible", "show_in_intranet")
        photo_hint = _first(raw, "has_photo", "photo_available", "profile_photo", "photo_url", "avatar_url", "profile_image_url", "profile_photo_url")
        photo = "Ja" if _truthy(photo_hint, default=bool(photo_hint)) else "Nej"
        person = normalize_person(raw)
        if person:
            shown += 1
            status = "Visas"
            reason = "OK" if photo == "Ja" else "OK – profilbild saknas, avatar används"
        else:
            filtered += 1
            status = "Filtrerad"
            if visible is not None and not _truthy(visible):
                reason = "Visa i Hopefli Hello = Nej"
            elif not name:
                reason = "Namn saknas"
            else:
                reason = "Posten kunde inte normaliseras"
        details.append({"name": str(name or f"Post {idx}"), "email": email, "status": status, "reason": reason, "photo": photo})
    return {"received": len(rows), "shown": shown, "filtered": filtered, "details": details}

def normalize_away(payload):
    rows = _extract_rows(payload)
    out = []
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        until = _first(raw, "until", "end_date", "to", "date_to")
        out.append({
            "cms_id": str(_first(raw, "id", "staff_id", "person_id", "user_id", "sub", default="") or "") or None,
            "email": str(_first(raw, "email", default="") or "").strip().lower() or None,
            "name": str(_first(raw, "name", "full_name", "display_name", default="") or "").strip() or None,
            "type": str(_first(raw, "type", "absence_type", "reason", "label", default="Frånvarande") or "Frånvarande").strip(),
            "until": str(until).strip() if until else None,
            "until_display": format_date_sv(until, include_year=False),
        })
    return out


def upcoming_birthdays(people, today=None, days=60, limit=6):
    today = today or date.today()
    rows = []
    for person in people:
        born = parse_date(person.get("birthday"))
        if not born:
            continue
        try:
            upcoming = date(today.year, born.month, born.day)
        except ValueError:
            # 29 Feb: use 28 Feb in non-leap years for display ordering.
            upcoming = date(today.year, 2, 28)
        if upcoming < today:
            try:
                upcoming = date(today.year + 1, born.month, born.day)
            except ValueError:
                upcoming = date(today.year + 1, 2, 28)
        delta = (upcoming - today).days
        if delta <= days:
            rows.append({"name": person["name"], "date": upcoming, "display": format_date_sv(upcoming, include_year=False), "days": delta})
    rows.sort(key=lambda x: (x["date"], x["name"].casefold()))
    return rows[:limit]


def employment_anniversaries(people, today=None, days=45, limit=6):
    today = today or date.today()
    rows = []
    for person in people:
        started = parse_date(person.get("employment_start_date"))
        if not started or started >= today:
            continue
        years = today.year - started.year
        if years < 1:
            continue
        try:
            anniversary = date(today.year, started.month, started.day)
        except ValueError:
            anniversary = date(today.year, 2, 28)
        if anniversary < today:
            years += 1
            try:
                anniversary = date(today.year + 1, started.month, started.day)
            except ValueError:
                anniversary = date(today.year + 1, 2, 28)
        delta = (anniversary - today).days
        if delta <= days:
            rows.append({"name": person["name"], "date": anniversary, "display": format_date_sv(anniversary, include_year=False), "years": years, "days": delta})
    rows.sort(key=lambda x: (x["date"], x["name"].casefold()))
    return rows[:limit]


class StaffService:
    def __init__(self, base_url, redis_client, staff_path, away_path, photo_path_template, cache_ttl=180, stale_ttl=86400, timeout=5):
        self.base_url = base_url.rstrip("/")
        self.redis = redis_client
        self.staff_path = staff_path
        self.away_path = away_path
        self.photo_path_template = photo_path_template
        self.cache_ttl = int(cache_ttl)
        self.stale_ttl = int(stale_ttl)
        self.timeout = int(timeout)

    def _url(self, path):
        if not path:
            return None
        if path.startswith("http://") or path.startswith("https://"):
            # Never allow the integration to become an arbitrary SSRF proxy.
            if urlparse(path).netloc != urlparse(self.base_url).netloc:
                raise StaffUnavailable("CMS API host mismatch")
            return path
        return self.base_url + "/" + path.lstrip("/")

    def _json_cache_get(self, key):
        try:
            raw = self.redis.get(key)
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def _json_cache_set(self, key, value, ttl):
        try:
            self.redis.setex(key, ttl, json.dumps(value, ensure_ascii=False))
        except Exception:
            pass

    def _get_json(self, access_token, path, cache_name, normalizer):
        if not access_token:
            raise StaffAuthExpired("missing access token")
        fresh_key = f"hello:staff:{cache_name}:fresh"
        stale_key = f"hello:staff:{cache_name}:stale"
        cached = self._json_cache_get(fresh_key)
        if cached is not None:
            return cached, {"source": "cache", "stale": False}
        try:
            resp = requests.get(self._url(path), headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}, timeout=self.timeout)
            if resp.status_code in {401, 403}:
                raise StaffAuthExpired(f"CMS returned {resp.status_code}")
            if resp.status_code == 404 and cache_name == "away":
                return [], {"source": "unsupported", "stale": False}
            resp.raise_for_status()
            data = normalizer(resp.json())
            self._json_cache_set(fresh_key, data, self.cache_ttl)
            self._json_cache_set(stale_key, data, self.stale_ttl)
            return data, {"source": "live", "stale": False}
        except StaffAuthExpired:
            stale = self._json_cache_get(stale_key)
            if stale is not None:
                return stale, {"source": "stale", "stale": True, "auth_expired": True}
            raise
        except Exception as exc:
            stale = self._json_cache_get(stale_key)
            if stale is not None:
                return stale, {"source": "stale", "stale": True, "error": exc.__class__.__name__}
            raise StaffUnavailable(exc.__class__.__name__) from exc

    def list_staff(self, access_token):
        return self._get_json(access_token, self.staff_path, "directory", normalize_staff)

    def diagnose_staff(self, access_token):
        if not access_token:
            raise StaffAuthExpired("missing access token")
        resp = requests.get(self._url(self.staff_path), headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"}, timeout=self.timeout)
        if resp.status_code in {401, 403}:
            raise StaffAuthExpired(f"CMS returned {resp.status_code}")
        resp.raise_for_status()
        return diagnose_staff_payload(resp.json())

    def away_today(self, access_token):
        if not self.away_path:
            return [], {"source": "disabled", "stale": False}
        return self._get_json(access_token, self.away_path, "away", normalize_away)

    def photo(self, access_token, cms_id):
        digest = hashlib.sha256(str(cms_id).encode()).hexdigest()
        data_key = f"hello:staff:photo:{digest}:data"
        type_key = f"hello:staff:photo:{digest}:type"
        try:
            cached = self.redis.get(data_key)
            if cached:
                mimetype = self.redis.get(type_key)
                return cached, (mimetype.decode() if isinstance(mimetype, bytes) else mimetype) or "image/jpeg"
        except Exception:
            pass
        if not access_token:
            raise StaffAuthExpired("missing access token")
        path = self.photo_path_template.format(id=cms_id)
        resp = requests.get(self._url(path), headers={"Authorization": f"Bearer {access_token}"}, timeout=self.timeout)
        if resp.status_code in {401, 403}:
            raise StaffAuthExpired("CMS photo token rejected")
        if resp.status_code == 404:
            return None, None
        resp.raise_for_status()
        content_type = (resp.headers.get("Content-Type") or "image/jpeg").split(";", 1)[0].strip().lower()
        if not content_type.startswith("image/") or len(resp.content) > 8 * 1024 * 1024:
            raise StaffUnavailable("invalid photo response")
        try:
            self.redis.setex(data_key, 3600, resp.content)
            self.redis.setex(type_key, 3600, content_type)
        except Exception:
            pass
        return resp.content, content_type
