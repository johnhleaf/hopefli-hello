import json
from datetime import date, datetime, time
from urllib.parse import urlparse
from zoneinfo import ZoneInfo

import requests

SV_MONTHS = [
    "januari", "februari", "mars", "april", "maj", "juni",
    "juli", "augusti", "september", "oktober", "november", "december",
]


class JobsAuthExpired(Exception):
    pass


class JobsUnavailable(Exception):
    pass


def _first(data, *names, default=None):
    if not isinstance(data, dict):
        return default
    for name in names:
        if name in data and data.get(name) not in (None, ""):
            return data.get(name)
    return default


def _extract_rows(payload):
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return []
    for key in ("jobs", "pipeline", "items", "data", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return []


def parse_date(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value).strip()[:10])
    except Exception:
        return None


def parse_time(value):
    if not value:
        return None
    if isinstance(value, time):
        return value.replace(tzinfo=None)
    text = str(value).strip()
    if not text:
        return None
    try:
        return time.fromisoformat(text[:8]).replace(tzinfo=None)
    except Exception:
        try:
            return time.fromisoformat(text[:5]).replace(tzinfo=None)
        except Exception:
            return None


def format_date_sv(value, include_year=True):
    d = parse_date(value)
    if not d:
        return None
    return f"{d.day} {SV_MONTHS[d.month - 1]}" + (f" {d.year}" if include_year else "")


def _format_time(value):
    t = parse_time(value)
    return t.strftime("%H:%M") if t else None


def _responsible_name(raw):
    responsible = _first(raw, "responsible", "owner", "project_manager", "coordinator")
    if isinstance(responsible, dict):
        return str(_first(responsible, "name", "full_name", "display_name", default="") or "").strip() or None
    if responsible:
        return str(responsible).strip() or None
    return str(_first(raw, "responsible_name", "owner_name", default="") or "").strip() or None


def normalize_job(raw, now=None):
    if not isinstance(raw, dict):
        return None
    status = str(_first(raw, "status", default="") or "").strip().lower()
    if status not in {"confirmed", "ongoing"}:
        return None

    name = str(_first(raw, "name", "title", default="") or "").strip()
    if not name:
        return None

    event_date = _first(raw, "event_date", "date", "start_date")
    start_time = _first(raw, "event_start_time", "start_time")
    end_time = _first(raw, "event_end_time", "end_time")
    d = parse_date(event_date)
    st = parse_time(start_time)
    et = parse_time(end_time)
    place = str(_first(raw, "place", "venue", "location_name", default="") or "").strip() or None
    city = str(_first(raw, "city", "town", default="") or "").strip() or None
    address = str(_first(raw, "address", default="") or "").strip() or None

    if place and city:
        place_display = f"{place}, {city}"
    else:
        place_display = place or city or "Plats ej angiven"

    start_display = _format_time(start_time)
    end_display = _format_time(end_time)
    time_display = f"{start_display}–{end_display}" if start_display and end_display else (start_display or end_display)

    # UI-only "Pågår nu". Event dates/times are interpreted in Sweden local time.
    now = now or datetime.now(ZoneInfo("Europe/Stockholm"))
    is_now = False
    if d and d == now.date():
        local_t = now.timetz().replace(tzinfo=None)
        if st and et:
            is_now = st <= local_t <= et
        elif status == "ongoing":
            is_now = True
    status_label = str(_first(raw, "status_label", default="") or "").strip() or ("Bekräftat" if status == "confirmed" else "Genomförs")

    return {
        "id": str(_first(raw, "id", "job_id", default="") or "") or None,
        "number": str(_first(raw, "number", "job_number", default="") or "").strip() or None,
        "name": name,
        "status": status,
        "status_label": status_label,
        "event_date": str(event_date).strip() if event_date else None,
        "event_date_obj": d,
        "date_display": format_date_sv(event_date, include_year=True),
        "date_short": (f"{d.day} {SV_MONTHS[d.month - 1][:3]}" if d else "Datum saknas"),
        "event_start_time": str(start_time).strip() if start_time else None,
        "event_end_time": str(end_time).strip() if end_time else None,
        "time_display": time_display,
        "place": place,
        "city": city,
        "address": address,
        "place_display": place_display,
        "responsible_name": _responsible_name(raw),
        "is_now": is_now,
    }


def normalize_jobs(payload, now=None):
    rows = []
    for raw in _extract_rows(payload):
        row = normalize_job(raw, now=now)
        if row:
            rows.append(row)
    # Keep objects JSON-cacheable after sort; event_date_obj is removed later.
    rows.sort(key=lambda x: (
        x.get("event_date_obj") is None,
        x.get("event_date_obj") or date.max,
        parse_time(x.get("event_start_time")) or time.max,
        (x.get("name") or "").casefold(),
    ))
    for row in rows:
        row.pop("event_date_obj", None)
    return rows


class JobsService:
    def __init__(self, base_url, redis_client, pipeline_path="/api/internal/v1/jobs/pipeline", cache_ttl=180, stale_ttl=86400, timeout=5):
        self.base_url = base_url.rstrip("/")
        self.redis = redis_client
        self.pipeline_path = pipeline_path
        self.cache_ttl = int(cache_ttl)
        self.stale_ttl = int(stale_ttl)
        self.timeout = int(timeout)

    def _url(self):
        path = self.pipeline_path
        if path.startswith("http://") or path.startswith("https://"):
            if urlparse(path).netloc != urlparse(self.base_url).netloc:
                raise JobsUnavailable("CMS API host mismatch")
            return path
        return self.base_url + "/" + path.lstrip("/")

    def _cache_get(self, key):
        try:
            raw = self.redis.get(key)
            return json.loads(raw) if raw else None
        except Exception:
            return None

    def _cache_set(self, key, value, ttl):
        try:
            self.redis.setex(key, ttl, json.dumps(value, ensure_ascii=False))
        except Exception:
            pass

    def pipeline(self, access_token):
        if not access_token:
            raise JobsAuthExpired("missing access token")
        fresh_key = "hello:jobs:pipeline:fresh"
        stale_key = "hello:jobs:pipeline:stale"
        cached = self._cache_get(fresh_key)
        if cached is not None:
            return cached, {"source": "cache", "stale": False}
        try:
            resp = requests.get(
                self._url(),
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                timeout=self.timeout,
            )
            if resp.status_code in {401, 403}:
                raise JobsAuthExpired(f"CMS returned {resp.status_code}")
            resp.raise_for_status()
            data = normalize_jobs(resp.json())
            self._cache_set(fresh_key, data, self.cache_ttl)
            self._cache_set(stale_key, data, self.stale_ttl)
            return data, {"source": "live", "stale": False}
        except JobsAuthExpired:
            stale = self._cache_get(stale_key)
            if stale is not None:
                return stale, {"source": "stale", "stale": True, "auth_expired": True}
            raise
        except Exception as exc:
            stale = self._cache_get(stale_key)
            if stale is not None:
                return stale, {"source": "stale", "stale": True, "error": exc.__class__.__name__}
            raise JobsUnavailable(exc.__class__.__name__) from exc
