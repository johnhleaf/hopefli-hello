from datetime import datetime
from zoneinfo import ZoneInfo

from app.jobs import normalize_jobs


def test_jobs_normalization_sorting_and_statuses():
    payload = [
        {"id": 2, "name": "Senare", "status": "ongoing", "status_label": "Genomförs", "event_date": "2026-10-18", "event_start_time": "19:00:00", "city": "Malmö"},
        {"id": 1, "name": "Sommarfest Helsingborg", "status": "confirmed", "status_label": "Bekräftat", "event_date": "2026-10-12", "event_start_time": "18:00:00", "event_end_time": "23:00:00", "place": "Clarion Sea U", "city": "Helsingborg", "responsible": {"id": 3, "name": "John Henrysson"}},
        {"id": 3, "name": "Skall döljas", "status": "draft", "event_date": "2026-10-01"},
    ]
    rows = normalize_jobs(payload, now=datetime(2026, 9, 30, 12, 0, tzinfo=ZoneInfo("Europe/Stockholm")))
    assert [row["name"] for row in rows] == ["Sommarfest Helsingborg", "Senare"]
    assert rows[0]["time_display"] == "18:00–23:00"
    assert rows[0]["place_display"] == "Clarion Sea U, Helsingborg"
    assert rows[0]["responsible_name"] == "John Henrysson"
    assert rows[0]["status_label"] == "Bekräftat"


def test_jobs_missing_place_responsible_and_now():
    rows = normalize_jobs([{
        "name": "Pågående event", "status": "ongoing", "event_date": "2026-09-30",
        "event_start_time": "12:00:00", "event_end_time": "14:00:00",
    }], now=datetime(2026, 9, 30, 13, 0, tzinfo=ZoneInfo("Europe/Stockholm")))
    assert rows[0]["place_display"] == "Plats ej angiven"
    assert rows[0]["responsible_name"] is None
    assert rows[0]["is_now"] is True
