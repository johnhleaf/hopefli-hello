from datetime import date
from app.staff import normalize_staff, normalize_away, upcoming_birthdays, employment_anniversaries


def test_staff_normalization_and_visibility():
    rows = normalize_staff({"staff": [
        {"id": 1, "name": "Anna Andersson", "email": "anna@example.com", "phone": "070 1", "birthday": "1990-10-17", "employment_start_date": "2024-10-01", "job_title": "Projektledare", "show_in_hello": True, "has_photo": True},
        {"id": 2, "name": "Dold Person", "show_in_hello": False},
    ]})
    assert len(rows) == 1
    assert rows[0]["name"] == "Anna Andersson"
    assert rows[0]["birthday_display"] == "17 oktober"
    assert rows[0]["employment_display"] == "1 oktober 2024"
    assert rows[0]["photo_available"] is True


def test_away_and_birthdays():
    away = normalize_away({"items": [{"staff_id": 1, "name": "Anna Andersson", "type": "Semester", "end_date": "2026-10-18"}]})
    assert away[0]["type"] == "Semester"
    assert away[0]["until_display"] == "18 oktober"

    people = normalize_staff([{"id": 1, "name": "Anna Andersson", "birthday": "1990-10-17", "employment_start_date": "2021-10-10"}])
    birthdays = upcoming_birthdays(people, today=date(2026, 9, 30), days=30)
    assert birthdays and birthdays[0]["display"] == "17 oktober"
    anniversaries = employment_anniversaries(people, today=date(2026, 9, 30), days=30)
    assert anniversaries and anniversaries[0]["years"] == 5
