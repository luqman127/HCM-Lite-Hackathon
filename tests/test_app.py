"""Smoke/security tests for the HCM Lite demo app. Run: pytest -q"""
import os
import re
import tempfile
from pathlib import Path

_tmp = tempfile.TemporaryDirectory()
os.environ["DATABASE_PATH"] = str(Path(_tmp.name) / "test_hcm.db")
os.environ["SECRET_KEY"] = "test-only-secret-key-not-for-production"
os.environ["ADMIN_EMAIL"] = ""
os.environ["ADMIN_PASSWORD"] = ""

import app as hcm

hcm.init_db()
hcm.app.config.update(TESTING=True)


def csrf(html):
    match = re.search(r'name="_csrf" value="([^"]+)"', html)
    assert match, "POST form should include a CSRF token"
    return match.group(1)


def test_first_run_csrf_and_employee_scope():
    client = hcm.app.test_client()
    page = client.get("/first-run")
    assert page.status_code == 200
    token = csrf(page.get_data(as_text=True))
    # State-changing requests without the token must fail.
    response = client.post("/first-run", data={"company": "Test Co", "email": "admin@test.local", "password": "StrongPassword123"})
    assert response.status_code == 400
    response = client.post("/first-run", data={"_csrf": token, "company": "Test Co", "email": "admin@test.local", "password": "StrongPassword123"})
    assert response.status_code == 302

    conn = hcm.sqlite3.connect(os.environ["DATABASE_PATH"])
    conn.execute("INSERT INTO departments(name) VALUES('Engineering')")
    admin_id = conn.execute("SELECT id FROM users WHERE email='admin@test.local'").fetchone()[0]
    for idx in (1, 2):
        email = f"employee{idx}@test.local"
        cur = conn.execute("INSERT INTO users(email,password,role,active,must_change) VALUES(?,?, 'Employee',1,0)", (email, hcm.generate_password_hash("EmployeePassword123")))
        conn.execute("INSERT INTO employees(user_id,code,name,email,department_id,designation,join_date,basic) VALUES(?,?,?,?,1,'Engineer','2026-01-01',50000)", (cur.lastrowid, f"E00{idx}", f"Employee {idx}", email))
    conn.commit(); conn.close()

    # Admin cannot record attendance on behalf of an employee through the self check-in endpoint.
    page = client.get("/attendance")
    assert page.status_code == 200
    token = csrf(page.get_data(as_text=True))
    assert client.post("/attendance", data={"_csrf": token, "action": "in", "employee_id": "1"}).status_code == 403

    # Employee session must not open another employee's profile.
    client.post("/logout", data={"_csrf": token})
    page = client.get("/login")
    token = csrf(page.get_data(as_text=True))
    response = client.post("/login", data={"_csrf": token, "email": "employee1@test.local", "password": "EmployeePassword123"})
    assert response.status_code == 302
    assert client.get("/employee/2").status_code == 403
    own_profile = client.get("/employee/1")
    assert own_profile.status_code == 200
    token = csrf(own_profile.get_data(as_text=True))
    conn = hcm.sqlite3.connect(os.environ["DATABASE_PATH"])
    conn.execute("UPDATE settings SET office_lat=24.8607,office_lng=67.0011,radius=150 WHERE id=1")
    conn.commit(); conn.close()
    # Server rejects a camera request that reports zero or multiple faces.
    rejected = client.post("/attendance/camera-checkin", data={"_csrf": token, "face_count": "2", "latitude": "24.8607", "longitude": "67.0011", "accuracy": "10"})
    assert rejected.status_code == 302
    conn = hcm.sqlite3.connect(os.environ["DATABASE_PATH"])
    assert conn.execute("SELECT COUNT(*) FROM attendance").fetchone()[0] == 0
    conn.close()
    accepted = client.post("/attendance/camera-checkin", data={"_csrf": token, "face_count": "1", "latitude": "24.8607", "longitude": "67.0011", "accuracy": "10"})
    assert accepted.status_code == 302
    conn = hcm.sqlite3.connect(os.environ["DATABASE_PATH"])
    assert conn.execute("SELECT source FROM attendance WHERE employee_id=1").fetchone()[0] == "camera"
    conn.close()
    duplicate = client.post("/attendance/camera-checkin", data={"_csrf": token, "face_count": "1", "latitude": "24.8607", "longitude": "67.0011", "accuracy": "10"})
    assert duplicate.status_code == 409

    # Leave overlap is rejected with the challenge's 422 validation status.
    start = hcm.local_today() + hcm.timedelta(days=1)
    while start.weekday() in {5, 6}:
        start += hcm.timedelta(days=1)
    leave_data = {"_csrf": token, "type": "Annual", "start": start.isoformat(), "end": start.isoformat(), "reason": "Test request"}
    assert client.post("/leave", data=leave_data).status_code == 302
    assert client.post("/leave", data=leave_data).status_code == 422
