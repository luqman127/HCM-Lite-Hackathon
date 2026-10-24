# HCM Lite — Saylani Hackathon

A responsive Flask + SQLite web app built against the supplied HCM Lite challenge brief. It starts with **no demo employees or fake attendance**. On a fresh install, the first visitor creates the company and the first Admin account at `/first-run`, unless `ADMIN_EMAIL` and `ADMIN_PASSWORD` are both configured on the server.

## Features implemented

- **Auth & access:** Admin, HR and Employee roles; hashed passwords; first-run Admin setup; temporary employee passwords with mandatory change; password change; server-side route guards; session CSRF protection on POST forms.
- **Organization setup:** company, office start time, grace period, weekend days, office coordinates/radius, departments, leave types, holidays, HR logins; activate/deactivate accounts and reset passwords.
- **Employees:** employee registration and login creation; paginated/searchable directory; Employee 360 profile and HR/Admin edit; self-service phone/address editing; CSV export; CSV import with dry-run validation and all-or-nothing import.
- **Attendance:** server-stamped self check-in/out; duplicate check-in protection; late/grace, half-day and inferred absence rules; optional browser face detection + GPS geofence (server-side Haversine, radius and GPS-accuracy checks; no photo storage); employee correction requests; HR/Admin approve/reject workflow; notifications and audit records.
- **Leave:** working-day calculation excluding configured weekends/holidays; balance checks; overlap checks; approval quota revalidation; comments; pending-request cancellation; smart leave form for common English/Roman Urdu weekday phrasing with user confirmation before saving.
- **Payroll:** monthly drafts; HRA and medical allowance; join-date proration; absence, unpaid leave and half-day deductions; illustrative tax slabs from the brief; 3-lates-to-half-day bonus penalty; PDF payslips; Admin-only finalization; finalized run lock.
- **Dashboards & analytics:** live database KPIs, department/date filters, date-range summary action, absence anomaly flags and a transparent heuristic attrition-risk score (not a validated prediction).
- **AI assistant:** optional OpenAI-compatible hosted API called only from the server; allow-listed function tools for headcount, attendance, late records, leave summary/balance, payroll summary and employee search; role-scoped tool results; employee salary privacy guard; 20 requests/hour per user; 15-second provider timeout and local fallback; AI logs.
- **Comms & audit:** announcements, user notifications, audit events with before/after data, Admin-only audit viewer.

## Run locally (Python 3.10+)

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python app.py
```

Open `http://127.0.0.1:5000`. If no Admin is provisioned from environment variables, create the first Admin at `/first-run`. Use a unique strong password. Do not deploy the sample `SECRET_KEY`; set a long random value in the hosting provider's environment settings and set `COOKIE_SECURE=1` when serving over HTTPS.

## Optional hosted AI

Set `AI_API_KEY`, `AI_BASE_URL` and `AI_MODEL` in `.env` or hosting environment variables. The browser never receives the provider key. Without a key, the app uses the safe local rules-based assistant. The hosted model must support OpenAI-compatible chat completions and function calling.

## Automated checks

```bash
pip install -r requirements.txt
pip install pytest
pytest -q
python -m py_compile app.py
```

The test suite covers first-run setup, CSRF enforcement, employee-vs-employee profile isolation, the rule that Admin/HR cannot write attendance through the employee check-in endpoint, and camera-check-in server validation.

## Suggested five-minute demo

1. Start from a fresh database; create company and Admin. Set office hours, grace period, weekend, a department and leave types.
2. Create an HR account; log in as HR and register 2–3 employees (show temporary password and first-login change).
3. Log in as an employee, change password, check in/out, submit leave using Smart Leave, then submit a correction request.
4. Log in as HR, approve leave and an attendance correction, show live dashboards and CSV dry-run/import, then run payroll.
5. Log in as Admin, finalize payroll, download/show a payslip as the employee, ask AI a data question, test that employee salary data is refused, and open audit log.

## Known limitations / honest scope

- The browser camera + GPS geofence bonus is implemented using a public MediaPipe CDN/model; it requires HTTPS, camera/location permissions and internet access to load the model. Native mobile attendance, face matching to an enrolled employee, and liveness checks are not implemented. The server validates GPS accuracy, office radius and the claimed face-count, but client-side face detection is not a high-assurance identity check.
- The hosted AI integration supports allow-listed function calling, but model behavior depends on the configured provider/model and API availability. Without an API key, the assistant is rules-based rather than generative.
- Smart Leave uses deterministic weekday/date parsing for common English and Roman Urdu phrases, not an LLM JSON parser; ambiguous requests should be re-entered with explicit dates.
- Dark-mode/PWA, native mobile attendance, face matching to an enrolled employee, and liveness checks are not implemented. The attrition score is a transparent heuristic for the demo and must not be treated as a validated employment decision tool.
- This is a hackathon demo, not a production HR/payroll system. Before real deployment, add HTTPS, a production WSGI server, robust rate limiting, database backups, stricter validation and concurrency testing, privacy review, and verify payroll/tax rules for the intended jurisdiction. The tax slabs are illustrative because that is how the brief defines them.

## Submission checklist

- Push this folder to a public repository or share it with judges.
- Deploy the web app and set `SECRET_KEY`, database path, `APP_TIMEZONE` (default `Asia/Karachi`) and AI credentials in host environment settings (never commit real secrets).
- Test the hosted app from a fresh database and verify every demo step before sharing the live link.
- Submit repository and hosted app links on the Saylani LMS.
