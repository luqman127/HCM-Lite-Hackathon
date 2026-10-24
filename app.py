import os, io, csv, json, sqlite3, calendar, secrets
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo
from functools import wraps
from flask import Flask, g, request, redirect, url_for, render_template, session, flash, send_file, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import requests

load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-only-change-me")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "0").lower() in ("1", "true", "yes"))
DB = os.getenv("DATABASE_PATH", "hcm_lite.db")
ROLES = ("Admin", "HR", "Employee")

def local_now():
    """Naive local timestamp for the configured business timezone (Asia/Karachi by default)."""
    return datetime.now(ZoneInfo(os.getenv("APP_TIMEZONE", "Asia/Karachi"))).replace(tzinfo=None)

def local_today():
    return local_now().date()

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(_=None):
    conn = g.pop("db", None)
    if conn: conn.close()

def init_db():
    conn = sqlite3.connect(DB)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, active INTEGER DEFAULT 1, must_change INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1), company TEXT, office_start TEXT DEFAULT '09:00', grace INTEGER DEFAULT 15, weekend TEXT DEFAULT '5,6', office_lat REAL, office_lng REAL, radius REAL DEFAULT 150);
    CREATE TABLE IF NOT EXISTS departments(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
    CREATE TABLE IF NOT EXISTS employees(id INTEGER PRIMARY KEY, user_id INTEGER UNIQUE REFERENCES users(id), code TEXT UNIQUE, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, phone TEXT DEFAULT '', address TEXT DEFAULT '', department_id INTEGER REFERENCES departments(id), designation TEXT DEFAULT '', join_date TEXT, basic REAL DEFAULT 0, active INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS attendance(id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL REFERENCES employees(id), day TEXT NOT NULL, check_in TEXT, check_out TEXT, status TEXT NOT NULL, source TEXT DEFAULT 'web', UNIQUE(employee_id,day));
    CREATE TABLE IF NOT EXISTS leave_types(id INTEGER PRIMARY KEY, name TEXT UNIQUE, quota INTEGER);
    CREATE TABLE IF NOT EXISTS holidays(id INTEGER PRIMARY KEY, day TEXT UNIQUE, name TEXT);
    CREATE TABLE IF NOT EXISTS leave_requests(id INTEGER PRIMARY KEY, employee_id INTEGER REFERENCES employees(id), type TEXT, start TEXT, end TEXT, reason TEXT, days INTEGER, status TEXT DEFAULT 'Pending', comment TEXT DEFAULT '', created TEXT);
    CREATE TABLE IF NOT EXISTS payroll_runs(id INTEGER PRIMARY KEY, month TEXT UNIQUE, status TEXT DEFAULT 'Draft', created TEXT);
    CREATE TABLE IF NOT EXISTS payslips(id INTEGER PRIMARY KEY, run_id INTEGER REFERENCES payroll_runs(id), employee_id INTEGER REFERENCES employees(id), basic REAL, hra REAL, medical REAL, gross REAL, deductions REAL, tax REAL, net REAL, UNIQUE(run_id,employee_id));
    CREATE TABLE IF NOT EXISTS announcements(id INTEGER PRIMARY KEY, title TEXT, body TEXT, author INTEGER REFERENCES users(id), created TEXT);
    CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), message TEXT, created TEXT, read INTEGER DEFAULT 0);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, actor INTEGER, action TEXT, entity TEXT, entity_id INTEGER, before_json TEXT, after_json TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS ai_logs(id INTEGER PRIMARY KEY, user_id INTEGER, question TEXT, answer TEXT, created TEXT);
    CREATE TABLE IF NOT EXISTS attendance_corrections(id INTEGER PRIMARY KEY, employee_id INTEGER NOT NULL REFERENCES employees(id), day TEXT NOT NULL, requested_check_in TEXT, requested_check_out TEXT, reason TEXT NOT NULL, status TEXT DEFAULT 'Pending', comment TEXT DEFAULT '', created TEXT NOT NULL, reviewer INTEGER REFERENCES users(id));
    """)
    conn.execute("INSERT OR IGNORE INTO settings(id,company) VALUES(1,'HCM Lite Company')")
    for name, quota in [("Annual",14),("Sick",8),("Casual",10),("Unpaid",9999)]:
        conn.execute("INSERT OR IGNORE INTO leave_types(name,quota) VALUES(?,?)",(name,quota))
    email=os.getenv("ADMIN_EMAIL","").strip().lower()
    password=os.getenv("ADMIN_PASSWORD","")
    if email and password:
        conn.execute("INSERT OR IGNORE INTO users(email,password,role,active,must_change) VALUES(?,?,?,?,0)",
                     (email,generate_password_hash(password),"Admin",1))
    conn.commit(); conn.close()

def current_user():
    if "user_id" not in session: return None
    return db().execute("SELECT * FROM users WHERE id=? AND active=1",(session["user_id"],)).fetchone()

def error_page(message,status=422,back=None):
    return render_template("error.html",message=message,status=status,back=back or url_for("dashboard")),status

def employee_for_user(uid):
    return db().execute("SELECT * FROM employees WHERE user_id=?",(uid,)).fetchone()

def login_required(fn):
    @wraps(fn)
    def wrap(*a,**kw):
        if not current_user(): return redirect(url_for("login"))
        return fn(*a,**kw)
    return wrap

def roles(*allowed):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrap(*a,**kw):
            if current_user()["role"] not in allowed:
                flash("You do not have permission for that action.","error")
                return redirect(url_for("dashboard"))
            return fn(*a,**kw)
        return wrap
    return deco

def audit(action, entity, entity_id=None, before=None, after=None):
    u=current_user()
    db().execute("INSERT INTO audit(actor,action,entity,entity_id,before_json,after_json,created) VALUES(?,?,?,?,?,?,?)",
       (u["id"] if u else None,action,entity,entity_id,json.dumps(dict(before)) if before else None,
        json.dumps(after) if after else None,local_now().isoformat(timespec="seconds")))
    db().commit()

def emp_scope(sql, params=()):
    u=current_user()
    if u["role"]=="Employee":
        e=employee_for_user(u["id"])
        return sql + (" AND " if " WHERE " in sql.upper() else " WHERE ") + "employee_id=?", tuple(params)+(e["id"] if e else -1,)
    return sql,tuple(params)

@app.context_processor
def inject():
    if "_csrf_token" not in session: session["_csrf_token"]=secrets.token_urlsafe(32)
    return {"me":current_user(),"today":local_today().isoformat(),"csrf_token":lambda:session.get("_csrf_token","")}

@app.before_request
def protect_post_requests():
    if request.method=="POST":
        expected=session.get("_csrf_token",""); supplied=request.form.get("_csrf","")
        if not expected or not supplied or not secrets.compare_digest(expected,supplied):
            abort(400,description="Security token missing or expired. Refresh the page and try again.")

@app.route("/")
def home():
    if not db().execute("SELECT 1 FROM users WHERE role='Admin' LIMIT 1").fetchone(): return redirect(url_for("first_run"))
    return redirect(url_for("dashboard") if current_user() else url_for("login"))

@app.route("/first-run",methods=["GET","POST"])
def first_run():
    conn=db()
    if conn.execute("SELECT 1 FROM users WHERE role='Admin' LIMIT 1").fetchone(): return redirect(url_for("login"))
    if request.method=="POST":
        company=request.form.get("company","").strip(); email=request.form.get("email","").strip().lower(); password=request.form.get("password","")
        if not company or "@" not in email or len(password)<10:
            flash("Enter a company name, valid email, and password of at least 10 characters.","error")
        else:
            try:
                conn.execute("INSERT INTO users(email,password,role,active,must_change) VALUES(?,?, 'Admin',1,0)",(email,generate_password_hash(password)))
                conn.execute("UPDATE settings SET company=? WHERE id=1",(company,)); conn.commit()
                session.clear(); session["user_id"]=conn.execute("SELECT id FROM users WHERE email=?",(email,)).fetchone()["id"]
                audit("first_run","company",1,after={"company":company,"admin_email":email})
                return redirect(url_for("setup"))
            except sqlite3.IntegrityError: conn.rollback(); flash("That email is already registered.","error")
    return render_template("first_run.html")

@app.route("/login",methods=["GET","POST"])
def login():
    if not db().execute("SELECT 1 FROM users WHERE role='Admin' LIMIT 1").fetchone(): return redirect(url_for("first_run"))
    if request.method=="POST":
        u=db().execute("SELECT * FROM users WHERE email=? AND active=1",(request.form.get("email","").strip().lower(),)).fetchone()
        if u and check_password_hash(u["password"],request.form.get("password","")):
            session.clear(); session["user_id"]=u["id"]
            return redirect(url_for("change_password") if u["must_change"] else url_for("dashboard"))
        flash("Invalid email or password.","error")
    return render_template("login.html")

@app.route("/logout",methods=["POST"])
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/change-password",methods=["GET","POST"])
@login_required
def change_password():
    if request.method=="POST":
        pw=request.form.get("password","")
        if len(pw)<8: flash("Password must be at least 8 characters.","error")
        else:
            db().execute("UPDATE users SET password=?,must_change=0 WHERE id=?",(generate_password_hash(pw),current_user()["id"]))
            db().commit(); flash("Password changed.")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html")

@app.route("/dashboard")
@login_required
def dashboard():
    u=current_user(); conn=db()
    e=employee_for_user(u["id"]) if u["role"]=="Employee" else None
    if u["role"]=="Employee":
        att=conn.execute("SELECT * FROM attendance WHERE employee_id=? ORDER BY day DESC LIMIT 8",(e["id"],)).fetchall() if e else []
        leaves=conn.execute("SELECT * FROM leave_requests WHERE employee_id=? ORDER BY id DESC LIMIT 5",(e["id"],)).fetchall() if e else []
        balance={}
        if e:
            for lt in conn.execute("SELECT * FROM leave_types"):
                used=conn.execute("SELECT COALESCE(SUM(days),0) n FROM leave_requests WHERE employee_id=? AND type=? AND status='Approved' AND substr(start,1,4)=?",
                                  (e["id"],lt["name"],str(local_today().year))).fetchone()["n"]
                balance[lt["name"]]=max(0,lt["quota"]-used) if lt["name"]!="Unpaid" else "Unlimited"
        slip=conn.execute("SELECT p.*,r.month FROM payslips p JOIN payroll_runs r ON r.id=p.run_id WHERE p.employee_id=? ORDER BY r.month DESC LIMIT 1",(e["id"],)).fetchone() if e else None
        return render_template("dashboard.html", role=u["role"], employee=e, att=att, leaves=leaves, balance=balance, slip=slip)
    stats={
      "employees":conn.execute("SELECT COUNT(*) n FROM employees WHERE active=1").fetchone()["n"],
      "present":conn.execute("SELECT COUNT(*) n FROM attendance WHERE day=? AND status IN ('Present','Late','Missing checkout','Half day')",(local_today().isoformat(),)).fetchone()["n"],
      "late":conn.execute("SELECT COUNT(*) n FROM attendance WHERE day=? AND status='Late'",(local_today().isoformat(),)).fetchone()["n"],
      "on_leave":conn.execute("SELECT COUNT(DISTINCT employee_id) n FROM leave_requests WHERE status='Approved' AND start<=? AND end>=?",(local_today().isoformat(),local_today().isoformat())).fetchone()["n"],
      "pending":conn.execute("SELECT COUNT(*) n FROM leave_requests WHERE status='Pending'").fetchone()["n"],
      "departments":conn.execute("SELECT d.name,COUNT(e.id) count FROM departments d LEFT JOIN employees e ON e.department_id=d.id AND e.active=1 GROUP BY d.id").fetchall(),
      "payroll_cost":0,"average_salary":0,"attrition_rate":0,
      "announcements":conn.execute("SELECT a.*,u.email FROM announcements a LEFT JOIN users u ON u.id=a.author ORDER BY a.id DESC LIMIT 5").fetchall()
    }
    latest=conn.execute("SELECT id FROM payroll_runs ORDER BY month DESC LIMIT 1").fetchone()
    stats["payroll_cost"]=conn.execute("SELECT COALESCE(SUM(gross),0) n FROM payslips WHERE run_id=?",(latest["id"],)).fetchone()["n"] if latest else 0
    stats["average_salary"]=conn.execute("SELECT COALESCE(AVG(basic),0) n FROM employees WHERE active=1").fetchone()["n"]
    counts=conn.execute("SELECT COUNT(*) total,SUM(CASE WHEN active=0 THEN 1 ELSE 0 END) inactive FROM employees").fetchone()
    stats["attrition_rate"]=(counts["inactive"] or 0)*100/counts["total"] if counts["total"] else 0
    return render_template("dashboard.html",role=u["role"],stats=stats)

@app.route("/setup",methods=["GET","POST"])
@roles("Admin")
def setup():
    if request.method=="POST":
        try:
            company=request.form.get("company","HCM Lite Company").strip(); office_start=request.form.get("office_start","09:00")
            datetime.strptime(office_start,"%H:%M"); grace=int(request.form.get("grace",15)); radius=float(request.form.get("radius",150))
            weekend=request.form.get("weekend","5,6").strip(); weekend_days={int(x.strip()) for x in weekend.split(",") if x.strip()!=""}
            lat=float(request.form["office_lat"]) if request.form.get("office_lat") else None; lng=float(request.form["office_lng"]) if request.form.get("office_lng") else None
            if not company or grace<0 or radius<=0 or not weekend_days or any(x<0 or x>6 for x in weekend_days) or (lat is None)!=(lng is None) or (lat is not None and not (-90<=lat<=90 and -180<=lng<=180)): raise ValueError("Check company, grace, weekend days, radius and coordinates")
            db().execute("UPDATE settings SET company=?,office_start=?,grace=?,weekend=?,office_lat=?,office_lng=?,radius=? WHERE id=1",(company,office_start,grace,",".join(str(x) for x in sorted(weekend_days)),lat,lng,radius))
            db().commit(); audit("update","settings",1,after={"company":company}); flash("Company settings saved.")
        except (ValueError,TypeError) as ex: db().rollback(); flash("Invalid company settings: "+str(ex),"error")
    settings=db().execute("SELECT * FROM settings WHERE id=1").fetchone()
    depts=db().execute("SELECT * FROM departments ORDER BY name").fetchall()
    types=db().execute("SELECT * FROM leave_types ORDER BY id").fetchall()
    return render_template("setup.html",settings=settings,depts=depts,types=types)

@app.route("/departments",methods=["POST"])
@roles("Admin")
def add_department():
    name=request.form.get("name","").strip()
    try:
        if name: db().execute("INSERT INTO departments(name) VALUES(?)",(name,)); db().commit(); audit("create","department",after={"name":name}); flash("Department added.")
    except sqlite3.IntegrityError: flash("Department already exists.","error")
    return redirect(url_for("setup"))

@app.route("/leave-types",methods=["POST"])
@roles("Admin")
def add_leave_type():
    name=request.form.get("name","").strip()
    try:
        quota=int(request.form.get("quota",0))
        if not name or quota<0: raise ValueError("Name and non-negative quota required")
        db().execute("INSERT INTO leave_types(name,quota) VALUES(?,?)",(name,quota))
        db().commit(); audit("create","leave_type",after={"name":name}); flash("Leave type added.")
    except (sqlite3.IntegrityError,ValueError): flash("Invalid or duplicate leave type.","error")
    return redirect(url_for("setup"))

@app.route("/users",methods=["GET","POST"])
@roles("Admin")
def users():
    if request.method=="POST":
        email=request.form.get("email","").strip().lower(); pw=request.form.get("password","")
        role=request.form.get("role","HR")
        if role not in ("HR","Employee") or len(pw)<8 or "@" not in email or "." not in email.split("@")[-1]:
            flash("Choose HR/Employee, a valid email and a password of at least 8 characters.","error")
        else:
            try:
                db().execute("INSERT INTO users(email,password,role,must_change) VALUES(?,?,?,1)",(email,generate_password_hash(pw),role))
                db().commit(); audit("create","user",after={"email":email,"role":role}); flash("Login created. Share the temporary password securely.")
            except sqlite3.IntegrityError: flash("Email already exists.","error")
    return render_template("users.html",users=db().execute("SELECT id,email,role,active,must_change FROM users ORDER BY id DESC").fetchall())

@app.route("/users/<int:uid>/action",methods=["POST"])
@roles("Admin")
def user_action(uid):
    conn=db(); target=conn.execute("SELECT * FROM users WHERE id=?",(uid,)).fetchone()
    if not target: return "Not found",404
    action=request.form.get("action")
    if target["id"]==current_user()["id"] and action in ("deactivate","reset"): flash("For safety, you cannot deactivate or reset your own active session here.","error")
    elif action=="deactivate":
        if target["role"]=="Admin" and conn.execute("SELECT COUNT(*) n FROM users WHERE role='Admin' AND active=1").fetchone()["n"]<=1: flash("Cannot deactivate the last active Admin.","error")
        else:
            conn.execute("UPDATE users SET active=0 WHERE id=?",(uid,)); conn.execute("UPDATE employees SET active=0 WHERE user_id=?",(uid,)); conn.commit(); audit("deactivate","user",uid,before={"active":target["active"]},after={"active":0}); flash("User deactivated.")
    elif action=="activate":
        conn.execute("UPDATE users SET active=1 WHERE id=?",(uid,)); conn.execute("UPDATE employees SET active=1 WHERE user_id=?",(uid,)); conn.commit(); audit("activate","user",uid,before={"active":target["active"]},after={"active":1}); flash("User activated.")
    elif action=="reset":
        temp=secrets.token_urlsafe(9); conn.execute("UPDATE users SET password=?,must_change=1 WHERE id=?",(generate_password_hash(temp),uid)); conn.commit(); audit("reset_password","user",uid); flash(f"Temporary password for {target['email']}: {temp}")
    else: flash("Unknown action.","error")
    return redirect(url_for("users"))

@app.route("/employees",methods=["GET","POST"])
@roles("Admin","HR")
def employees():
    conn=db()
    if request.method=="POST":
        f=request.form; email=f.get("email","").strip().lower(); name=f.get("name","").strip(); code=f.get("code","").strip()
        try:
            if not code or not name or "@" not in email or "." not in email.split("@")[-1]: raise ValueError("Enter a code, name and valid email")
            basic_value=float(f.get("basic",0))
            if basic_value<=0: raise ValueError("Salary must be greater than zero")
            join_value=f.get("join_date") or local_today().isoformat(); datetime.strptime(join_value,"%Y-%m-%d")
            dept_value=int(f["department_id"]) if f.get("department_id") else None
            if dept_value and not conn.execute("SELECT 1 FROM departments WHERE id=?",(dept_value,)).fetchone(): raise ValueError("Select a valid department")
            pw=secrets.token_urlsafe(9)
            cur=conn.execute("INSERT INTO users(email,password,role,must_change) VALUES(?,?,?,1)",(email,generate_password_hash(pw),"Employee"))
            cur=conn.execute("""INSERT INTO employees(user_id,code,name,email,phone,address,department_id,designation,join_date,basic)
              VALUES(?,?,?,?,?,?,?,?,?,?)""",(cur.lastrowid,code,name,email,f.get("phone",""),f.get("address",""),
              dept_value,f.get("designation",""),join_value,basic_value))
            conn.commit(); audit("create","employee",cur.lastrowid,after={"name":name,"email":email})
            flash(f"Employee created. Temporary password: {pw}")
        except (sqlite3.IntegrityError,ValueError) as ex:
            conn.rollback(); flash("Could not create employee: "+str(ex)+". Check duplicate email/code and required fields.","error")
    q=request.args.get("q","").strip()
    try: page=max(1,int(request.args.get("page",1)))
    except ValueError: page=1
    sql="""SELECT e.*,d.name department FROM employees e LEFT JOIN departments d ON d.id=e.department_id"""
    where=""; params=()
    if q: where=" WHERE e.name LIKE ? OR e.email LIKE ? OR e.code LIKE ?"; params=(f"%{q}%",)*3
    total=conn.execute("SELECT COUNT(*) n FROM employees e"+where,params).fetchone()["n"]
    pages=max(1,(total+24)//25); page=min(page,pages)
    rows=conn.execute(sql+where+" ORDER BY e.id DESC LIMIT 25 OFFSET ?",params+((page-1)*25,)).fetchall()
    depts=conn.execute("SELECT * FROM departments ORDER BY name").fetchall()
    return render_template("employees.html",employees=rows,depts=depts,q=q,page=page,pages=pages,total=total)

@app.route("/employee/<int:eid>/edit",methods=["GET","POST"])
@roles("Admin","HR")
def edit_employee(eid):
    conn=db(); e=conn.execute("SELECT * FROM employees WHERE id=?",(eid,)).fetchone()
    if not e: return "Not found",404
    if request.method=="POST":
        f=request.form; name=f.get("name","").strip(); email=f.get("email","").strip().lower(); code=f.get("code","").strip()
        try:
            if not name or not code or "@" not in email or "." not in email.split("@")[-1]: raise ValueError("Name, code and valid email are required")
            basic=float(f.get("basic",0))
            if basic<=0: raise ValueError("Salary must be greater than zero")
            join_date=f.get("join_date",""); datetime.strptime(join_date,"%Y-%m-%d")
            dept=int(f["department_id"]) if f.get("department_id") else None
            if dept and not conn.execute("SELECT 1 FROM departments WHERE id=?",(dept,)).fetchone(): raise ValueError("Unknown department")
            conflict=conn.execute("SELECT id FROM employees WHERE id!=? AND (email=? OR code=?)",(eid,email,code)).fetchone()
            if conflict: raise ValueError("Email or employee code already belongs to another employee")
            before=dict(e)
            conn.execute("UPDATE employees SET code=?,name=?,email=?,phone=?,address=?,department_id=?,designation=?,join_date=?,basic=? WHERE id=?",(code,name,email,f.get("phone","").strip(),f.get("address","").strip(),dept,f.get("designation","").strip(),join_date,basic,eid))
            conn.execute("UPDATE users SET email=? WHERE id=?",(email,e["user_id"]))
            conn.commit(); audit("update","employee",eid,before=before,after={"name":name,"email":email,"code":code,"basic":basic}); flash("Employee details updated."); return redirect(url_for("employee_profile",eid=eid))
        except (ValueError,sqlite3.IntegrityError) as ex: conn.rollback(); flash("Could not update employee: "+str(ex),"error")
        e=conn.execute("SELECT * FROM employees WHERE id=?",(eid,)).fetchone()
    depts=conn.execute("SELECT * FROM departments ORDER BY name").fetchall()
    return render_template("edit_employee.html",e=e,depts=depts)

@app.route("/employee/<int:eid>")
@roles("Admin","HR","Employee")
def employee_profile(eid):
    u=current_user(); e=db().execute("SELECT e.*,d.name department FROM employees e LEFT JOIN departments d ON d.id=e.department_id WHERE e.id=?",(eid,)).fetchone()
    if not e: return "Not found",404
    if u["role"]=="Employee" and (not employee_for_user(u["id"]) or employee_for_user(u["id"])["id"]!=eid): return "Forbidden",403
    return render_template("employee_profile.html",e=e)

@app.route("/attendance/camera-checkin",methods=["POST"])
@roles("Employee")
def camera_checkin():
    e=employee_for_user(current_user()["id"]); conn=db()
    if not e or not e["active"]: return "Employee profile not found or inactive",403
    try:
        faces=int(request.form.get("face_count","0")); lat=float(request.form.get("latitude","")); lng=float(request.form.get("longitude","")); accuracy=float(request.form.get("accuracy",""))
        if not (-90<=lat<=90 and -180<=lng<=180 and 0<accuracy<=100): raise ValueError()
    except (ValueError,TypeError): flash("Camera check-in needs valid GPS coordinates with accuracy of 100 m or better.","error"); return redirect(url_for("attendance"))
    if faces!=1: flash("Camera check-in requires exactly one detected face. No photo is uploaded or stored.","error"); return redirect(url_for("attendance"))
    settings=conn.execute("SELECT * FROM settings WHERE id=1").fetchone()
    if settings["office_lat"] is None or settings["office_lng"] is None: flash("Admin must configure office latitude and longitude first.","error"); return redirect(url_for("attendance"))
    from math import radians, sin, cos, asin, sqrt
    lat1,lon1,lat2,lon2=map(radians,[settings["office_lat"],settings["office_lng"],lat,lng])
    dlat=lat2-lat1; dlon=lon2-lon1
    h=sin(dlat/2)**2+cos(lat1)*cos(lat2)*sin(dlon/2)**2
    distance=6371000*2*asin(sqrt(min(1,h)))
    if distance>float(settings["radius"] or 150): flash(f"Outside the office geofence ({distance:.0f} m; limit {settings['radius']:.0f} m). Use an HR correction if this is an error.","error"); return redirect(url_for("attendance"))
    day=local_today().isoformat(); now=local_now(); existing=conn.execute("SELECT id FROM attendance WHERE employee_id=? AND day=?",(e["id"],day)).fetchone()
    if existing: return error_page("A check-in already exists for today.",409,url_for("attendance"))
    conn.execute("UPDATE attendance SET status='Missing checkout' WHERE employee_id=? AND day<? AND check_in IS NOT NULL AND check_out IS NULL AND status IN ('Present','Late')",(e["id"],day))
    start=datetime.combine(local_today(),datetime.strptime(settings["office_start"],"%H:%M").time())+timedelta(minutes=settings["grace"])
    status="Late" if now>start else "Present"
    conn.execute("INSERT INTO attendance(employee_id,day,check_in,status,source) VALUES(?,?,?,?, 'camera')",(e["id"],day,now.isoformat(timespec="minutes"),status))
    conn.commit(); audit("camera_check_in","attendance",e["id"],after={"day":day,"time":now.isoformat(timespec="minutes"),"distance_m":round(distance),"gps_accuracy_m":round(accuracy)})
    flash(f"Camera check-in accepted ({distance:.0f} m from office; GPS accuracy {accuracy:.0f} m). No image was stored.")
    return redirect(url_for("attendance"))

@app.route("/attendance",methods=["GET","POST"])
@roles("HR","Employee","Admin")
def attendance():
    u=current_user(); conn=db()
    if request.method=="POST":
        if u["role"]!="Employee": return "Attendance must be recorded by the employee; use the correction workflow for changes.",403
        e=employee_for_user(u["id"])
        eid=e["id"] if e else 0
        if not conn.execute("SELECT id FROM employees WHERE id=? AND active=1",(eid,)).fetchone(): return "Employee not found",404
        day=local_today().isoformat(); now=local_now()
        settings=conn.execute("SELECT * FROM settings WHERE id=1").fetchone()
        row=conn.execute("SELECT * FROM attendance WHERE employee_id=? AND day=?",(eid,day)).fetchone()
        action=request.form.get("action","in")
        if action=="in":
            if row: return error_page("A check-in already exists for today.",409,url_for("attendance"))
            else:
                conn.execute("UPDATE attendance SET status='Missing checkout' WHERE employee_id=? AND day<? AND check_in IS NOT NULL AND check_out IS NULL AND status IN ('Present','Late')",(eid,day))
                start=datetime.strptime(settings["office_start"],"%H:%M").time()
                late=now.time()>((datetime.combine(local_today(),start)+timedelta(minutes=settings["grace"])).time())
                conn.execute("INSERT INTO attendance(employee_id,day,check_in,status) VALUES(?,?,?,?)",(eid,day,now.isoformat(timespec="minutes"),"Late" if late else "Present"))
                conn.commit(); audit("check_in","attendance",eid,after={"day":day,"time":now.isoformat()}); flash("Checked in.")
        else:
            if not row or row["check_out"]: flash("No open check-in found.","error")
            else:
                hours=(now-datetime.fromisoformat(row["check_in"])).total_seconds()/3600
                status="Half day" if hours<5 else row["status"]
                conn.execute("UPDATE attendance SET check_out=?,status=? WHERE id=?",(now.isoformat(timespec="minutes"),status,row["id"]))
                conn.commit(); audit("check_out","attendance",row["id"],after={"time":now.isoformat(),"status":status}); flash("Checked out.")
        return redirect(url_for("attendance"))
    start_day=request.args.get("from",local_today().replace(day=1).isoformat())
    try: datetime.strptime(start_day,"%Y-%m-%d")
    except ValueError: start_day=local_today().replace(day=1).isoformat()
    end_day=local_today().isoformat()
    sql="""SELECT a.*,e.name,e.code FROM attendance a JOIN employees e ON e.id=a.employee_id WHERE a.day BETWEEN ? AND ?"""
    params=(start_day,end_day)
    own=employee_for_user(u["id"]) if u["role"]=="Employee" else None
    if u["role"]=="Employee": sql+=" AND a.employee_id=?"; params+=(own["id"] if own else -1,)
    actual=[dict(r) for r in conn.execute(sql+" ORDER BY a.day DESC,a.id DESC LIMIT 1000",params).fetchall()]
    people=conn.execute("SELECT id,name,code,join_date FROM employees WHERE active=1"+(" AND id=?" if own else "")+" ORDER BY name",(own["id"],) if own else ()).fetchall()
    recorded={(r["employee_id"],r["day"]) for r in conn.execute("SELECT employee_id,day FROM attendance WHERE day BETWEEN ? AND ?",(start_day,end_day)).fetchall()}
    approved=conn.execute("SELECT employee_id,start,end FROM leave_requests WHERE status='Approved' AND NOT(end<? OR start>?)",(start_day,end_day)).fetchall()
    leave_map={}
    for lv in approved: leave_map.setdefault(lv["employee_id"],[]).append((lv["start"],lv["end"]))
    settings=conn.execute("SELECT weekend FROM settings WHERE id=1").fetchone(); weekend=set(map(int,settings["weekend"].split(",")))
    holidays={r["day"] for r in conn.execute("SELECT day FROM holidays WHERE day BETWEEN ? AND ?",(start_day,end_day)).fetchall()}
    day_cursor=datetime.strptime(start_day,"%Y-%m-%d").date(); last_day=local_today(); inferred=[]
    while day_cursor<=last_day:
        ds=day_cursor.isoformat()
        if day_cursor.weekday() not in weekend and ds not in holidays:
            for person in people:
                if person["join_date"] and person["join_date"]>ds: continue
                key=(person["id"],ds)
                on_leave=any(a<=ds<=b for a,b in leave_map.get(person["id"],[]))
                if key not in recorded and not on_leave:
                    inferred.append({"id":-1,"employee_id":person["id"],"day":ds,"check_in":None,"check_out":None,"status":"Absent","name":person["name"],"code":person["code"],"source":"inferred"})
        day_cursor+=timedelta(days=1)
    rows=sorted(actual+inferred,key=lambda r:(r["day"],r.get("id",0)),reverse=True)[:200]
    staff=conn.execute("SELECT id,name,code FROM employees WHERE active=1 ORDER BY name").fetchall() if u["role"]!="Employee" else []
    corrections_sql="SELECT c.*,e.name,e.code FROM attendance_corrections c JOIN employees e ON e.id=c.employee_id"
    corrections_params=()
    if u["role"]=="Employee": corrections_sql+=" WHERE c.employee_id=?"; corrections_params=(own["id"] if own else -1,)
    corrections=conn.execute(corrections_sql+" ORDER BY c.id DESC LIMIT 100",corrections_params).fetchall()
    return render_template("attendance.html",rows=rows,staff=staff,own=own,corrections=corrections)

def working_days(start,end):
    holidays={r["day"] for r in db().execute("SELECT day FROM holidays WHERE day BETWEEN ? AND ?",(start,end))}
    weekend=set(map(int,db().execute("SELECT weekend FROM settings WHERE id=1").fetchone()["weekend"].split(",")))
    d=datetime.strptime(start,"%Y-%m-%d").date(); stop=datetime.strptime(end,"%Y-%m-%d").date(); count=0
    while d<=stop:
        if d.weekday() not in weekend and d.isoformat() not in holidays: count+=1
        d+=timedelta(days=1)
    return count

@app.route("/leave",methods=["GET","POST"])
@roles("Admin","HR","Employee")
def leave():
    u=current_user(); conn=db()
    if request.method=="POST":
        if u["role"]!="Employee": return "Attendance must be recorded by the employee; use the correction workflow for changes.",403
        e=employee_for_user(u["id"])
        eid=e["id"] if e else 0
        typ=request.form.get("type","Casual"); start=request.form.get("start",""); end=request.form.get("end",""); reason=request.form.get("reason","").strip()
        try:
            days=working_days(start,end)
            if end<start or days<=0: raise ValueError()
            overlap=conn.execute("SELECT id FROM leave_requests WHERE employee_id=? AND status IN ('Pending','Approved') AND NOT(end<? OR start>?)",(eid,start,end)).fetchone()
            lt=conn.execute("SELECT quota FROM leave_types WHERE name=?",(typ,)).fetchone()
            if not lt: raise ValueError()
            if overlap: return error_page("Leave overlaps another pending/approved request.",422,url_for("leave"))
            else:
                used=conn.execute("SELECT COALESCE(SUM(days),0) n FROM leave_requests WHERE employee_id=? AND type=? AND status='Approved' AND substr(start,1,4)=?",(eid,typ,start[:4])).fetchone()["n"]
                if typ!="Unpaid" and used+days>lt["quota"]: return error_page("Leave balance is insufficient.",422,url_for("leave"))
                else:
                    conn.execute("INSERT INTO leave_requests(employee_id,type,start,end,reason,days,status,created) VALUES(?,?,?,?,?,?,?,?)",(eid,typ,start,end,reason,days,"Pending",local_now().isoformat(timespec="seconds")))
                    conn.commit(); audit("create","leave_request",after={"employee_id":eid,"type":typ,"start":start,"end":end}); flash("Leave request submitted.")
        except (ValueError,TypeError): return error_page("Enter valid dates and leave type.",422,url_for("leave"))
        return redirect(url_for("leave"))
    sql="""SELECT l.*,e.name,e.code FROM leave_requests l JOIN employees e ON e.id=l.employee_id"""
    params=()
    if u["role"]=="Employee":
        e=employee_for_user(u["id"]); sql+=" WHERE l.employee_id=?"; params=(e["id"] if e else -1,)
    rows=conn.execute(sql+" ORDER BY l.id DESC",params).fetchall()
    staff=conn.execute("SELECT id,name FROM employees WHERE active=1 ORDER BY name").fetchall() if u["role"]!="Employee" else []
    types=conn.execute("SELECT * FROM leave_types ORDER BY id").fetchall()
    return render_template("leave.html",rows=rows,staff=staff,types=types)

@app.route("/leave/<int:lid>/decision",methods=["POST"])
@roles("HR","Admin")
def leave_decision(lid):
    conn=db(); row=conn.execute("SELECT * FROM leave_requests WHERE id=?",(lid,)).fetchone()
    if not row: return "Not found",404
    status=request.form.get("status")
    if status not in ("Approved","Rejected"): return "Invalid status",400
    if row["status"]!="Pending": return "Request already decided",409
    if status=="Approved":
        other=conn.execute("SELECT id FROM leave_requests WHERE employee_id=? AND id!=? AND status='Approved' AND NOT(end<? OR start>?)",(row["employee_id"],lid,row["start"],row["end"])).fetchone()
        if other: flash("Cannot approve overlapping approved leave.","error"); return redirect(url_for("leave"))
        lt=conn.execute("SELECT quota FROM leave_types WHERE name=?",(row["type"],)).fetchone()
        if lt and row["type"].lower()!="unpaid":
            used=conn.execute("SELECT COALESCE(SUM(days),0) n FROM leave_requests WHERE employee_id=? AND type=? AND status='Approved' AND substr(start,1,4)=?",(row["employee_id"],row["type"],row["start"][:4])).fetchone()["n"]
            if used+row["days"]>lt["quota"]: flash("Cannot approve: leave quota would be exceeded.","error"); return redirect(url_for("leave"))
    conn.execute("UPDATE leave_requests SET status=?,comment=? WHERE id=? AND status='Pending'",(status,request.form.get("comment",""),lid))
    conn.execute("INSERT INTO notifications(user_id,message,created) SELECT user_id,?,? FROM employees WHERE id=?",
                 (f"Leave request {status.lower()}: {row['start']} to {row['end']}",local_now().isoformat(timespec="seconds"),row["employee_id"]))
    conn.commit(); audit("leave_"+status.lower(),"leave_request",lid,before=dict(row),after={"status":status}); flash("Leave decision saved.")
    return redirect(url_for("leave"))

@app.route("/leave/<int:lid>/cancel",methods=["POST"])
@login_required
def cancel_leave(lid):
    u=current_user(); conn=db(); row=conn.execute("SELECT * FROM leave_requests WHERE id=?",(lid,)).fetchone()
    if not row: return "Not found",404
    if u["role"]=="Employee":
        e=employee_for_user(u["id"])
        if not e or e["id"]!=row["employee_id"]: return "Forbidden",403
    elif u["role"] not in ("Admin","HR"): return "Forbidden",403
    if row["status"]!="Pending": flash("Only pending requests can be cancelled.","error")
    else:
        conn.execute("UPDATE leave_requests SET status='Cancelled' WHERE id=? AND status='Pending'",(lid,)); conn.commit()
        audit("cancel","leave_request",lid,before=dict(row),after={"status":"Cancelled"}); flash("Leave request cancelled.")
    return redirect(url_for("leave"))

@app.route("/attendance/correction",methods=["POST"])
@roles("Employee")
def attendance_correction():
    e=employee_for_user(current_user()["id"])
    if not e: return "Employee profile not found",404
    day=request.form.get("day",""); reason=request.form.get("reason","").strip()
    try: datetime.strptime(day,"%Y-%m-%d")
    except ValueError: flash("Choose a valid date.","error"); return redirect(url_for("attendance"))
    if not reason: flash("A reason is required.","error"); return redirect(url_for("attendance"))
    conn=db()
    if conn.execute("SELECT id FROM attendance_corrections WHERE employee_id=? AND day=? AND status='Pending'",(e["id"],day)).fetchone():
        flash("A correction request for this date is already pending.","error")
    else:
        cur=conn.execute("INSERT INTO attendance_corrections(employee_id,day,requested_check_in,requested_check_out,reason,created) VALUES(?,?,?,?,?,?)",(e["id"],day,request.form.get("check_in") or None,request.form.get("check_out") or None,reason,local_now().isoformat(timespec="seconds")))
        conn.commit(); audit("create","attendance_correction",cur.lastrowid,after={"employee_id":e["id"],"day":day}); flash("Correction request sent to HR.")
    return redirect(url_for("attendance"))

@app.route("/attendance/correction/<int:cid>/decision",methods=["POST"])
@roles("HR","Admin")
def attendance_correction_decision(cid):
    conn=db(); row=conn.execute("SELECT * FROM attendance_corrections WHERE id=?",(cid,)).fetchone()
    if not row: return "Not found",404
    status=request.form.get("status")
    if status not in ("Approved","Rejected") or row["status"]!="Pending": return "Invalid or already decided request",409
    before=dict(row); comment=request.form.get("comment","").strip()
    if status=="Approved":
        existing=conn.execute("SELECT * FROM attendance WHERE employee_id=? AND day=?",(row["employee_id"],row["day"])).fetchone()
        ci=row["requested_check_in"]; co=row["requested_check_out"]
        if ci:
            try: datetime.fromisoformat(ci)
            except ValueError: return "Check-in must be ISO date/time",400
        if co:
            try: datetime.fromisoformat(co)
            except ValueError: return "Check-out must be ISO date/time",400
        if not ci and not co: return error_page("Provide at least one corrected check-in or check-out time.",422,url_for("attendance"))
        effective_ci=ci or (existing["check_in"] if existing else None); effective_co=co or (existing["check_out"] if existing else None)
        if not existing and not effective_ci: return error_page("A new attendance record needs a check-in time.",422,url_for("attendance"))
        if effective_ci and effective_co and datetime.fromisoformat(effective_co)<datetime.fromisoformat(effective_ci): return error_page("Check-out must be after check-in.",422,url_for("attendance"))
        status_att="Present"
        if effective_ci:
            settings=conn.execute("SELECT * FROM settings WHERE id=1").fetchone(); dt=datetime.fromisoformat(effective_ci)
            start=datetime.combine(dt.date(),datetime.strptime(settings["office_start"],"%H:%M").time())+timedelta(minutes=settings["grace"])
            if dt>start: status_att="Late"
        if effective_ci and effective_co and (datetime.fromisoformat(effective_co)-datetime.fromisoformat(effective_ci)).total_seconds()<18000: status_att="Half day"
        if existing: conn.execute("UPDATE attendance SET check_in=COALESCE(?,check_in),check_out=COALESCE(?,check_out),status=? WHERE id=?",(ci,co,status_att,existing["id"]))
        elif effective_ci: conn.execute("INSERT INTO attendance(employee_id,day,check_in,check_out,status,source) VALUES(?,?,?,?,?,'correction')",(row["employee_id"],row["day"],effective_ci,effective_co,status_att))
    conn.execute("UPDATE attendance_corrections SET status=?,comment=?,reviewer=? WHERE id=?",(status,comment,current_user()["id"],cid))
    conn.execute("INSERT INTO notifications(user_id,message,created) SELECT user_id,?,? FROM employees WHERE id=?",(f"Attendance correction for {row['day']}: {status.lower()}",local_now().isoformat(timespec="seconds"),row["employee_id"]))
    conn.commit(); audit("attendance_correction_"+status.lower(),"attendance_correction",cid,before=before,after={"status":status,"comment":comment}); flash("Correction decision saved.")
    return redirect(url_for("attendance"))

@app.route("/employees/import",methods=["GET","POST"])
@roles("Admin","HR")
def import_employees():
    report=None
    if request.method=="POST":
        upload=request.files.get("file")
        if not upload or not upload.filename.lower().endswith(".csv"):
            flash("Upload a CSV file.","error")
        else:
            try:
                reader=csv.DictReader(io.StringIO(upload.stream.read().decode("utf-8-sig")))
                required={"code","name","email","department","designation","join_date","basic"}
                if not reader.fieldnames or not required.issubset(set(reader.fieldnames)): raise ValueError("CSV headers required: "+", ".join(sorted(required)))
                seen_codes=set(); seen_emails=set(); valid=[]; errors=[]; depts={r["name"].lower():r["id"] for r in db().execute("SELECT * FROM departments")}
                for n,row in enumerate(reader,2):
                    issues=[]; email=(row.get("email") or "").strip().lower(); code=(row.get("code") or "").strip(); name=(row.get("name") or "").strip()
                    if not code: issues.append("code required")
                    if not name: issues.append("name required")
                    if "@" not in email or "." not in email.split("@")[-1]: issues.append("invalid email")
                    if code in seen_codes or db().execute("SELECT 1 FROM employees WHERE code=?",(code,)).fetchone(): issues.append("duplicate code")
                    if email in seen_emails or db().execute("SELECT 1 FROM employees WHERE email=? OR user_id IN (SELECT id FROM users WHERE email=?)",(email,email)).fetchone(): issues.append("duplicate email")
                    seen_codes.add(code); seen_emails.add(email)
                    dept=(row.get("department") or "").strip().lower()
                    if dept and dept not in depts: issues.append("unknown department")
                    try:
                        datetime.strptime(row.get("join_date", ""),"%Y-%m-%d"); basic=float(row.get("basic",0))
                        if basic<=0: issues.append("salary must be > 0")
                    except Exception: issues.append("join_date must be YYYY-MM-DD and salary numeric")
                    if issues: errors.append({"row":n,"issues":issues})
                    else: valid.append({**row,"email":email,"code":code,"name":name,"department_id":depts.get(dept),"basic":basic})
                report={"valid":valid,"errors":errors,"total":len(valid)+len(errors),"imported":False}
                if request.form.get("action")=="import" and not errors:
                    credentials=[]
                    for row in valid:
                        temp=secrets.token_urlsafe(9); credentials.append({"email":row["email"],"password":temp}); cur=db().execute("INSERT INTO users(email,password,role,must_change) VALUES(?,?, 'Employee',1)",(row["email"],generate_password_hash(temp)))
                        db().execute("INSERT INTO employees(user_id,code,name,email,phone,address,department_id,designation,join_date,basic) VALUES(?,?,?,?,?,?,?,?,?,?)",(cur.lastrowid,row["code"],row["name"],row["email"],row.get("phone",""),row.get("address",""),row["department_id"],row["designation"],row["join_date"],row["basic"]))
                    db().commit(); audit("import","employees",after={"count":len(valid)}); report["imported"]=True; report["valid_count"]=len(valid); report["valid"]=[]; report["credentials"]=credentials
            except (UnicodeDecodeError,csv.Error,ValueError,sqlite3.IntegrityError) as ex: db().rollback(); flash("CSV could not be processed: "+str(ex),"error")
    return render_template("import_employees.html",report=report)

@app.route("/profile",methods=["GET","POST"])
@roles("Employee")
def my_profile():
    e=employee_for_user(current_user()["id"])
    if not e: return "Employee profile not found",404
    if request.method=="POST":
        db().execute("UPDATE employees SET phone=?,address=? WHERE id=?",(request.form.get("phone","").strip(),request.form.get("address","").strip(),e["id"])); db().commit()
        audit("update","employee_profile",e["id"],before={"phone":e["phone"],"address":e["address"]},after={"phone":request.form.get("phone",""),"address":request.form.get("address","")}); flash("Profile updated."); return redirect(url_for("my_profile"))
    return render_template("my_profile.html",e=e)

@app.route("/dashboard/summary",methods=["POST"])
@roles("Admin","HR")
def dashboard_summary():
    conn=db(); start=request.form.get("from",local_today().replace(day=1).isoformat()); end=request.form.get("to",local_today().isoformat())
    try: datetime.strptime(start,"%Y-%m-%d"); datetime.strptime(end,"%Y-%m-%d")
    except ValueError: flash("Enter valid dates.","error"); return redirect(url_for("dashboard"))
    if end<start: flash("End date must be on or after start date.","error"); return redirect(url_for("dashboard"))
    total=conn.execute("SELECT COUNT(*) n FROM employees WHERE active=1").fetchone()["n"]
    late=conn.execute("SELECT COUNT(*) n FROM attendance WHERE day BETWEEN ? AND ? AND status='Late'",(start,end)).fetchone()["n"]
    pending=conn.execute("SELECT COUNT(*) n FROM leave_requests WHERE status='Pending'").fetchone()["n"]
    approved=conn.execute("SELECT COUNT(*) n FROM leave_requests WHERE status='Approved' AND NOT(end<? OR start>?)",(start,end)).fetchone()["n"]
    insights=[f"There are {total} active employees in the current database.",f"{late} late attendance record(s) were recorded between {start} and {end}.",f"{pending} leave request(s) are awaiting a decision.",f"{approved} approved leave request(s) overlap the selected period."]
    return render_template("summary.html",insights=insights,start=start,end=end)

@app.route("/payroll",methods=["GET","POST"])
@roles("Admin","HR")
def payroll():
    conn=db()
    if request.method=="POST":
        month=request.form.get("month","")
        try: datetime.strptime(month,"%Y-%m")
        except ValueError: flash("Select a valid month.","error"); return redirect(url_for("payroll"))
        existing=conn.execute("SELECT * FROM payroll_runs WHERE month=?",(month,)).fetchone()
        if existing and existing["status"]=="Finalized": flash("This payroll month is finalized and locked.","error"); return redirect(url_for("payroll"))
        if not existing:
            cur=conn.execute("INSERT INTO payroll_runs(month,created) VALUES(?,?)",(month,local_now().isoformat(timespec="seconds"))); run_id=cur.lastrowid
        else: run_id=existing["id"]; conn.execute("DELETE FROM payslips WHERE run_id=?",(run_id,))
        y,m=map(int,month.split("-")); days=calendar.monthrange(y,m)[1]
        start=date(y,m,1); end=date(y,m,days)
        effective_end=min(end,local_today()) if month==local_today().strftime("%Y-%m") else end
        workdays=max(1,working_days(start.isoformat(),end.isoformat()))
        staff=conn.execute("SELECT * FROM employees WHERE active=1").fetchall()
        for e in staff:
            basic=float(e["basic"] or 0); hra=basic*.4; med=basic*.1; full_gross=basic+hra+med
            employee_start=max(start,datetime.strptime(e["join_date"],"%Y-%m-%d").date()) if e["join_date"] else start
            employee_end=effective_end
            if employee_start>employee_end:
                eligible_days=0
            else:
                eligible_days=working_days(employee_start.isoformat(),employee_end.isoformat())
            factor=eligible_days/workdays
            basic_pay=basic*factor; hra_pay=hra*factor; med_pay=med*factor
            gross=basic_pay+hra_pay+med_pay
            attended=conn.execute("SELECT COUNT(*) n FROM attendance WHERE employee_id=? AND day BETWEEN ? AND ? AND status!='Absent'",(e["id"],employee_start.isoformat(),employee_end.isoformat())).fetchone()["n"] if eligible_days else 0
            approved=conn.execute("SELECT type,start,end FROM leave_requests WHERE employee_id=? AND status='Approved' AND NOT(end<? OR start>?)",(e["id"],employee_start.isoformat(),employee_end.isoformat())).fetchall() if eligible_days else []
            approved_days=0; unpaid=0
            for lv in approved:
                lv_start=max(employee_start,datetime.strptime(lv["start"],"%Y-%m-%d").date()); lv_end=min(employee_end,datetime.strptime(lv["end"],"%Y-%m-%d").date())
                if lv_start<=lv_end:
                    ld=working_days(lv_start.isoformat(),lv_end.isoformat()); approved_days+=ld
                    if lv["type"].lower()=="unpaid": unpaid+=ld
            absences=max(0,eligible_days-attended-approved_days)
            half=conn.execute("SELECT COUNT(*) n FROM attendance WHERE employee_id=? AND day BETWEEN ? AND ? AND status='Half day'",(e["id"],employee_start.isoformat(),employee_end.isoformat())).fetchone()["n"] if eligible_days else 0
            late_count=conn.execute("SELECT COUNT(*) n FROM attendance WHERE employee_id=? AND day BETWEEN ? AND ? AND status='Late'",(e["id"],employee_start.isoformat(),employee_end.isoformat())).fetchone()["n"] if eligible_days else 0
            late_penalty=(late_count//3)*.5
            per_day=full_gross/workdays
            deductions=per_day*(absences+unpaid+.5*half+late_penalty)
            annual=full_gross*12
            if annual<=600000: tax=0
            elif annual<=1200000: tax=annual*.05/12
            elif annual<=2400000: tax=(30000+(annual-1200000)*.15)/12
            elif annual<=3600000: tax=(210000+(annual-2400000)*.25)/12
            else: tax=(510000+(annual-3600000)*.35)/12
            conn.execute("INSERT INTO payslips(run_id,employee_id,basic,hra,medical,gross,deductions,tax,net) VALUES(?,?,?,?,?,?,?,?,?)",(run_id,e["id"],basic_pay,hra_pay,med_pay,gross,deductions,tax,max(0,gross-deductions-tax)))
        conn.commit(); audit("create","payroll_run",run_id,after={"month":month}); flash("Payroll draft calculated.")
        return redirect(url_for("payroll"))
    runs=conn.execute("SELECT * FROM payroll_runs ORDER BY month DESC").fetchall()
    return render_template("payroll.html",runs=runs)

@app.route("/payroll/<int:rid>")
@roles("Admin","HR","Employee")
def payroll_detail(rid):
    u=current_user(); run=db().execute("SELECT * FROM payroll_runs WHERE id=?",(rid,)).fetchone()
    if not run: return "Not found",404
    sql="""SELECT p.*,e.name,e.code,e.user_id FROM payslips p JOIN employees e ON e.id=p.employee_id WHERE p.run_id=?"""
    params=(rid,)
    if u["role"]=="Employee":
        e=employee_for_user(u["id"]); sql+=" AND p.employee_id=?"; params+=(e["id"] if e else -1,)
    rows=db().execute(sql,params).fetchall()
    return render_template("payroll_detail.html",run=run,rows=rows)

@app.route("/payroll/<int:rid>/finalize",methods=["POST"])
@roles("Admin")
def finalize_payroll(rid):
    run=db().execute("SELECT * FROM payroll_runs WHERE id=?",(rid,)).fetchone()
    if not run: return "Not found",404
    db().execute("UPDATE payroll_runs SET status='Finalized' WHERE id=? AND status='Draft'",(rid,)); db().commit()
    audit("finalize","payroll_run",rid,before=dict(run),after={"status":"Finalized"}); flash("Payroll finalized and locked.")
    return redirect(url_for("payroll"))

@app.route("/payslip/<int:pid>.pdf")
@roles("Admin","HR","Employee")
def payslip_pdf(pid):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    u=current_user()
    sql="""SELECT p.*,e.name,e.code,e.user_id,r.month,r.status FROM payslips p JOIN employees e ON e.id=p.employee_id JOIN payroll_runs r ON r.id=p.run_id WHERE p.id=?"""
    row=db().execute(sql,(pid,)).fetchone()
    if not row: return "Not found",404
    if u["role"]=="Employee" and row["user_id"]!=u["id"]: return "Forbidden",403
    buf=io.BytesIO(); c=canvas.Canvas(buf,pagesize=A4)
    c.setFont("Helvetica-Bold",20); c.drawString(55,790,"HCM Lite - Payslip")
    c.setFont("Helvetica",11)
    lines=[f"Employee: {row['name']} ({row['code']})",f"Month: {row['month']}",f"Status: {row['status']}","",
      f"Basic salary: {row['basic']:.2f}",f"HRA: {row['hra']:.2f}",f"Medical allowance: {row['medical']:.2f}",
      f"Gross: {row['gross']:.2f}",f"Deductions: {row['deductions']:.2f}",f"Tax: {row['tax']:.2f}",f"Net pay: {row['net']:.2f}"]
    y=750
    for line in lines: c.drawString(60,y,line); y-=26
    c.save(); buf.seek(0)
    return send_file(buf,as_attachment=True,download_name=f"payslip-{row['month']}-{row['code']}.pdf",mimetype="application/pdf")

@app.route("/announcements",methods=["GET","POST"])
@login_required
def announcements():
    u=current_user(); conn=db()
    if request.method=="POST":
        if u["role"] not in ("Admin","HR"): return "Forbidden",403
        title=request.form.get("title","").strip(); body=request.form.get("body","").strip()
        if title and body:
            cur=conn.execute("INSERT INTO announcements(title,body,author,created) VALUES(?,?,?,?)",(title,body,u["id"],local_now().isoformat(timespec="seconds")))
            conn.commit(); audit("create","announcement",cur.lastrowid); flash("Announcement posted.")
        return redirect(url_for("announcements"))
    rows=conn.execute("SELECT a.*,u.email FROM announcements a LEFT JOIN users u ON u.id=a.author ORDER BY a.id DESC").fetchall()
    return render_template("announcements.html",rows=rows)

@app.route("/analytics")
@roles("Admin","HR")
def analytics():
    conn=db(); start=request.args.get("from",local_today().replace(day=1).isoformat()); end=request.args.get("to",local_today().isoformat())
    try: datetime.strptime(start,"%Y-%m-%d"); datetime.strptime(end,"%Y-%m-%d")
    except ValueError: start=local_today().replace(day=1).isoformat(); end=local_today().isoformat()
    if end<start: start=local_today().replace(day=1).isoformat(); end=local_today().isoformat()
    try: dept_id=int(request.args.get("department_id",0))
    except ValueError: dept_id=0
    conditions=""; params=[start,end]
    if dept_id:
        conditions=" WHERE d.id=?"; params.append(dept_id)
    depts=conn.execute("""SELECT d.id,d.name,COUNT(DISTINCT e.id) headcount,
      SUM(CASE WHEN a.status='Late' THEN 1 ELSE 0 END) late_count
      FROM departments d LEFT JOIN employees e ON e.department_id=d.id AND e.active=1
      LEFT JOIN attendance a ON a.employee_id=e.id AND a.day BETWEEN ? AND ?"""+conditions+" GROUP BY d.id ORDER BY d.name",tuple(params)).fetchall()
    if dept_id:
        headcount=conn.execute("SELECT COUNT(*) n FROM employees WHERE active=1 AND department_id=?",(dept_id,)).fetchone()["n"]
        gross=conn.execute("SELECT COALESCE(SUM(p.gross),0) n FROM payslips p JOIN employees e ON e.id=p.employee_id JOIN payroll_runs r ON r.id=p.run_id WHERE e.department_id=? AND r.month BETWEEN ? AND ?",(dept_id,start[:7],end[:7])).fetchone()["n"]
        pending=conn.execute("SELECT COUNT(*) n FROM leave_requests l JOIN employees e ON e.id=l.employee_id WHERE l.status='Pending' AND e.department_id=? AND NOT(l.end<? OR l.start>?)",(dept_id,start,end)).fetchone()["n"]
    else:
        headcount=conn.execute("SELECT COUNT(*) n FROM employees WHERE active=1").fetchone()["n"]
        gross=conn.execute("SELECT COALESCE(SUM(p.gross),0) n FROM payslips p JOIN payroll_runs r ON r.id=p.run_id WHERE r.month BETWEEN ? AND ?",(start[:7],end[:7])).fetchone()["n"]
        pending=conn.execute("SELECT COUNT(*) n FROM leave_requests WHERE status='Pending' AND NOT(end<? OR start>?)",(start,end)).fetchone()["n"]
    summary={"headcount":headcount,"gross":gross,"pending":pending}
    # Transparent heuristic: scores are operational flags, not a validated HR prediction.
    risk_rows=[]; anomaly_rows=[]
    people_sql="SELECT e.*,d.name department FROM employees e LEFT JOIN departments d ON d.id=e.department_id WHERE e.active=1"
    people_params=()
    if dept_id: people_sql+=" AND e.department_id=?"; people_params=(dept_id,)
    people=conn.execute(people_sql+" ORDER BY e.name",people_params).fetchall()
    period_start=datetime.strptime(start,"%Y-%m-%d").date(); period_end=min(datetime.strptime(end,"%Y-%m-%d").date(),local_today())
    for person in people:
        pstart=max(period_start,datetime.strptime(person["join_date"],"%Y-%m-%d").date()) if person["join_date"] else period_start
        eligible=working_days(pstart.isoformat(),period_end.isoformat()) if pstart<=period_end else 0
        attended=conn.execute("SELECT COUNT(*) n FROM attendance WHERE employee_id=? AND day BETWEEN ? AND ? AND status!='Absent'",(person["id"],pstart.isoformat(),period_end.isoformat())).fetchone()["n"] if eligible else 0
        late_count=conn.execute("SELECT COUNT(*) n FROM attendance WHERE employee_id=? AND day BETWEEN ? AND ? AND status='Late'",(person["id"],pstart.isoformat(),period_end.isoformat())).fetchone()["n"] if eligible else 0
        approved=conn.execute("SELECT type,start,end FROM leave_requests WHERE employee_id=? AND status='Approved' AND NOT(end<? OR start>?)",(person["id"],pstart.isoformat(),period_end.isoformat())).fetchall() if eligible else []
        leave_days=0
        for lv in approved:
            a=max(pstart,datetime.strptime(lv["start"],"%Y-%m-%d").date()); b=min(period_end,datetime.strptime(lv["end"],"%Y-%m-%d").date())
            if a<=b: leave_days+=working_days(a.isoformat(),b.isoformat())
        absent=max(0,eligible-attended-leave_days)
        request_count=conn.execute("SELECT COUNT(*) n FROM leave_requests WHERE employee_id=? AND NOT(end<? OR start>?)",(person["id"],start,end)).fetchone()["n"]
        score=min(100,late_count*5+absent*10+request_count*2)
        if score>=40: risk_rows.append({"name":person["name"],"department":person["department"] or "-","score":score,"late":late_count,"absent":absent})
        if absent>=3 or (eligible>=5 and absent/eligible>=0.2): anomaly_rows.append({"name":person["name"],"department":person["department"] or "-","absent":absent,"eligible":eligible})
    all_depts=conn.execute("SELECT id,name FROM departments ORDER BY name").fetchall()
    return render_template("analytics.html",depts=depts,summary=summary,all_depts=all_depts,start=start,end=end,department_id=dept_id,risk_rows=risk_rows,anomaly_rows=anomaly_rows)

def tool_data(question, u):
    conn=db(); q=question.lower(); role=u["role"]; e=employee_for_user(u["id"]) if role=="Employee" else None
    if any(x in q for x in ["who is on leave", "on leave today", "leave today", "kis ki chhutti", "chhutti par"]):
        today=local_today().isoformat()
        if role=="Employee":
            if not e: return "No employee profile is linked to your account."
            own_leave=conn.execute("SELECT type,start,end,status FROM leave_requests WHERE employee_id=? AND status='Approved' AND start<=? AND end>=?",(e["id"],today,today)).fetchall()
            return ("You are on approved leave today: "+", ".join(r["type"] for r in own_leave)) if own_leave else "You have no approved leave recorded for today. I cannot disclose colleagues' leave details in employee self-service."
        rows=conn.execute("SELECT e.name,l.type FROM leave_requests l JOIN employees e ON e.id=l.employee_id WHERE l.status='Approved' AND l.start<=? AND l.end>=? ORDER BY e.name",(today,today)).fetchall()
        return "Approved leave today: "+("; ".join(f"{r['name']} ({r['type']})" for r in rows) if rows else "no employees currently have approved leave recorded")
    if "late" in q and any(x in q for x in ["most often","most","who came","late-comer","late comer","sab se zyada","zyada late"]):
        month=local_today().strftime("%Y-%m")
        if role=="Employee":
            if not e: return "No employee profile is linked to your account."
            count=conn.execute("SELECT COUNT(*) n FROM attendance WHERE employee_id=? AND status='Late' AND substr(day,1,7)=?",(e["id"],month)).fetchone()["n"]
            return f"You have {count} late attendance record(s) this month. I cannot rank colleagues for employee self-service."
        rows=conn.execute("SELECT e.name,COUNT(*) late_count FROM attendance a JOIN employees e ON e.id=a.employee_id WHERE a.status='Late' AND substr(a.day,1,7)=? GROUP BY e.id ORDER BY late_count DESC,e.name LIMIT 5",(month,)).fetchall()
        return "Most late records this month: "+("; ".join(f"{r['name']} ({r['late_count']})" for r in rows) if rows else "no late attendance records")
    if "attendance rate" in q:
        today=local_today(); start=today.replace(day=1); end=today
        days=working_days(start.isoformat(),end.isoformat())
        if role=="Employee":
            if not e: return "No employee profile is linked to your account."
            count=conn.execute("SELECT COUNT(*) n FROM attendance WHERE employee_id=? AND day BETWEEN ? AND ? AND status!='Absent'",(e["id"],start.isoformat(),end.isoformat())).fetchone()["n"]
            rate=(count/days*100) if days else 0
            return f"Your recorded attendance rate this month is {rate:.1f}% ({count} attendance record(s) over {days} working day(s))."
        headcount=conn.execute("SELECT COUNT(*) n FROM employees WHERE active=1 AND join_date<=?",(end.isoformat(),)).fetchone()["n"]
        total=max(1,headcount*days)
        count=conn.execute("SELECT COUNT(*) n FROM attendance WHERE day BETWEEN ? AND ? AND status!='Absent'",(start.isoformat(),end.isoformat())).fetchone()["n"]
        return f"Recorded attendance rate this month is {min(100,count/total*100):.1f}% ({count} recorded employee-days out of up to {total} employee-days). This is based on current database records."
    if any(x in q for x in ["my leave","leave balance","sick leave","casual leave","how many leaves","chutti","chhutti","kitni leave","baki leave","bachi hai","meri leave"]):
        if role=="Employee" and e:
            result={}
            for lt in conn.execute("SELECT * FROM leave_types"):
                used=conn.execute("SELECT COALESCE(SUM(days),0) n FROM leave_requests WHERE employee_id=? AND type=? AND status='Approved' AND substr(start,1,4)=?",(e["id"],lt["name"],str(local_today().year))).fetchone()["n"]
                result[lt["name"]]="Unlimited" if lt["name"]=="Unpaid" else max(0,lt["quota"]-used)
            return "Your remaining leave balance: "+json.dumps(result)
        return "Leave balances are available to employees for their own account; HR/Admin can review requests."
    if any(x in q for x in ["salary","payroll","net pay"]):
        if role=="Employee":
            return "I can only show your own payslips. Open Payroll to view your salary records; I cannot share another employee's salary."
        total=conn.execute("SELECT COUNT(*) n,COALESCE(SUM(gross),0) gross,COALESCE(SUM(net),0) net FROM payslips").fetchone()
        return f"Payroll records: {total['n']} payslips; total gross {total['gross']:.2f}; total net {total['net']:.2f}."
    if any(x in q for x in ["headcount","employees","employee","how many people","active employees","kitne log","kitne employee"]):
        if role=="Employee": return "For privacy, employee-wide directory statistics are not available in your self-service assistant."
        import re
        match=re.search(r"\bin\s+([a-z0-9 &_-]+?)(?:\?|$)",q)
        if match:
            dept=match.group(1).strip(" .?!")
            if dept and dept not in ("the company","company","total","all departments"):
                row=conn.execute("SELECT COUNT(*) n FROM employees e JOIN departments d ON d.id=e.department_id WHERE e.active=1 AND lower(d.name)=lower(?)",(dept,)).fetchone()
                return f"There are {row['n']} active employees in {dept}."
        n=conn.execute("SELECT COUNT(*) n FROM employees WHERE active=1").fetchone()["n"]
        return f"There are {n} active employees in the current database."
    if "late" in q or "attendance" in q or "present" in q:
        if role=="Employee" and e:
            r=conn.execute("SELECT COUNT(*) late FROM attendance WHERE employee_id=? AND status='Late' AND substr(day,1,7)=?",(e["id"],local_today().strftime("%Y-%m"))).fetchone()
            return f"You have {r['late']} late attendance record(s) this month."
        r=conn.execute("SELECT COUNT(*) late FROM attendance WHERE status='Late' AND substr(day,1,7)=?",(local_today().strftime("%Y-%m"),)).fetchone()
        return f"There are {r['late']} late attendance record(s) this month."
    if any(x in q for x in ["policy","grace","half day","office time","weekend","quota","leave rule"]):
        s=conn.execute("SELECT * FROM settings WHERE id=1").fetchone()
        return f"Policy: office starts {s['office_start']}, grace time {s['grace']} minutes; late after the grace period; half-day under 5 hours; weekend days are configured in company settings. Default quotas: Annual 14, Sick 8, Casual 10; unpaid leave unlimited. Leave counts working days only, skipping weekends and configured holidays."
    return "I can help with headcount, attendance/late records, leave balance, payroll summaries, and attendance/leave policy. I don't know the answer from the available data."

@app.route("/smart-leave",methods=["GET","POST"])
@roles("Employee")
def smart_leave():
    sentence=""; parsed=None; types=db().execute("SELECT * FROM leave_types ORDER BY id").fetchall()
    if request.method=="POST":
        sentence=request.form.get("sentence","").strip(); q=sentence.lower()
        weekdays={"monday":0,"mon":0,"tuesday":1,"tue":1,"tues":1,"wednesday":2,"wed":2,"thursday":3,"thu":3,"thurs":3,"friday":4,"fri":4,"saturday":5,"sat":5,"sunday":6,"sun":6}
        import re
        found=[]
        for word,wd in weekdays.items():
            if re.search(r"\b"+word+r"\b",q) and wd not in found: found.append(wd)
        if "sick" in q or "tabiyat" in q or "bimar" in q: typ="Sick"
        elif "annual" in q or "vacation" in q: typ="Annual"
        else: typ="Casual"
        today=local_today(); targets=[]
        if found:
            first=found[0]; delta=(first-today.weekday())%7
            if delta==0: delta=7
            first_date=today+timedelta(days=delta); targets=[first_date]
            if len(found)>1:
                second=found[1]; d2=(second-first)%7
                if d2==0: d2=7
                targets.append(first_date+timedelta(days=d2))
            start=targets[0]; end=targets[-1]
        else:
            dates=re.findall(r"\b(20\d{2}-\d{2}-\d{2})\b",q)
            try: start=datetime.strptime(dates[0],"%Y-%m-%d").date(); end=datetime.strptime(dates[1],"%Y-%m-%d").date() if len(dates)>1 else start
            except Exception: start=end=None
        if not start or not end or end<start:
            flash("I couldn't confidently identify dates. Try e.g. 'Need next Monday and Tuesday off for a wedding' or include YYYY-MM-DD dates.","error")
        else:
            reason=sentence
            for phrase in ("for a wedding","wedding","for my sister's wedding","for sister wedding","for a family event","family event","doctor appointment","for appointment"):
                if phrase in q: reason=phrase.replace("for ","").strip().capitalize(); break
            parsed={"type":typ,"start":start.isoformat(),"end":end.isoformat(),"reason":reason or "Personal leave"}
    return render_template("smart_leave.html",sentence=sentence,parsed=parsed,types=types)

def execute_ai_tool(name,args,u):
    """Small allow-listed AI tool layer. It never accepts SQL and always enforces role scope."""
    conn=db(); role=u["role"]; own=employee_for_user(u["id"]) if role=="Employee" else None
    if name=="get_headcount":
        if role=="Employee": return {"error":"Not available to employee role"}
        dept=(args.get("department") or "").strip()
        if dept:
            row=conn.execute("SELECT COUNT(*) n FROM employees e JOIN departments d ON d.id=e.department_id WHERE e.active=1 AND lower(d.name)=lower(?)",(dept,)).fetchone()
            return {"active_headcount":row["n"],"department":dept}
        return {"active_headcount":conn.execute("SELECT COUNT(*) n FROM employees WHERE active=1").fetchone()["n"]}
    if name=="get_attendance_summary":
        start=args.get("start") or local_today().replace(day=1).isoformat(); end=args.get("end") or local_today().isoformat()
        if end<start: return {"error":"End date must be on or after start date"}
        if role=="Employee":
            if not own: return {"error":"No employee profile linked"}
            row=conn.execute("SELECT COUNT(*) total,SUM(CASE WHEN status='Late' THEN 1 ELSE 0 END) late,SUM(CASE WHEN status IN ('Present','Late','Half day','Missing checkout') THEN 1 ELSE 0 END) attended FROM attendance WHERE employee_id=? AND day BETWEEN ? AND ?",(own["id"],start,end)).fetchone()
        else:
            row=conn.execute("SELECT COUNT(*) total,SUM(CASE WHEN status='Late' THEN 1 ELSE 0 END) late,SUM(CASE WHEN status IN ('Present','Late','Half day','Missing checkout') THEN 1 ELSE 0 END) attended FROM attendance WHERE day BETWEEN ? AND ?",(start,end)).fetchone()
        return {"from":start,"to":end,"records":row["total"] or 0,"late":row["late"] or 0,"attended_records":row["attended"] or 0}
    if name=="get_late_comers":
        if role=="Employee":
            if not own: return {"error":"No employee profile linked"}
            rows=conn.execute("SELECT day,check_in,status FROM attendance WHERE employee_id=? AND status='Late' ORDER BY day DESC LIMIT 10",(own["id"],)).fetchall()
        else:
            rows=conn.execute("SELECT e.name,a.day,a.check_in FROM attendance a JOIN employees e ON e.id=a.employee_id WHERE a.status='Late' ORDER BY a.day DESC LIMIT 20").fetchall()
        return [dict(r) for r in rows]
    if name=="get_leave_summary":
        if role=="Employee":
            if not own: return {"error":"No employee profile linked"}
            rows=conn.execute("SELECT type,status,COUNT(*) requests,COALESCE(SUM(days),0) days FROM leave_requests WHERE employee_id=? GROUP BY type,status",(own["id"],)).fetchall()
        else: rows=conn.execute("SELECT type,status,COUNT(*) requests,COALESCE(SUM(days),0) days FROM leave_requests GROUP BY type,status").fetchall()
        return [dict(r) for r in rows]
    if name=="get_my_leave_balance":
        if role!="Employee" or not own: return {"error":"This tool is available only to a linked employee"}
        result={}
        for lt in conn.execute("SELECT * FROM leave_types"):
            used=conn.execute("SELECT COALESCE(SUM(days),0) n FROM leave_requests WHERE employee_id=? AND type=? AND status='Approved' AND substr(start,1,4)=?",(own["id"],lt["name"],str(local_today().year))).fetchone()["n"]
            result[lt["name"]]="Unlimited" if lt["name"].lower()=="unpaid" else max(0,lt["quota"]-used)
        return result
    if name=="get_payroll_summary":
        if role=="Employee":
            if not own: return {"error":"No employee profile linked"}
            rows=conn.execute("SELECT r.month,p.gross,p.net FROM payslips p JOIN payroll_runs r ON r.id=p.run_id WHERE p.employee_id=? ORDER BY r.month DESC LIMIT 12",(own["id"],)).fetchall()
            return [dict(r) for r in rows]
        rows=conn.execute("SELECT r.month,r.status,COUNT(p.id) employees,COALESCE(SUM(p.gross),0) gross,COALESCE(SUM(p.net),0) net FROM payroll_runs r LEFT JOIN payslips p ON p.run_id=r.id GROUP BY r.id ORDER BY r.month DESC LIMIT 12").fetchall()
        return [dict(r) for r in rows]
    if name=="search_employees":
        if role=="Employee": return {"error":"Employee directory search is not available in employee self-service"}
        term=(args.get("query") or "").strip()
        if not term: return []
        rows=conn.execute("SELECT e.name,e.code,e.designation,d.name department FROM employees e LEFT JOIN departments d ON d.id=e.department_id WHERE e.active=1 AND (e.name LIKE ? OR e.code LIKE ? OR e.email LIKE ?) ORDER BY e.name LIMIT 10",(f"%{term}%",)*3).fetchall()
        return [dict(r) for r in rows]
    return {"error":"Unknown tool"}

AI_TOOLS=[
 {"type":"function","function":{"name":"get_headcount","description":"Get active headcount, optionally for a department. Admin/HR only.","parameters":{"type":"object","properties":{"department":{"type":"string"}},"required":[]}}},
 {"type":"function","function":{"name":"get_attendance_summary","description":"Summarize attendance records and late counts for a date range. Employees receive own data only.","parameters":{"type":"object","properties":{"start":{"type":"string","description":"YYYY-MM-DD"},"end":{"type":"string","description":"YYYY-MM-DD"}},"required":[]}}},
 {"type":"function","function":{"name":"get_late_comers","description":"List late attendance records. Employees receive own records only.","parameters":{"type":"object","properties":{},"required":[]}}},
 {"type":"function","function":{"name":"get_leave_summary","description":"Summarize leave request counts and days. Employees receive own data only.","parameters":{"type":"object","properties":{},"required":[]}}},
 {"type":"function","function":{"name":"get_my_leave_balance","description":"Get the current employee's remaining leave balance.","parameters":{"type":"object","properties":{},"required":[]}}},
 {"type":"function","function":{"name":"get_payroll_summary","description":"Summarize payroll. Employees receive only their own payslips.","parameters":{"type":"object","properties":{},"required":[]}}},
 {"type":"function","function":{"name":"search_employees","description":"Search active employees by name, code or email. Admin/HR only.","parameters":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}}}
]

@app.route("/ai",methods=["GET","POST"])
@login_required
def ai():
    answer=None; question=""
    if request.method=="POST":
        question=request.form.get("question","").strip(); u=current_user()
        recent=db().execute("SELECT COUNT(*) n FROM ai_logs WHERE user_id=? AND created>=?",(u["id"],(local_now()-timedelta(hours=1)).isoformat(timespec="seconds"))).fetchone()["n"]
        if recent>=20:
            flash("AI usage limit reached (20 requests/hour). Please try again later.","error")
            return render_template("ai.html",question=question,answer="AI request limit reached. Please try again later.")
        answer=tool_data(question,u)
        key=os.getenv("AI_API_KEY")
        if key and question:
            try:
                base=os.getenv("AI_BASE_URL","https://api.openai.com/v1").rstrip("/")+"/chat/completions"
                headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"}
                system="You are HCM Lite assistant. Database facts must come only from the provided allow-listed tools. Never reveal another employee's salary or private data. Policy: office start and grace are set in company settings; leave counts working days excluding weekends/holidays; approved leave is quota-limited except unpaid; payroll is illustrative and Admin finalizes it. If a tool refuses, politely explain. Answer in the user's language when possible."
                messages=[{"role":"system","content":system},{"role":"user","content":question}]
                payload={"model":os.getenv("AI_MODEL","gpt-4o-mini"),"messages":messages,"tools":AI_TOOLS,"tool_choice":"auto","temperature":0.2}
                r=requests.post(base,headers=headers,json=payload,timeout=15); r.raise_for_status(); msg=r.json()["choices"][0]["message"]
                if msg.get("tool_calls"):
                    messages.append(msg)
                    for call in msg["tool_calls"]:
                        try: args=json.loads(call["function"].get("arguments") or "{}")
                        except json.JSONDecodeError: args={}
                        result=execute_ai_tool(call["function"]["name"],args,u)
                        messages.append({"role":"tool","tool_call_id":call["id"],"content":json.dumps(result,default=str)})
                    r=requests.post(base,headers=headers,json={"model":os.getenv("AI_MODEL","gpt-4o-mini"),"messages":messages,"temperature":0.2},timeout=15); r.raise_for_status(); msg=r.json()["choices"][0]["message"]
                answer=msg.get("content") or answer
            except Exception: answer += "\n\nAI service unavailable; showing the safe local answer."
        answer += "\n\nAI-generated" if key else "\n\n(Local rules-based answer; configure AI_API_KEY for hosted LLM.)"
        db().execute("INSERT INTO ai_logs(user_id,question,answer,created) VALUES(?,?,?,?)",(u["id"],question,answer,local_now().isoformat(timespec="seconds"))); db().commit()
    return render_template("ai.html",question=question,answer=answer)

@app.route("/audit")
@roles("Admin")
def audit_page():
    rows=db().execute("SELECT a.*,u.email FROM audit a LEFT JOIN users u ON u.id=a.actor ORDER BY a.id DESC LIMIT 300").fetchall()
    return render_template("audit.html",rows=rows)

@app.route("/notifications")
@login_required
def notifications():
    rows=db().execute("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100",(current_user()["id"],)).fetchall()
    db().execute("UPDATE notifications SET read=1 WHERE user_id=?",(current_user()["id"],)); db().commit()
    return render_template("notifications.html",rows=rows)

@app.route("/holidays",methods=["GET","POST"])
@roles("Admin")
def holidays():
    if request.method=="POST":
        try:
            db().execute("INSERT INTO holidays(day,name) VALUES(?,?)",(request.form["day"],request.form["name"])); db().commit(); audit("create","holiday",after={"day":request.form["day"]}); flash("Holiday added.")
        except sqlite3.IntegrityError: flash("Holiday already exists.","error")
        return redirect(url_for("holidays"))
    return render_template("holidays.html",rows=db().execute("SELECT * FROM holidays ORDER BY day").fetchall())

@app.route("/export/employees.csv")
@roles("Admin","HR")
def export_employees():
    rows=db().execute("SELECT e.code,e.name,e.email,e.phone,e.address,d.name department,e.designation,e.join_date,e.basic FROM employees e LEFT JOIN departments d ON d.id=e.department_id ORDER BY e.name").fetchall()
    out=io.StringIO(); w=csv.writer(out); w.writerow(["code","name","email","phone","address","department","designation","join_date","basic"])
    for r in rows: w.writerow(list(r))
    return send_file(io.BytesIO(out.getvalue().encode("utf-8-sig")),as_attachment=True,download_name="employees.csv",mimetype="text/csv")

# Initialize schema for both direct execution and WSGI deployments (e.g. gunicorn app:app).
init_db()

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.getenv("PORT","5000")),debug=False)
