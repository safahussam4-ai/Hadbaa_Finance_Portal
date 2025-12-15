import os
import sqlite3
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file, g
)
from werkzeug.security import generate_password_hash, check_password_hash

import pandas as pd
import logging
from logging.handlers import RotatingFileHandler

# ============================================================
#                     CONFIG & PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

app = Flask(__name__)
app.secret_key = "CHANGE_ME_TO_REAL_SECRET_KEY"

# ============================================================
#                        LOGGING
# ============================================================

log_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, "portal.log"),
    maxBytes=5_000_000,
    backupCount=3,
    encoding="utf-8",
)
log_formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
log_handler.setFormatter(log_formatter)
log_handler.setLevel(logging.INFO)

app.logger.setLevel(logging.INFO)
app.logger.addHandler(log_handler)
app.logger.info("🔥 Hadbaa Finance Portal 3.0 starting up")


# ============================================================
#                      DB HELPERS
# ============================================================

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            full_name TEXT,
            email TEXT,
            password_hash TEXT,
            role TEXT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS expense_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            is_active INTEGER DEFAULT 1
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            requester_id INTEGER,
            department TEXT,
            item_description TEXT,
            expense_type_id INTEGER,
            estimated_total REAL,
            status TEXT,
            created_at TEXT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS disbursements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER,
            amount REAL,
            receipt_no TEXT,
            receipt_date TEXT
        )
        """
    )

    conn.commit()
    seed_data(conn)
    conn.close()
    app.logger.info("📚 Database initialized")


def seed_data(conn):
    # Seed users
    default_users = [
        ("requester", "موظف طلبات", "req@example.com", "123456", "requester"),
        ("fund_manager", "مدير صندوق المالية", "fund@example.com", "123456", "fund_manager"),
        ("finance_manager", "مدير الشؤون المالية", "finance@example.com", "123456", "finance_manager"),
        ("president", "رئيس الجامعة", "president@example.com", "123456", "president"),
        ("cashier", "أمين الصندوق", "cashier@example.com", "123456", "cashier"),
    ]
    for username, full_name, email, pwd, role in default_users:
        row = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO users (username, full_name, email, password_hash, role) "
                "VALUES (?, ?, ?, ?, ?)",
                (username, full_name, email, generate_password_hash(pwd), role),
            )
            app.logger.info(f"👤 Seed user created: {username} ({role})")

    # Seed expense types
    defaults = ["أثاث", "أجهزة مختبرية", "قرطاسية", "خدمات صيانة", "برمجيات", "أخرى"]
    for name in defaults:
        row = conn.execute("SELECT id FROM expense_types WHERE name=?", (name,)).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO expense_types (name, is_active) VALUES (?, 1)",
                (name,),
            )
            app.logger.info(f"💡 Seed expense type: {name}")

    conn.commit()


# ============================================================
#                  AUTH / SESSION HELPERS
# ============================================================

from functools import wraps


def current_user():
    if "user_id" not in session:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()
    return user


@app.before_request
def load_user_and_log():
    g.user = current_user()
    app.logger.info(
        f"➡️ {request.method} {request.path} | IP={request.remote_addr} | "
        f"User={g.user['username'] if g.user else 'anonymous'}"
    )


@app.context_processor
def inject_user():
    return {"user": g.get("user")}


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if g.user is None:
            flash("يجب تسجيل الدخول أولاً", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapper


def role_required(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if g.user is None or g.user["role"] not in roles:
                flash("ليست لديك صلاحية الوصول", "danger")
                app.logger.warning(
                    f"🚫 Unauthorized access to {request.path} by "
                    f"{g.user['username'] if g.user else 'anonymous'}"
                )
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)

        return wrapper

    return decorator


# ============================================================
#                       AUTH ROUTES
# ============================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            flash("تم تسجيل الدخول بنجاح", "success")
            app.logger.info(f"✅ Login: {username}")
            return redirect(url_for("dashboard"))
        else:
            flash("اسم المستخدم أو كلمة المرور غير صحيحة", "danger")
            app.logger.warning(f"❌ Failed login attempt for {username}")

    return render_template("login.html", title="تسجيل الدخول")


@app.route("/logout")
def logout():
    if g.user:
        app.logger.info(f"👋 Logout: {g.user['username']}")
    session.clear()
    flash("تم تسجيل الخروج", "info")
    return redirect(url_for("login"))


# ============================================================
#                      CORE LOGIC
# ============================================================

def determine_next_approver(amount: float) -> str:
    if amount <= 2_000_000:
        return "fund_manager"
    elif amount <= 20_000_000:
        return "finance_manager"
    else:
        return "president"


@app.route("/")
@login_required
def dashboard():
    conn = get_db()
    stats = conn.execute(
        "SELECT status, COUNT(*) AS c FROM requests GROUP BY status"
    ).fetchall()

    my_latest = conn.execute(
        """
        SELECT r.*, e.name AS expense_type_name
        FROM requests r
        LEFT JOIN expense_types e ON r.expense_type_id = e.id
        WHERE requester_id=?
        ORDER BY datetime(created_at) DESC
        LIMIT 5
        """,
        (g.user["id"],),
    ).fetchall()
    conn.close()
    return render_template(
        "dashboard.html",
        title="لوحة التحكم",
        stats=stats,
        my_requests=my_latest,
    )


@app.route("/requests/new", methods=["GET", "POST"])
@login_required
@role_required("requester")
def new_request():
    conn = get_db()
    expense_types = conn.execute(
        "SELECT * FROM expense_types WHERE is_active=1 ORDER BY name"
    ).fetchall()

    if request.method == "POST":
        department = request.form.get("department")
        item_description = request.form.get("item_description")
        expense_type_id = request.form.get("expense_type_id") or None
        estimated_total = float(request.form.get("estimated_total") or 0)

        next_role = determine_next_approver(estimated_total)
        status = f"pending_{next_role}"

        conn.execute(
            """
            INSERT INTO requests (
                requester_id, department, item_description,
                expense_type_id, estimated_total, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                g.user["id"],
                department,
                item_description,
                expense_type_id,
                estimated_total,
                status,
                datetime.now().strftime("%Y-%m-%d %H:%M"),
            ),
        )
        conn.commit()
        conn.close()

        flash("تم إرسال الطلب بنجاح", "success")
        app.logger.info(
            f"📝 Request created by {g.user['username']} | amount={estimated_total} | status={status}"
        )
        return redirect(url_for("dashboard"))

    conn.close()
    return render_template(
        "new_request.html",
        title="طلب شراء جديد",
        expense_types=expense_types,
    )


@app.route("/requests")
@login_required
def list_requests():
    conn = get_db()

    if g.user["role"] == "requester":
        rows = conn.execute(
            """
            SELECT r.*, e.name AS expense_type_name
            FROM requests r
            LEFT JOIN expense_types e ON r.expense_type_id = e.id
            WHERE requester_id=?
            ORDER BY datetime(created_at) DESC
            """,
            (g.user["id"],),
        ).fetchall()
    elif g.user["role"] in ("fund_manager", "finance_manager", "president"):
        status = f"pending_{g.user['role']}"
        rows = conn.execute(
            """
            SELECT r.*, e.name AS expense_type_name
            FROM requests r
            LEFT JOIN expense_types e ON r.expense_type_id = e.id
            WHERE status=?
            ORDER BY datetime(created_at)
            """,
            (status,),
        ).fetchall()
    elif g.user["role"] == "cashier":
        rows = conn.execute(
            """
            SELECT r.*, e.name AS expense_type_name
            FROM requests r
            LEFT JOIN expense_types e ON r.expense_type_id = e.id
            WHERE status='approved_to_cashier'
            ORDER BY datetime(created_at)
            """
        ).fetchall()
    else:
        rows = []

    conn.close()
    return render_template(
        "requests_list.html",
        title="الطلبات",
        rows=rows,
    )


@app.route("/requests/<int:rid>/decision", methods=["POST"])
@login_required
def request_decision(rid):
    action = request.form.get("action")
    conn = get_db()
    row = conn.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()

    if row is None:
        flash("الطلب غير موجود", "danger")
        conn.close()
        return redirect(url_for("list_requests"))

    required_role = None
    if row["status"] == "pending_fund_manager":
        required_role = "fund_manager"
    elif row["status"] == "pending_finance_manager":
        required_role = "finance_manager"
    elif row["status"] == "pending_president":
        required_role = "president"

    if required_role and g.user["role"] != required_role:
        flash("لا تملك صلاحية اتخاذ القرار على هذا الطلب", "danger")
        conn.close()
        return redirect(url_for("list_requests"))

    if action == "approve":
        next_status = "approved_to_cashier"
        conn.execute("UPDATE requests SET status=? WHERE id=?", (next_status, rid))
        conn.commit()
        conn.close()
        flash("تمت الموافقة على الطلب وتحويله لأمين الصندوق", "success")
        app.logger.info(
            f"✔ APPROVED request #{rid} by {g.user['username']} -> {next_status}"
        )
    elif action == "reject":
        conn.execute("UPDATE requests SET status='rejected' WHERE id=?", (rid,))
        conn.commit()
        conn.close()
        flash("تم رفض الطلب", "warning")
        app.logger.info(f"❌ REJECTED request #{rid} by {g.user['username']}")
    else:
        conn.close()
        flash("إجراء غير معروف", "danger")

    return redirect(url_for("list_requests"))


# ============================================================
#                     CASHIER & DISBURSEMENT
# ============================================================

@app.route("/cashier")
@login_required
@role_required("cashier")
def cashier_dashboard():
    conn = get_db()
    rows = conn.execute(
        """
        SELECT r.*, e.name AS expense_type_name
        FROM requests r
        LEFT JOIN expense_types e ON r.expense_type_id = e.id
        WHERE status='approved_to_cashier'
        ORDER BY datetime(created_at)
        """
    ).fetchall()
    conn.close()
    return render_template(
        "cashier.html",
        title="طلبات جاهزة للصرف",
        rows=rows,
    )


@app.route("/cashier/disburse/<int:rid>", methods=["GET", "POST"])
@login_required
@role_required("cashier")
def disburse(rid):
    conn = get_db()
    req = conn.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
    if req is None:
        conn.close()
        flash("الطلب غير موجود", "danger")
        return redirect(url_for("cashier_dashboard"))

    if request.method == "POST":
        amount = float(request.form.get("amount") or 0)
        receipt_no = request.form.get("receipt_no")
        receipt_date = request.form.get("receipt_date")

        conn.execute(
            """
            INSERT INTO disbursements (request_id, amount, receipt_no, receipt_date)
            VALUES (?, ?, ?, ?)
            """,
            (rid, amount, receipt_no, receipt_date),
        )
        conn.execute(
            "UPDATE requests SET status='paid' WHERE id=?",
            (rid,),
        )
        conn.commit()
        conn.close()

        flash("تم تسجيل عملية الصرف", "success")
        app.logger.info(
            f"💵 DISBURSE request #{rid} | amount={amount} | cashier={g.user['username']}"
        )
        return redirect(url_for("cashier_dashboard"))

    conn.close()
    return render_template(
        "disburse.html",
        title="صرف طلب",
        req=req,
    )


# ============================================================
#                  EXPENSE TYPES (ADMIN)
# ============================================================

@app.route("/expense-types", methods=["GET", "POST"])
@login_required
@role_required("finance_manager", "president")
def expense_types():
    conn = get_db()

    if request.method == "POST":
        action = request.form.get("action")
        name = request.form.get("name")
        etid = request.form.get("id")

        if action == "create" and name:
            conn.execute(
                "INSERT INTO expense_types (name, is_active) VALUES (?, 1)",
                (name,),
            )
            conn.commit()
            flash("تمت إضافة نوع مصروف جديد", "success")
        elif action == "update" and etid and name:
            conn.execute(
                "UPDATE expense_types SET name=? WHERE id=?",
                (name, etid),
            )
            conn.commit()
            flash("تم تعديل نوع المصروف", "success")
        elif action == "toggle" and etid:
            row = conn.execute(
                "SELECT is_active FROM expense_types WHERE id=?", (etid,)
            ).fetchone()
            if row:
                new_val = 0 if row["is_active"] else 1
                conn.execute(
                    "UPDATE expense_types SET is_active=? WHERE id=?",
                    (new_val, etid),
                )
                conn.commit()
                flash("تم تحديث حالة التفعيل", "success")

    rows = conn.execute(
        "SELECT * FROM expense_types ORDER BY is_active DESC, name"
    ).fetchall()
    conn.close()
    return render_template(
        "expense_types.html",
        title="أنواع المصروفات",
        rows=rows,
    )


# ============================================================
#                          REPORTS
# ============================================================

@app.route("/reports")
@login_required
def reports_home():
    return render_template("reports.html", title="التقارير")


def export_requests_to_excel(status_filter, filename):
    conn = get_db()
    if status_filter == "pending":
        rows = conn.execute(
            "SELECT * FROM requests WHERE status LIKE 'pending_%'"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM requests WHERE status=?",
            (status_filter,),
        ).fetchall()
    conn.close()

    if not rows:
        return None

    df = pd.DataFrame(rows)
    path = os.path.join(BASE_DIR, filename)
    df.to_excel(path, index=False)
    return path


@app.route("/reports/export/<kind>")
@login_required
def reports_export(kind):
    mapping = {
        "unpaid": ("approved_to_cashier", "unpaid_requests.xlsx"),
        "rejected": ("rejected", "rejected_requests.xlsx"),
        "pending": ("pending", "pending_requests.xlsx"),
        "paid": ("paid", "paid_requests.xlsx"),
    }
    if kind not in mapping:
        flash("نوع تقرير غير معروف", "danger")
        return redirect(url_for("reports_home"))

    status_filter, filename = mapping[kind]
    path = export_requests_to_excel(status_filter, filename)
    if not path:
        flash("لا توجد بيانات للتصدير", "info")
        return redirect(url_for("reports_home"))

    app.logger.info(f"📊 Excel report generated: {kind}")
    return send_file(path, as_attachment=True)


# ============================================================
#                        ANALYTICS
# ============================================================

@app.route("/analytics")
@login_required
@role_required("finance_manager", "president")
def analytics():
    conn = get_db()
    by_dept = conn.execute(
        """
        SELECT department, SUM(estimated_total) AS total
        FROM requests
        WHERE status IN ('approved_to_cashier', 'paid')
        GROUP BY department
        ORDER BY total DESC
        """
    ).fetchall()

    by_expense = conn.execute(
        """
        SELECT e.name AS expense_type, SUM(r.estimated_total) AS total
        FROM requests r
        LEFT JOIN expense_types e ON r.expense_type_id = e.id
        WHERE r.status IN ('approved_to_cashier', 'paid')
        GROUP BY expense_type
        ORDER BY total DESC
        """
    ).fetchall()

    by_month = conn.execute(
        """
        SELECT substr(created_at, 1, 7) AS ym, SUM(estimated_total) AS total
        FROM requests
        GROUP BY ym
        ORDER BY ym
        """
    ).fetchall()
    conn.close()

    return render_template(
        "analytics.html",
        title="التحليلات المالية",
        by_dept=by_dept,
        by_expense=by_expense,
        by_month=by_month,
    )


# ============================================================
#                         MAIN
# ============================================================

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
