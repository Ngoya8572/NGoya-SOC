from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3, os, socket, platform, random
from datetime import datetime, timezone

try:
    import psutil
except ImportError:
    psutil = None

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "soc.db")
app = Flask(__name__)
app.secret_key = os.environ.get("SOC_SECRET_KEY", "change-this-development-key")


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def now():
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'analyst')""")
        con.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            severity TEXT NOT NULL, category TEXT NOT NULL,
            source TEXT NOT NULL, message TEXT NOT NULL)""")
        user = con.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not user:
            con.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                        ("admin", generate_password_hash("ChangeMe123!"), "admin"))
        count = con.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"]
        if count == 0:
            con.execute("INSERT INTO events(created_at,severity,category,source,message) VALUES(?,?,?,?,?)",
                        (now(), "INFO", "SYSTEM", "localhost", "NGoya SOC initialized successfully"))


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if "username" not in session:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Authentication required"}), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapped


def network_snapshot():
    result = {"hostname": socket.gethostname(), "platform": platform.system(),
              "interfaces": [], "bytes_sent": 0, "bytes_recv": 0}
    if psutil:
        counters = psutil.net_io_counters(pernic=True)
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for name, c in counters.items():
            ips = [addr.address for addr in addrs.get(name, [])
                   if getattr(addr, "family", None) == socket.AF_INET]
            result["interfaces"].append({
                "name": name, "is_up": stats[name].isup if name in stats else False,
                "speed": stats[name].speed if name in stats else 0,
                "ipv4": ", ".join(ips) or "—",
                "sent": c.bytes_sent, "received": c.bytes_recv
            })
            result["bytes_sent"] += c.bytes_sent
            result["bytes_recv"] += c.bytes_recv
    return result


def event_totals(con):
    return con.execute("""SELECT COUNT(*) AS total,
        SUM(CASE WHEN severity='HIGH' THEN 1 ELSE 0 END) AS high,
        SUM(CASE WHEN severity='MEDIUM' THEN 1 ELSE 0 END) AS medium
        FROM events""").fetchone()


@app.route("/")
def index():
    if "username" not in session:
        return redirect(url_for("login"))
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    with db() as con:
        events = con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 8").fetchall()
        totals = event_totals(con)
    return render_template("dashboard.html", events=events, totals=totals,
                           net=network_snapshot())


@app.route("/api/events")
@login_required
def api_events():
    with db() as con:
        rows = con.execute("SELECT id, created_at, severity, category, source, message "
                           "FROM events ORDER BY id DESC LIMIT 8").fetchall()
        totals = event_totals(con)
    return jsonify({
        "events": [dict(row) for row in rows],
        "totals": {"total": totals["total"] or 0, "high": totals["high"] or 0,
                   "medium": totals["medium"] or 0},
        "server_time": now()
    })


@app.route("/api/status")
@login_required
def api_status():
    return jsonify(network_snapshot())


@app.route("/events")
@login_required
def events():
    with db() as con:
        rows = con.execute("SELECT * FROM events ORDER BY id DESC LIMIT 200").fetchall()
    return render_template("events.html", events=rows)


@app.route("/test-alert", methods=["POST"])
@login_required
def test_alert():
    severity = random.choice(["LOW", "MEDIUM", "HIGH"])
    messages = {
        "LOW": "Test event: unfamiliar service observed in the lab.",
        "MEDIUM": "Test event: repeated connection attempts simulated.",
        "HIGH": "TEST ONLY: simulated high-priority security alert."
    }
    with db() as con:
        con.execute("INSERT INTO events(created_at,severity,category,source,message) VALUES(?,?,?,?,?)",
                    (now(), severity, "SIMULATION", "localhost", messages[severity]))
    flash("A simulated test event was saved. It is not a real attack detection.", "success")
    return redirect(url_for("dashboard"))


@app.route("/health")
def health():
    return jsonify({"status": "ok", "application": "NGoya SOC"})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
