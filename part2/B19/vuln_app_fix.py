from flask import Flask, request, g, render_template_string
import sqlite3, os
import logging
import bcrypt
from datetime import datetime

DB = 'vuln.db'
LOGFILE = 'app.log'

app = Flask(__name__)
# vuln 1 - app.secret_key = 'devkey'

#Fixed
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# -------------------------
# Logging configuration
# -------------------------
logging.basicConfig(
    filename=LOGFILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)
logger.info("Application start")

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB)
        # return rows as tuples (default)
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db:
        db.close()

@app.route('/')
def index():
    return """
    <h2>Safe Web App (Passwords hashed, logging added)</h2>
    <ul>
      <li><a href="/search">Search users</a></li>
      <li><a href="/login">Login</a></li>
    </ul>
    """

# ---------------------------
# SAFE LOGIN (bcrypt + logging)
# ---------------------------
@app.route('/login', methods=['GET','POST'])
def login():
    msg = ''
    if request.method == 'POST':
        user = request.form.get('user','').strip()
        pwd = request.form.get('pwd','')

        db = get_db()

        # fetch stored password hash for the user (if exists)
        row = db.execute(
            "SELECT id, password FROM users WHERE username=?",
            (user,)
        ).fetchone()

        # log the attempt (INFO). Do not log actual password.
        logger.info("Login attempt for user=%s from=%s", user, request.remote_addr)

        if row:
            stored_hash = row[1]
            # stored_hash is a string; bcrypt works with bytes
            try:
                if bcrypt.checkpw(pwd.encode('utf-8'), stored_hash.encode('utf-8')):
                    logger.info("Login SUCCESS for user=%s", user)
                    return f"Welcome, {user}!"
                else:
                    logger.warning("Login FAILED (wrong password) for user=%s", user)
                    msg = "Login failed"
            except Exception as e:
                logger.error("Error checking password for user=%s: %s", user, str(e))
                msg = "Login failed"
        else:
            logger.warning("Login FAILED (no such user) for user=%s", user)
            msg = "Login failed"

    return f"""
      <h3>Login</h3>
      <form method="post">
        User: <input name="user"><br>
        Pass: <input name="pwd" type="password"><br>
        <button>Login</button>
      </form>
      <p>{msg}</p>
    """

# ----------------------------------------------------------
# SAFE SEARCH — parameterized SQL + Jinja auto-escaping (Part B)
# ----------------------------------------------------------
@app.route('/search')
def search():
    q = request.args.get('q','')
    db = get_db()

    # log search queries at debug/notice level (avoid storing too-large inputs)
    if len(q) > 0:
        logger.info("Search query: %s (len=%d) from=%s", q[:200], len(q), request.remote_addr)

    rows = db.execute(
        "SELECT id, username FROM users WHERE username LIKE ?",
        ('%' + q + '%',)
    ).fetchall()

    return render_template_string("""
      <h3>Search results for: {{ q }}</h3>
      <ul>
        {% for r in rows %}
          <li>{{ r[1] }}</li>
        {% endfor %}
      </ul>
      <form><input name="q" value="{{ q }}"><button>Search</button></form>
    """, q=q, rows=rows)

# -------------------------------------
# Database creation (with bcrypt hashes)
# -------------------------------------
def create_db_with_hashed_users():
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    # hash passwords and store as UTF-8 strings
    alice_pw = bcrypt.hashpw(b"alicepass", bcrypt.gensalt()).decode('utf-8')
    bob_pw = bcrypt.hashpw(b"bobpass", bcrypt.gensalt()).decode('utf-8')
    conn.execute("INSERT INTO users(username,password) VALUES (?,?)", ('alice', alice_pw))
    conn.execute("INSERT INTO users(username,password) VALUES (?,?)", ('bob', bob_pw))
    conn.commit()
    conn.close()
    logger.info("Database created with hashed users: alice, bob")

if __name__ == '__main__':
    # create DB if missing (with hashed passwords)
    if not os.path.exists(DB):
        create_db_with_hashed_users()
        print("DB created with users: alice, bob (passwords hashed).")
    # vuln 2 - app.run(debug=True, host="0.0.0.0")

    #Fixed
    app.run(debug=False, host="127.0.0.1")