from flask import Flask, request, g, render_template_string
import sqlite3, os
import logging
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

DB = 'vuln.db'
LOGFILE = 'app.log'

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))

# Rate limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["100 per hour"])

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
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db:
        db.close()

# Security headers
@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

@app.route('/')
def index():
    return """
    <h2>Enhanced Secure Web App</h2>
    <ul>
      <li><a href="/search">Search users</a></li>
      <li><a href="/login">Login</a></li>
    </ul>
    """

@app.route('/login', methods=['GET','POST'])
@limiter.limit("5 per minute")  # Rate limiting on login
def login():
    msg = ''
    if request.method == 'POST':
        user = request.form.get('user','').strip()
        pwd = request.form.get('pwd','')

        # Input length validation
        if len(user) > 50 or len(pwd) > 128:
            logger.warning("Input too long from=%s", request.remote_addr)
            return "Invalid input", 400

        db = get_db()
        row = db.execute(
            "SELECT id, password FROM users WHERE username=?",
            (user,)
        ).fetchone()

        logger.info("Login attempt for user=%s from=%s", user, request.remote_addr)

        if row:
            stored_hash = row[1]
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
        User: <input name="user" maxlength="50"><br>
        Pass: <input name="pwd" type="password" maxlength="128"><br>
        <button>Login</button>
      </form>
      <p>{msg}</p>
    """

@app.route('/search')
def search():
    q = request.args.get('q','')

    # Input length validation
    if len(q) > 100:
        return "Search query too long", 400

    db = get_db()
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

def create_db_with_hashed_users():
    conn = sqlite3.connect(DB)
    conn.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
    alice_pw = bcrypt.hashpw(b"alicepass", bcrypt.gensalt()).decode('utf-8')
    bob_pw = bcrypt.hashpw(b"bobpass", bcrypt.gensalt()).decode('utf-8')
    conn.execute("INSERT INTO users(username,password) VALUES (?,?)", ('alice', alice_pw))
    conn.execute("INSERT INTO users(username,password) VALUES (?,?)", ('bob', bob_pw))
    conn.commit()
    conn.close()

if __name__ == '__main__':
    if not os.path.exists(DB):
        create_db_with_hashed_users()
        print("DB created with users: alice, bob (passwords hashed).")
    app.run(debug=False, host="127.0.0.1")