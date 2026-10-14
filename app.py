import os
import logging
from dotenv import load_dotenv
from flask import (Flask, request, session, redirect, url_for,
                   render_template_string, jsonify, flash)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

# ---------------------------------------------------------------
# Konfigurasi
# ---------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "ganti-ini-di-env")
app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"mysql+pymysql://{os.getenv('DB_USER')}:{os.getenv('DB_PASS')}"
    f"@{os.getenv('DB_HOST')}:3306/{os.getenv('DB_NAME')}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Log aplikasi (masuk ke journald lewat systemd), berguna untuk deteksi brute force
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = app.logger


def client_ip():
    # Nginx meneruskan IP asli lewat X-Forwarded-For (proxy_params)
    return request.headers.get("X-Forwarded-For", request.remote_addr)


# ---------------------------------------------------------------
# Model
# ---------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    stock = db.Column(db.Integer, default=0)


# ---------------------------------------------------------------
# Template (inline supaya tetap satu file)
# ---------------------------------------------------------------
BASE = """
<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title or 'E-Commerce' }}</title>
  <style>
    body{font-family:sans-serif;max-width:800px;margin:2rem auto;padding:0 1rem}
    nav a{margin-right:1rem} table{width:100%;border-collapse:collapse}
    td,th{border-bottom:1px solid #ddd;padding:.5rem;text-align:left}
    .flash{background:#fff3cd;padding:.5rem 1rem;margin:1rem 0}
  </style>
</head>
<body>
  <nav>
    <a href="{{ url_for('index') }}">Produk</a>
    <a href="{{ url_for('cart') }}">Keranjang ({{ session.get('cart', {})|length }})</a>
    {% if session.get('user') %}
      <span>Halo, {{ session['user'] }}</span>
      <a href="{{ url_for('logout') }}">Logout</a>
    {% else %}
      <a href="{{ url_for('login') }}">Login</a>
      <a href="{{ url_for('register') }}">Daftar</a>
    {% endif %}
  </nav>
  {% for m in get_flashed_messages() %}<div class="flash">{{ m }}</div>{% endfor %}
  {{ body|safe }}
</body>
</html>
"""


def page(body, title=None):
    return render_template_string(BASE, body=body, title=title)


# ---------------------------------------------------------------
# Routes
# ---------------------------------------------------------------
@app.route("/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify(status="ok", db="ok")
    except Exception as e:
        log.error("Health check DB gagal: %s", e)
        return jsonify(status="error", db="down"), 500


@app.route("/")
def index():
    q = request.args.get("q", "").strip()
    query = Product.query
    if q:
        # ORM memakai parameterized query (aman dari SQL Injection)
        query = query.filter(Product.name.ilike(f"%{q}%"))
    products = query.all()

    rows = render_template_string("""
      <h2>Daftar Produk</h2>
      <form method="get"><input name="q" value="{{ q }}" placeholder="Cari produk">
      <button>Cari</button></form>
      <table>
        <tr><th>Nama</th><th>Harga</th><th>Stok</th><th></th></tr>
        {% for p in products %}
        <tr>
          <td>{{ p.name }}</td>
          <td>Rp {{ '{:,}'.format(p.price) }}</td>
          <td>{{ p.stock }}</td>
          <td><form method="post" action="{{ url_for('add_to_cart', pid=p.id) }}">
              <button>+ Keranjang</button></form></td>
        </tr>
        {% else %}<tr><td colspan="4">Tidak ada produk.</td></tr>{% endfor %}
      </table>""", products=products, q=q)
    return page(rows, "Produk")


@app.route("/cart/add/<int:pid>", methods=["POST"])
def add_to_cart(pid):
    product = db.session.get(Product, pid)
    if not product:
        flash("Produk tidak ditemukan.")
        return redirect(url_for("index"))
    cart = session.get("cart", {})
    cart[str(pid)] = cart.get(str(pid), 0) + 1
    session["cart"] = cart
    flash(f"{product.name} ditambahkan ke keranjang.")
    return redirect(url_for("index"))


@app.route("/cart")
def cart():
    cart = session.get("cart", {})
    items, total = [], 0
    for pid, qty in cart.items():
        p = db.session.get(Product, int(pid))
        if p:
            subtotal = p.price * qty
            total += subtotal
            items.append((p, qty, subtotal))
    body = render_template_string("""
      <h2>Keranjang</h2>
      <table>
        <tr><th>Produk</th><th>Qty</th><th>Subtotal</th></tr>
        {% for p, qty, sub in items %}
        <tr><td>{{ p.name }}</td><td>{{ qty }}</td>
            <td>Rp {{ '{:,}'.format(sub) }}</td></tr>
        {% else %}<tr><td colspan="3">Keranjang kosong.</td></tr>{% endfor %}
      </table>
      <h3>Total: Rp {{ '{:,}'.format(total) }}</h3>""", items=items, total=total)
    return page(body, "Keranjang")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(password) < 8:
            flash("Username min. 3 karakter dan password min. 8 karakter.")
        elif User.query.filter_by(username=username).first():
            flash("Username sudah dipakai.")
        else:
            db.session.add(User(username=username,
                                password_hash=generate_password_hash(password)))
            db.session.commit()
            flash("Registrasi berhasil, silakan login.")
            return redirect(url_for("login"))
    return page("""
      <h2>Daftar</h2>
      <form method="post">
        <p><input name="username" placeholder="Username" required></p>
        <p><input name="password" type="password" placeholder="Password" required></p>
        <button>Daftar</button>
      </form>""", "Daftar")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session["user"] = user.username
            log.info("LOGIN_SUCCESS user=%s ip=%s", username, client_ip())
            return redirect(url_for("index"))
        # Baris ini yang nanti dibaca Wazuh untuk deteksi brute force
        log.warning("LOGIN_FAILED user=%s ip=%s", username, client_ip())
        flash("Username atau password salah.")
    return page("""
      <h2>Login</h2>
      <form method="post">
        <p><input name="username" placeholder="Username" required></p>
        <p><input name="password" type="password" placeholder="Password" required></p>
        <button>Login</button>
      </form>""", "Login")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------
# Inisialisasi DB + data contoh
# ---------------------------------------------------------------
def init_db():
    with app.app_context():
        db.create_all()
        if Product.query.count() == 0:
            db.session.add_all([
                Product(name="Keyboard Mekanik", price=450000, stock=20),
                Product(name="Mouse Wireless", price=175000, stock=35),
                Product(name="Headset Gaming", price=320000, stock=15),
                Product(name="Webcam HD", price=280000, stock=10),
            ])
            db.session.commit()


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
