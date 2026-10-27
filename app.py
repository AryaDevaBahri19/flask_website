import csv
import hmac
import json
import io
import logging
import os
import re
import secrets
import smtplib
import time
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from logging.handlers import RotatingFileHandler, SysLogHandler
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for, flash, session,
                   Response, send_from_directory, abort)
from flask_mysqldb import MySQL
from flask_wtf.csrf import CSRFProtect, CSRFError
from MySQLdb import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

if os.environ.get('BEHIND_PROXY') == '1':
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)

app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

app.config['MYSQL_HOST'] = os.environ.get('DB_HOST', 'localhost')
app.config['MYSQL_USER'] = os.environ.get('DB_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.environ.get('DB_PASSWORD', '')
app.config['MYSQL_DB'] = os.environ.get('DB_NAME', 'flask_login')

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('USE_HTTPS') == '1'
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 2   
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024        

mysql = MySQL(app)
csrf = CSRFProtect(app)


log_keamanan = logging.getLogger('squishly.security')
log_keamanan.setLevel(logging.INFO)

_handler_file = RotatingFileHandler(
    os.environ.get('LOG_FILE', 'keamanan.log'),
    maxBytes=1_000_000, backupCount=5, encoding='utf-8'
)
_handler_file.setFormatter(logging.Formatter('%(asctime)s squishly: %(message)s'))
log_keamanan.addHandler(_handler_file)

if os.environ.get('SYSLOG_HOST'):
    _handler_syslog = SysLogHandler(
        address=(os.environ['SYSLOG_HOST'], int(os.environ.get('SYSLOG_PORT', '514')))
    )
    _handler_syslog.setFormatter(logging.Formatter('squishly: %(message)s'))
    log_keamanan.addHandler(_handler_syslog)


def _bersih(nilai):
    """Membuang baris baru dan tanda kutip supaya log tidak bisa disisipi baris palsu."""
    return str(nilai).replace('\r', ' ').replace('\n', ' ').replace('"', "'")[:200]


def catat(event, **kv):
    bagian = [f'event={event}', f'ip={request.remote_addr}']
    for k, v in kv.items():
        bagian.append(f'{k}="{_bersih(v)}"')
    log_keamanan.info(' '.join(bagian))

USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{3,30}$')
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
TELEPON_RE = re.compile(r'^\+?[0-9]{8,15}$')
NEGARA_RE = re.compile(r"^[A-Za-z\u00C0-\u00FF .'\-]{2,60}$")
GAMBAR_RE = re.compile(r'^[A-Za-z0-9_\-]+\.(jpg|jpeg|png|webp|gif)$', re.IGNORECASE)

UPLOAD_DIR = os.path.abspath(os.path.join(app.root_path, 'static', 'img'))
os.makedirs(UPLOAD_DIR, exist_ok=True)

MAX_GAGAL = 5
KUNCI_DETIK = 300
percobaan = {}


def kunci_percobaan(username):
    return (request.remote_addr, username.lower())


def terkunci(key):
    data = percobaan.get(key)
    if not data:
        return False
    jumlah, waktu = data
    if time.time() - waktu > KUNCI_DETIK:
        percobaan.pop(key, None)
        return False
    return jumlah >= MAX_GAGAL


def catat_gagal(key):
    jumlah, _ = percobaan.get(key, (0, 0))
    percobaan[key] = (jumlah + 1, time.time())


def pengguna_saat_ini():
    """Membaca status akun yang sedang login langsung dari database.
    Mengembalikan (username, role) atau None kalau tidak login / akun nonaktif / sudah dihapus."""
    uid = session.get('user_id')
    if not uid:
        return None
    cur = mysql.connection.cursor()
    cur.execute("SELECT username, role, aktif FROM users WHERE id=%s", (uid,))
    row = cur.fetchone()
    cur.close()
    if not row or not row[2]:
        return None
    if session.get('role') != row[1]:
        session['role'] = row[1]
    return row[0], row[1]


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not pengguna_saat_ini():
            session.clear()
            flash('Silakan login dulu.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        p = pengguna_saat_ini()
        if not p or p[1] != 'admin':
            catat('akses_admin_ditolak', username=session.get('username', '-'), path=request.path)
            flash('Halaman ini hanya untuk admin.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


@app.after_request
def header_keamanan(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return resp


@app.errorhandler(CSRFError)
def csrf_error(e):
    catat('csrf_gagal', path=request.path)
    flash('Formulir sudah kedaluwarsa. Silakan coba lagi.', 'danger')
    return redirect(url_for('login'))


def validasi_register(form):
    """Mengembalikan (data_dict, None) atau (None, pesan_error)."""
    username = form.get('username', '').strip()
    password = form.get('password', '')
    email = form.get('email', '').strip().lower()
    alamat = form.get('alamat', '').strip()
    negara = form.get('negara', '').strip()
    telepon = re.sub(r'[\s\-().]', '', form.get('telepon', ''))
    tanggal_lahir = form.get('tanggal_lahir', '').strip()

    if not USERNAME_RE.match(username):
        return None, 'Username 3-30 karakter, hanya huruf, angka, dan underscore.'
    if len(password) < 8 or len(password) > 128:
        return None, 'Password minimal 8 karakter.'
    if not EMAIL_RE.match(email) or len(email) > 100:
        return None, 'Format email tidak valid.'
    if not 5 <= len(alamat) <= 255:
        return None, 'Alamat harus 5-255 karakter.'
    if not NEGARA_RE.match(negara):
        return None, 'Nama negara tidak valid.'
    if not TELEPON_RE.match(telepon):
        return None, 'Nomor telepon harus 8-15 angka (boleh diawali +).'

    try:
        tgl = date.fromisoformat(tanggal_lahir)
    except ValueError:
        return None, 'Tanggal lahir tidak valid.'
    if tgl > date.today():
        return None, 'Tanggal lahir tidak boleh dari masa depan.'
    if tgl.year < 1900:
        return None, 'Tanggal lahir tidak valid.'

    return {
        'username': username, 'password': password, 'email': email,
        'alamat': alamat, 'negara': negara, 'telepon': telepon,
        'tanggal_lahir': tgl,
    }, None


OTP_BERLAKU_MENIT = 10    
OTP_MAX_SALAH = 5         
OTP_JEDA_KIRIM = 60       


def buat_otp():
    return f"{secrets.randbelow(1_000_000):06d}"


def kirim_otp(email, kode):
    """Mengirim OTP lewat SMTP. Kalau SMTP_HOST belum diset (mode belajar),
    kode dicetak di terminal tempat Flask berjalan."""
    host = os.environ.get('SMTP_HOST')
    if not host:
        print(f'[DEV] Kode OTP untuk {email}: {kode}')
        return True

    pengirim = os.environ.get('SMTP_FROM') or os.environ.get('SMTP_USER') or 'noreply@squishly.local'
    msg = EmailMessage()
    msg['Subject'] = 'Kode verifikasi Squishly'
    msg['From'] = pengirim
    msg['To'] = email
    msg.set_content(
        f'Kode verifikasi kamu: {kode}\n\n'
        f'Kode berlaku {OTP_BERLAKU_MENIT} menit. Jangan bagikan kode ini ke siapa pun.\n'
        'Kalau kamu tidak merasa mendaftar, abaikan email ini.'
    )
    try:
        with smtplib.SMTP(host, int(os.environ.get('SMTP_PORT', '587')), timeout=10) as server:
            if os.environ.get('SMTP_TLS', '1') == '1':
                server.starttls()
            if os.environ.get('SMTP_USER'):
                server.login(os.environ['SMTP_USER'], os.environ.get('SMTP_PASSWORD', ''))
            server.send_message(msg)
        return True
    except Exception as e:
        app.logger.error('Gagal mengirim OTP: %s', e)
        return False


def hapus_pending(email):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM registrasi_pending WHERE email=%s", (email,))
    mysql.connection.commit()
    cur.close()


def samarkan_email(email):
    nama, _, domain = email.partition('@')
    return nama[:1] + '***@' + domain


@app.route('/', methods=['GET', 'POST'])
def login():
    aksi = request.form.get('action')

    if aksi == 'register':
        data, error = validasi_register(request.form)
        if error:
            flash(error, 'danger')
        else:
            cur = mysql.connection.cursor()
            cur.execute("DELETE FROM registrasi_pending WHERE kadaluarsa < %s",
                        (datetime.now() - timedelta(hours=1),))
            cur.execute(
                "SELECT username, email FROM users WHERE username=%s OR email=%s",
                (data['username'], data['email'])
            )
            ada = cur.fetchall()

            if ada:
                cur.close()
                if any(r[1] == data['email'] for r in ada):
                    flash('Email sudah terdaftar!', 'danger')
                else:
                    flash('Username sudah digunakan!', 'danger')
            else:
                cur.execute("SELECT dikirim_terakhir FROM registrasi_pending WHERE email=%s",
                            (data['email'],))
                lama = cur.fetchone()
                if lama and (datetime.now() - lama[0]).total_seconds() < OTP_JEDA_KIRIM:
                    cur.close()
                    flash('Kode OTP baru saja dikirim. Tunggu sebentar sebelum mencoba lagi.', 'danger')
                else:
                    kode = buat_otp()
                    sekarang = datetime.now()
                    cur.execute("DELETE FROM registrasi_pending WHERE email=%s", (data['email'],))
                    cur.execute(
                        "INSERT INTO registrasi_pending (email, username, password_hash, alamat, negara, "
                        "telepon, tanggal_lahir, otp_hash, kadaluarsa, percobaan, dikirim_terakhir) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,0,%s)",
                        (data['email'], data['username'], generate_password_hash(data['password']),
                         data['alamat'], data['negara'], data['telepon'], data['tanggal_lahir'],
                         generate_password_hash(kode),
                         sekarang + timedelta(minutes=OTP_BERLAKU_MENIT), sekarang)
                    )
                    mysql.connection.commit()
                    cur.close()

                    if kirim_otp(data['email'], kode):
                        catat('otp_terkirim', email=data['email'])
                        session['pending_email'] = data['email']
                        flash('Kode OTP sudah dikirim ke email kamu.', 'success')
                        return redirect(url_for('verifikasi'))

                    catat('otp_gagal_kirim', email=data['email'])
                    hapus_pending(data['email'])
                    flash('Gagal mengirim email OTP. Coba lagi nanti.', 'danger')

    elif aksi == 'login':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        key = kunci_percobaan(username)

        if terkunci(key):
            catat('login_terkunci', username=username)
            flash('Terlalu banyak percobaan gagal. Coba lagi beberapa menit lagi.', 'danger')
            return render_template('index.html', form=request.form, hari_ini=date.today().isoformat())

        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT id, username, password, role, aktif FROM users WHERE username=%s",
            (username,)
        )
        user = cur.fetchone()

        valid = False
        if user:
            tersimpan = user[2]
            if tersimpan.startswith(('scrypt:', 'pbkdf2:')):
                valid = check_password_hash(tersimpan, password)
            else:
                # Akun lama dengan password teks biasa: cocokkan, lalu langsung diubah jadi hash
                valid = hmac.compare_digest(tersimpan.encode('utf-8'), password.encode('utf-8'))
                if valid:
                    cur.execute(
                        "UPDATE users SET password=%s WHERE id=%s",
                        (generate_password_hash(password), user[0])
                    )
                    mysql.connection.commit()
        cur.close()

        if valid and not user[4]:
            catat('login_akun_nonaktif', username=user[1])
            flash('Akun kamu dinonaktifkan. Hubungi admin.', 'danger')
            return render_template('index.html', form=request.form, hari_ini=date.today().isoformat())

        if valid:
            percobaan.pop(key, None)
            session.clear()               
            session.permanent = True
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            catat('login_berhasil', username=user[1], role=user[3])
            flash(f'Selamat datang {user[1]}!', 'success')

            if user[3] == 'admin':
                return redirect(url_for('admin'))
            return redirect(url_for('home'))

        catat_gagal(key)
        catat('login_gagal', username=username)
        flash('Username atau password salah!', 'danger')

    return render_template('index.html', form=request.form, hari_ini=date.today().isoformat())


@app.route('/verifikasi', methods=['GET', 'POST'])
def verifikasi():
    email = session.get('pending_email')
    if not email:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT username, password_hash, alamat, negara, telepon, tanggal_lahir, "
        "otp_hash, kadaluarsa, percobaan FROM registrasi_pending WHERE email=%s",
        (email,)
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        session.pop('pending_email', None)
        flash('Data pendaftaran tidak ditemukan. Silakan daftar ulang.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        kode = request.form.get('kode', '').strip()

        if datetime.now() > row[7]:
            cur.close()
            hapus_pending(email)
            session.pop('pending_email', None)
            catat('otp_kedaluwarsa', email=email)
            flash('Kode OTP sudah kedaluwarsa. Silakan daftar ulang.', 'danger')
            return redirect(url_for('login'))

        if len(kode) == 6 and kode.isdigit() and check_password_hash(row[6], kode):
            try:
                cur.execute(
                    "INSERT INTO users(username, password, email, alamat, negara, telepon, tanggal_lahir) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s)",
                    (row[0], row[1], email, row[2], row[3], row[4], row[5])
                )
                cur.execute("DELETE FROM registrasi_pending WHERE email=%s", (email,))
                mysql.connection.commit()
                cur.close()
                session.pop('pending_email', None)
                catat('registrasi_terverifikasi', email=email, username=row[0])
                flash('Email terverifikasi, registrasi berhasil! Silakan login.', 'success')
            except IntegrityError:
                cur.execute("DELETE FROM registrasi_pending WHERE email=%s", (email,))
                mysql.connection.commit()
                cur.close()
                session.pop('pending_email', None)
                flash('Username atau email sudah digunakan. Silakan daftar ulang.', 'danger')
            return redirect(url_for('login'))

        # kode salah
        cur.execute("UPDATE registrasi_pending SET percobaan = percobaan + 1 WHERE email=%s", (email,))
        mysql.connection.commit()
        sisa = OTP_MAX_SALAH - (row[8] + 1)
        catat('otp_salah', email=email, sisa=max(sisa, 0))
        if sisa <= 0:
            cur.execute("DELETE FROM registrasi_pending WHERE email=%s", (email,))
            mysql.connection.commit()
            cur.close()
            session.pop('pending_email', None)
            flash('Terlalu banyak kode salah. Silakan daftar ulang.', 'danger')
            return redirect(url_for('login'))
        flash(f'Kode OTP salah. Sisa percobaan: {sisa}.', 'danger')

    cur.close()
    return render_template('verifikasi.html', email=samarkan_email(email),
                           menit=OTP_BERLAKU_MENIT)


@app.route('/verifikasi/kirim-ulang', methods=['POST'])
def verifikasi_kirim_ulang():
    email = session.get('pending_email')
    if not email:
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT dikirim_terakhir FROM registrasi_pending WHERE email=%s", (email,))
    row = cur.fetchone()
    if not row:
        cur.close()
        session.pop('pending_email', None)
        return redirect(url_for('login'))

    if (datetime.now() - row[0]).total_seconds() < OTP_JEDA_KIRIM:
        cur.close()
        flash('Tunggu sebentar sebelum meminta kode baru.', 'danger')
        return redirect(url_for('verifikasi'))

    kode = buat_otp()
    sekarang = datetime.now()
    cur.execute(
        "UPDATE registrasi_pending SET otp_hash=%s, kadaluarsa=%s, percobaan=0, dikirim_terakhir=%s "
        "WHERE email=%s",
        (generate_password_hash(kode), sekarang + timedelta(minutes=OTP_BERLAKU_MENIT), sekarang, email)
    )
    mysql.connection.commit()
    cur.close()

    if kirim_otp(email, kode):
        flash('Kode OTP baru sudah dikirim.', 'success')
    else:
        flash('Gagal mengirim email OTP. Coba lagi nanti.', 'danger')
    return redirect(url_for('verifikasi'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


def validasi_produk(form):
    """Mengembalikan ((nama, deskripsi, harga, stok, kategori), None) atau (None, pesan_error)."""
    nama = form.get('nama', '').strip()
    deskripsi = form.get('deskripsi', '').strip()
    kategori = form.get('kategori', '')
    try:
        harga = int(form.get('harga', ''))
        stok = int(form.get('stok', ''))
    except ValueError:
        return None, 'Harga dan stok harus berupa angka.'

    if not nama or len(nama) > 100:
        return None, 'Nama wajib diisi (maksimal 100 karakter).'
    if len(deskripsi) > 255:
        return None, 'Deskripsi maksimal 255 karakter.'
    if not 0 <= harga <= 1_000_000_000:
        return None, 'Harga tidak valid.'
    if not 0 <= stok <= 100_000:
        return None, 'Stok tidak valid.'
    if kategori not in KATEGORI:
        return None, 'Kategori tidak valid.'
    return (nama, deskripsi, harga, stok, kategori), None


# ------------------------------------------------------------
# Upload dan hapus gambar di static/img
# ------------------------------------------------------------
def deteksi_tipe(header):
    """Menentukan jenis gambar dari isi file (bukan dari nama file)."""
    if header.startswith(b'\xff\xd8\xff'):
        return 'jpg'
    if header.startswith(b'\x89PNG\r\n\x1a\n'):
        return 'png'
    if header[:6] in (b'GIF87a', b'GIF89a'):
        return 'gif'
    if header[:4] == b'RIFF' and header[8:12] == b'WEBP':
        return 'webp'
    return None


def simpan_gambar(file):
    """Menyimpan gambar ke static/img dengan nama acak.
    Mengembalikan (nama_file, None), (None, None) kalau tidak ada file, atau (None, pesan_error)."""
    if not file or not file.filename:
        return None, None

    header = file.stream.read(16)
    file.stream.seek(0)
    tipe = deteksi_tipe(header)
    if not tipe:
        return None, 'File harus berupa gambar JPG, PNG, WEBP, atau GIF.'

    nama = secrets.token_hex(8) + '.' + tipe
    file.save(os.path.join(UPLOAD_DIR, nama))
    return nama, None


def hapus_gambar(nama):
    """Menghapus file dari static/img, kecuali masih dipakai produk lain.
    Panggil setelah baris produk di database dihapus atau diubah."""
    if not nama or not GAMBAR_RE.match(nama):
        return

    cur = mysql.connection.cursor()
    cur.execute("SELECT COUNT(*) FROM produk WHERE gambar=%s", (nama,))
    masih_dipakai = cur.fetchone()[0] > 0
    cur.close()
    if masih_dipakai:
        return

    path = os.path.abspath(os.path.join(UPLOAD_DIR, nama))
    if os.path.dirname(path) != UPLOAD_DIR:
        return
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


@app.errorhandler(413)
def file_terlalu_besar(e):
    flash('Ukuran file terlalu besar (maksimal 5 MB).', 'danger')
    if session.get('role') == 'admin':
        return redirect(url_for('admin'))
    return redirect(url_for('riwayat'))


@app.route('/admin')
@admin_required
def admin():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nama, deskripsi, harga, gambar, stok, kategori FROM produk ORDER BY id DESC")
    daftar = cur.fetchall()
    cur.close()
    return render_template('admin.html', daftar=daftar)


@app.route('/admin/tambah', methods=['GET', 'POST'])
@admin_required
def admin_tambah():
    if request.method == 'POST':
        data, error = validasi_produk(request.form)
        if error:
            flash(error, 'danger')
            return render_template('admin_form.html', p=None, judul='Tambah Produk')

        nama_file, error = simpan_gambar(request.files.get('gambar'))
        if error:
            flash(error, 'danger')
            return render_template('admin_form.html', p=None, judul='Tambah Produk')

        nama, deskripsi, harga, stok, kategori = data
        try:
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO produk (nama, deskripsi, harga, gambar, stok, kategori) VALUES (%s,%s,%s,%s,%s,%s)",
                (nama, deskripsi, harga, nama_file or '', stok, kategori)
            )
            mysql.connection.commit()
            cur.close()
        except Exception:
            hapus_gambar(nama_file)   # batalkan file yang sudah terlanjur tersimpan
            raise

        catat('admin_produk_tambah', admin=session.get('username'), produk=nama)
        flash('Produk berhasil ditambahkan.', 'success')
        return redirect(url_for('admin'))

    return render_template('admin_form.html', p=None, judul='Tambah Produk')


@app.route('/admin/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit(id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nama, deskripsi, harga, gambar, stok, kategori FROM produk WHERE id=%s", (id,))
    p = cur.fetchone()
    cur.close()
    if not p:
        flash('Produk tidak ditemukan.', 'danger')
        return redirect(url_for('admin'))

    if request.method == 'POST':
        data, error = validasi_produk(request.form)
        if error:
            flash(error, 'danger')
            return redirect(url_for('admin_edit', id=id))

        nama_file, error = simpan_gambar(request.files.get('gambar'))
        if error:
            flash(error, 'danger')
            return redirect(url_for('admin_edit', id=id))

        gambar_lama = p[4]
        gambar_baru = nama_file or gambar_lama
        nama, deskripsi, harga, stok, kategori = data
        try:
            cur = mysql.connection.cursor()
            cur.execute(
                "UPDATE produk SET nama=%s, deskripsi=%s, harga=%s, gambar=%s, stok=%s, kategori=%s WHERE id=%s",
                (nama, deskripsi, harga, gambar_baru, stok, kategori, id)
            )
            mysql.connection.commit()
            cur.close()
        except Exception:
            hapus_gambar(nama_file)
            raise

        if nama_file:
            hapus_gambar(gambar_lama)   # gambar lama diganti, hapus filenya

        catat('admin_produk_edit', admin=session.get('username'), id=id)
        flash('Produk berhasil diperbarui.', 'success')
        return redirect(url_for('admin'))

    return render_template('admin_form.html', p=p, judul='Edit Produk')


@app.route('/admin/hapus/<int:id>', methods=['POST'])
@admin_required
def admin_hapus(id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT gambar FROM produk WHERE id=%s", (id,))
    row = cur.fetchone()
    cur.execute("DELETE FROM produk WHERE id=%s", (id,))
    mysql.connection.commit()
    cur.close()

    if row:
        hapus_gambar(row[0])   # hapus file gambarnya dari static/img

    catat('admin_produk_hapus', admin=session.get('username'), id=id)
    flash('Produk dihapus.', 'success')
    return redirect(url_for('admin'))


# ------------------------------------------------------------
# Admin: pesanan, bukti bayar, laporan, pengguna
# ------------------------------------------------------------
STATUS_PESANAN = {
    'menunggu_pembayaran': 'Menunggu pembayaran',
    'menunggu_verifikasi': 'Menunggu verifikasi',
    'disetujui': 'Disetujui',
    'ditolak': 'Ditolak',
    'dibatalkan': 'Dibatalkan',
}

# Bukti bayar disimpan di luar folder static, jadi tidak bisa dibuka lewat URL publik.
BUKTI_DIR = os.path.abspath(os.path.join(app.root_path, 'uploads', 'bukti'))
os.makedirs(BUKTI_DIR, exist_ok=True)
BUKTI_RE = re.compile(r'^[A-Za-z0-9_\-]+\.(jpg|jpeg|png|webp|gif|pdf)$', re.IGNORECASE)


@app.template_filter('rupiah')
def filter_rupiah(n):
    return 'Rp ' + f'{int(n or 0):,}'.replace(',', '.')


@app.template_filter('tanggal')
def filter_tanggal(d, fmt='%d-%m-%Y %H:%M'):
    return d.strftime(fmt) if d else '-'


@app.template_filter('status_label')
def filter_status(kode):
    return STATUS_PESANAN.get(kode, kode)


# ---------- Pesanan dan approval bukti bayar ----------
@app.route('/admin/pesanan')
@admin_required
def admin_pesanan():
    batalkan_kedaluwarsa()
    status = request.args.get('status', '')
    cur = mysql.connection.cursor()
    cur.execute("SELECT status, COUNT(*) FROM pesanan GROUP BY status")
    jumlah = {r[0]: r[1] for r in cur.fetchall()}

    sql = ("SELECT p.id, u.username, p.dibuat_pada, p.total, p.status "
           "FROM pesanan p JOIN users u ON u.id = p.user_id")
    args = []
    if status in STATUS_PESANAN:
        sql += " WHERE p.status=%s"
        args.append(status)
    sql += " ORDER BY p.id DESC LIMIT 200"
    cur.execute(sql, args or None)
    daftar = cur.fetchall()
    cur.close()
    return render_template('admin_pesanan.html', daftar=daftar, status=status,
                           jumlah=jumlah, daftar_status=STATUS_PESANAN)


@app.route('/admin/pesanan/<int:id>')
@admin_required
def admin_pesanan_detail(id):
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT p.id, u.username, u.email, u.telepon, u.alamat, p.total, p.status, "
        "p.bukti_bayar, p.catatan_admin, p.dibuat_pada, p.diverifikasi_pada "
        "FROM pesanan p JOIN users u ON u.id = p.user_id WHERE p.id=%s", (id,)
    )
    p = cur.fetchone()
    if not p:
        cur.close()
        flash('Pesanan tidak ditemukan.', 'danger')
        return redirect(url_for('admin_pesanan'))
    cur.execute("SELECT nama_produk, harga, jumlah FROM detail_pesanan WHERE pesanan_id=%s", (id,))
    items = cur.fetchall()
    cur.close()
    return render_template('admin_pesanan_detail.html', p=p, items=items)


@app.route('/admin/bukti/<nama>')
@admin_required
def admin_bukti(nama):
    if not BUKTI_RE.match(nama):
        abort(404)
    return send_from_directory(BUKTI_DIR, nama)


@app.route('/admin/pesanan/<int:id>/setujui', methods=['POST'])
@admin_required
def admin_pesanan_setujui(id):
    cur = mysql.connection.cursor()
    cur.execute(
        "UPDATE pesanan SET status='disetujui', diverifikasi_pada=%s, catatan_admin=NULL "
        "WHERE id=%s AND status='menunggu_verifikasi'", (datetime.now(), id)
    )
    berhasil = cur.rowcount == 1
    mysql.connection.commit()
    cur.close()

    if berhasil:
        catat('pesanan_disetujui', admin=session.get('username'), pesanan=id)
        flash('Pembayaran disetujui.', 'success')
    else:
        flash('Pesanan ini tidak sedang menunggu verifikasi.', 'danger')
    return redirect(url_for('admin_pesanan_detail', id=id))


@app.route('/admin/pesanan/<int:id>/tolak', methods=['POST'])
@admin_required
def admin_pesanan_tolak(id):
    catatan = request.form.get('catatan', '').strip()[:255]
    if not catatan:
        flash('Alasan penolakan wajib diisi.', 'danger')
        return redirect(url_for('admin_pesanan_detail', id=id))

    cur = mysql.connection.cursor()
    cur.execute(
        "UPDATE pesanan SET status='ditolak', diverifikasi_pada=%s, catatan_admin=%s "
        "WHERE id=%s AND status='menunggu_verifikasi'", (datetime.now(), catatan, id)
    )
    berhasil = cur.rowcount == 1
    if berhasil:
        # stok barang dikembalikan, karena pesanan ini batal
        cur.execute(
            "UPDATE produk pr JOIN detail_pesanan d ON d.produk_id = pr.id "
            "SET pr.stok = pr.stok + d.jumlah WHERE d.pesanan_id=%s", (id,)
        )
    mysql.connection.commit()
    cur.close()

    if berhasil:
        catat('pesanan_ditolak', admin=session.get('username'), pesanan=id)
        flash('Pembayaran ditolak dan stok dikembalikan.', 'success')
    else:
        flash('Pesanan ini tidak sedang menunggu verifikasi.', 'danger')
    return redirect(url_for('admin_pesanan_detail', id=id))


# ---------- Laporan transaksi ----------
def rentang_laporan():
    try:
        sampai = date.fromisoformat(request.args.get('sampai', ''))
    except ValueError:
        sampai = date.today()
    try:
        dari = date.fromisoformat(request.args.get('dari', ''))
    except ValueError:
        dari = sampai - timedelta(days=29)
    if dari > sampai:
        dari, sampai = sampai, dari
    if (sampai - dari).days > 366:
        dari = sampai - timedelta(days=366)
    awal = datetime.combine(dari, datetime.min.time())
    akhir = datetime.combine(sampai + timedelta(days=1), datetime.min.time())
    return dari, sampai, awal, akhir


@app.route('/admin/laporan')
@admin_required
def admin_laporan():
    dari, sampai, awal, akhir = rentang_laporan()
    cur = mysql.connection.cursor()

    cur.execute(
        "SELECT COUNT(*), "
        "COALESCE(SUM(status='disetujui'), 0), "
        "COALESCE(SUM(status='menunggu_verifikasi'), 0), "
        "COALESCE(SUM(CASE WHEN status='disetujui' THEN total END), 0) "
        "FROM pesanan WHERE dibuat_pada >= %s AND dibuat_pada < %s", (awal, akhir)
    )
    ringkasan = cur.fetchone()

    cur.execute(
        "SELECT DATE(dibuat_pada), COUNT(*), "
        "SUM(CASE WHEN status='disetujui' THEN 1 ELSE 0 END), "
        "COALESCE(SUM(CASE WHEN status='disetujui' THEN total END), 0) "
        "FROM pesanan WHERE dibuat_pada >= %s AND dibuat_pada < %s "
        "GROUP BY DATE(dibuat_pada) ORDER BY DATE(dibuat_pada) DESC", (awal, akhir)
    )
    harian = cur.fetchall()

    cur.execute(
        "SELECT d.nama_produk, SUM(d.jumlah), SUM(d.jumlah * d.harga) "
        "FROM detail_pesanan d JOIN pesanan p ON p.id = d.pesanan_id "
        "WHERE p.status='disetujui' AND p.dibuat_pada >= %s AND p.dibuat_pada < %s "
        "GROUP BY d.nama_produk ORDER BY SUM(d.jumlah) DESC LIMIT 10", (awal, akhir)
    )
    terlaris = cur.fetchall()
    cur.close()

    return render_template('admin_laporan.html', dari=dari, sampai=sampai,
                           ringkasan=ringkasan, harian=harian, terlaris=terlaris)


def aman_csv(nilai):
    """Mencegah CSV injection: sel yang diawali = + - @ akan dibaca Excel sebagai rumus."""
    nilai = '' if nilai is None else str(nilai)
    return "'" + nilai if nilai[:1] in ('=', '+', '-', '@', '\t', '\r') else nilai


@app.route('/admin/laporan.csv')
@admin_required
def admin_laporan_csv():
    dari, sampai, awal, akhir = rentang_laporan()
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT p.id, p.dibuat_pada, u.username, p.status, p.total "
        "FROM pesanan p JOIN users u ON u.id = p.user_id "
        "WHERE p.dibuat_pada >= %s AND p.dibuat_pada < %s ORDER BY p.id", (awal, akhir)
    )
    rows = cur.fetchall()
    cur.close()

    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['ID Pesanan', 'Tanggal', 'Pelanggan', 'Status', 'Total (Rp)'])
    for r in rows:
        w.writerow([r[0], r[1].strftime('%Y-%m-%d %H:%M'), aman_csv(r[2]),
                    STATUS_PESANAN.get(r[3], r[3]), r[4]])

    catat('laporan_export', admin=session.get('username'), dari=dari, sampai=sampai)
    return Response('\ufeff' + buf.getvalue(), mimetype='text/csv', headers={
        'Content-Disposition': f'attachment; filename=laporan_{dari}_{sampai}.csv'
    })


# ---------- Manajemen akun pengguna ----------
@app.route('/admin/pengguna')
@admin_required
def admin_pengguna():
    q = request.args.get('q', '').strip()[:50]
    sql = "SELECT id, username, email, telepon, negara, role, aktif FROM users"
    args = []
    if q:
        aman = q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        sql += " WHERE username LIKE %s OR email LIKE %s"
        args = [f'%{aman}%', f'%{aman}%']
    sql += " ORDER BY id DESC LIMIT 200"
    cur = mysql.connection.cursor()
    cur.execute(sql, args or None)
    daftar = cur.fetchall()
    cur.close()
    return render_template('admin_pengguna.html', daftar=daftar, q=q)


@app.route('/admin/pengguna/<int:id>/aktif', methods=['POST'])
@admin_required
def admin_pengguna_aktif(id):
    if id == session.get('user_id'):
        flash('Kamu tidak bisa menonaktifkan akunmu sendiri.', 'danger')
        return redirect(url_for('admin_pengguna'))

    nilai = 1 if request.form.get('aktif') == '1' else 0
    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET aktif=%s WHERE id=%s", (nilai, id))
    mysql.connection.commit()
    cur.close()

    catat('pengguna_aktif' if nilai else 'pengguna_nonaktif',
          admin=session.get('username'), target_id=id)
    flash('Akun diaktifkan.' if nilai else 'Akun dinonaktifkan.', 'success')
    return redirect(url_for('admin_pengguna'))


@app.route('/admin/pengguna/<int:id>/role', methods=['POST'])
@admin_required
def admin_pengguna_role(id):
    role = request.form.get('role', '')
    if role not in ('user', 'admin'):
        flash('Role tidak valid.', 'danger')
        return redirect(url_for('admin_pengguna'))
    if id == session.get('user_id'):
        flash('Kamu tidak bisa mengubah role akunmu sendiri.', 'danger')
        return redirect(url_for('admin_pengguna'))

    cur = mysql.connection.cursor()
    cur.execute("UPDATE users SET role=%s WHERE id=%s", (role, id))
    mysql.connection.commit()
    cur.close()

    catat('pengguna_ubah_role', admin=session.get('username'), target_id=id, role=role)
    flash('Role pengguna diperbarui.', 'success')
    return redirect(url_for('admin_pengguna'))


KATEGORI = {
    'big_plushie': 'Big Plushie',
    'plushie': 'Plushie',
    'squishy': 'Squishy',
    'pillow': 'Pillow',
}

URUTAN = {
    'terbaru': 'p.id DESC',
    'termurah': 'p.harga ASC',
    'termahal': 'p.harga DESC',
    'rating': 'rata DESC, jumlah_review DESC',
}

PESANAN_KEDALUWARSA_JAM = 24   # pesanan yang belum dibayar dibatalkan otomatis setelah 24 jam

BANK = {
    'nama': os.environ.get('BANK_NAMA', 'BCA'),
    'rekening': os.environ.get('BANK_REKENING', '1234567890'),
    'atas_nama': os.environ.get('BANK_ATAS_NAMA', 'Squishly (contoh)'),
}


@app.context_processor
def konteks_global():
    return {'KATEGORI': KATEGORI}


@app.template_filter('kategori_label')
def filter_kategori(kode):
    return KATEGORI.get(kode, kode or '-')


def like_aman(teks):
    return teks.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')


# ---------- Katalog: cari, filter, urutkan ----------
@app.route('/home')
@login_required
def home():
    q = request.args.get('q', '').strip()[:50]
    kategori = request.args.get('kategori', '')
    urut = request.args.get('urut', 'terbaru')
    if urut not in URUTAN:
        urut = 'terbaru'
    if kategori not in KATEGORI:
        kategori = ''

    sql = ("SELECT p.id, p.nama, p.deskripsi, p.harga, p.gambar, p.stok, p.kategori, "
           "COALESCE(AVG(r.rating), 0) AS rata, COUNT(r.id) AS jumlah_review "
           "FROM produk p LEFT JOIN review r ON r.produk_id = p.id")
    where, args = [], []
    if kategori:
        where.append("p.kategori=%s")
        args.append(kategori)
    if q:
        where.append("(p.nama LIKE %s OR p.deskripsi LIKE %s)")
        args += [f'%{like_aman(q)}%', f'%{like_aman(q)}%']
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " GROUP BY p.id ORDER BY " + URUTAN[urut] + " LIMIT 60"

    cur = mysql.connection.cursor()
    cur.execute(sql, args or None)
    produk = cur.fetchall()
    cur.close()
    return render_template('home.html', produk=produk, q=q, kategori=kategori, urut=urut)


@app.route('/produk/<int:id>')
@login_required
def produk_detail(id):
    uid = session['user_id']
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nama, deskripsi, harga, gambar, stok, kategori FROM produk WHERE id=%s", (id,))
    p = cur.fetchone()
    if not p:
        cur.close()
        flash('Produk tidak ditemukan.', 'danger')
        return redirect(url_for('home'))

    cur.execute("SELECT COALESCE(AVG(rating), 0), COUNT(*) FROM review WHERE produk_id=%s", (id,))
    rata, jumlah = cur.fetchone()
    cur.execute(
        "SELECT u.username, r.rating, r.komentar, r.dibuat_pada FROM review r "
        "JOIN users u ON u.id = r.user_id WHERE r.produk_id=%s "
        "ORDER BY r.dibuat_pada DESC LIMIT 50", (id,)
    )
    ulasan = cur.fetchall()
    cur.execute(
        "SELECT 1 FROM pesanan ps JOIN detail_pesanan d ON d.pesanan_id = ps.id "
        "WHERE ps.user_id=%s AND d.produk_id=%s AND ps.status='disetujui' LIMIT 1", (uid, id)
    )
    boleh_review = cur.fetchone() is not None
    cur.execute("SELECT rating, komentar FROM review WHERE produk_id=%s AND user_id=%s", (id, uid))
    ulasan_saya = cur.fetchone()
    cur.close()

    return render_template('produk.html', p=p, rata=float(rata), jumlah=jumlah, ulasan=ulasan,
                           boleh_review=boleh_review, ulasan_saya=ulasan_saya)


@app.route('/produk/<int:id>/review', methods=['POST'])
@login_required
def produk_review(id):
    uid = session['user_id']
    try:
        rating = int(request.form.get('rating', ''))
    except ValueError:
        rating = 0
    komentar = request.form.get('komentar', '').strip()

    if not 1 <= rating <= 5:
        flash('Pilih rating 1 sampai 5.', 'danger')
        return redirect(url_for('produk_detail', id=id))
    if len(komentar) > 500:
        flash('Ulasan maksimal 500 karakter.', 'danger')
        return redirect(url_for('produk_detail', id=id))

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT 1 FROM pesanan ps JOIN detail_pesanan d ON d.pesanan_id = ps.id "
        "WHERE ps.user_id=%s AND d.produk_id=%s AND ps.status='disetujui' LIMIT 1", (uid, id)
    )
    if not cur.fetchone():
        cur.close()
        flash('Kamu hanya bisa mengulas produk yang pernah kamu beli (pembayaran sudah disetujui).', 'danger')
        return redirect(url_for('produk_detail', id=id))

    cur.execute(
        "INSERT INTO review (produk_id, user_id, rating, komentar) VALUES (%s,%s,%s,%s) "
        "ON DUPLICATE KEY UPDATE rating=VALUES(rating), komentar=VALUES(komentar), dibuat_pada=CURRENT_TIMESTAMP",
        (id, uid, rating, komentar)
    )
    mysql.connection.commit()
    cur.close()
    catat('review_dikirim', username=session.get('username'), produk=id, rating=rating)
    flash('Terima kasih, ulasanmu tersimpan.', 'success')
    return redirect(url_for('produk_detail', id=id))


# ---------- Pembatalan dan kedaluwarsa pesanan ----------
def _batalkan(cur, pesanan_id, catatan, user_id=None):
    """Membatalkan pesanan yang belum dibayar dan mengembalikan stoknya.
    Berhasil hanya kalau statusnya masih 'menunggu_pembayaran'."""
    sql = "UPDATE pesanan SET status='dibatalkan', catatan_admin=%s WHERE id=%s AND status='menunggu_pembayaran'"
    args = [catatan, pesanan_id]
    if user_id is not None:
        sql += " AND user_id=%s"
        args.append(user_id)
    cur.execute(sql, args)
    if cur.rowcount != 1:
        return False
    cur.execute(
        "UPDATE produk pr JOIN detail_pesanan d ON d.produk_id = pr.id "
        "SET pr.stok = pr.stok + d.jumlah WHERE d.pesanan_id=%s", (pesanan_id,)
    )
    return True


def batalkan_kedaluwarsa():
    batas = datetime.now() - timedelta(hours=PESANAN_KEDALUWARSA_JAM)
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM pesanan WHERE status='menunggu_pembayaran' AND dibuat_pada < %s", (batas,))
    for (pid,) in cur.fetchall():
        _batalkan(cur, pid, 'Dibatalkan otomatis: melewati batas waktu pembayaran')
    mysql.connection.commit()
    cur.close()



@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    batalkan_kedaluwarsa()

    
    try:
        data = json.loads(request.form.get('items', '[]')[:5000])
        if not isinstance(data, list) or not 0 < len(data) <= 50:
            raise ValueError
        jumlah = {}
        for it in data:
            pid, q = int(it['id']), int(it['q'])
            if q < 1:
                raise ValueError
            jumlah[pid] = jumlah.get(pid, 0) + q
        if any(q > 99 for q in jumlah.values()):
            raise ValueError
    except (ValueError, TypeError, KeyError):
        flash('Data keranjang tidak valid.', 'danger')
        return redirect(url_for('home'))

    ids = list(jumlah)
    marks = ','.join(['%s'] * len(ids))
    cur = mysql.connection.cursor()
    try:
        cur.execute(f"SELECT id, nama, harga, stok FROM produk WHERE id IN ({marks}) FOR UPDATE", ids)
        produk = {r[0]: r for r in cur.fetchall()}

        for pid, q in jumlah.items():
            p = produk.get(pid)
            if not p:
                raise LookupError('Ada produk di keranjang yang sudah tidak tersedia.')
            if p[3] < q:
                raise LookupError(f'Stok {p[1]} tidak cukup (tersisa {p[3]}). Kurangi jumlahnya.')

        total = sum(produk[pid][2] * q for pid, q in jumlah.items())
        cur.execute("INSERT INTO pesanan (user_id, total, status) VALUES (%s,%s,'menunggu_pembayaran')",
                    (session['user_id'], total))
        pesanan_id = cur.lastrowid

        for pid, q in jumlah.items():
            cur.execute("UPDATE produk SET stok = stok - %s WHERE id=%s AND stok >= %s", (q, pid, q))
            if cur.rowcount != 1:
                raise LookupError(f'Stok {produk[pid][1]} baru saja habis.')
            cur.execute(
                "INSERT INTO detail_pesanan (pesanan_id, produk_id, nama_produk, harga, jumlah) "
                "VALUES (%s,%s,%s,%s,%s)", (pesanan_id, pid, produk[pid][1], produk[pid][2], q)
            )
        mysql.connection.commit()
    except LookupError as e:
        mysql.connection.rollback()
        cur.close()
        flash(str(e), 'danger')
        return redirect(url_for('home'))
    except Exception:
        mysql.connection.rollback()
        cur.close()
        raise
    cur.close()

    catat('checkout', username=session.get('username'), pesanan=pesanan_id, total=total)
    return redirect(url_for('pesanan_detail', id=pesanan_id, baru=1))


# ---------- Riwayat dan detail pesanan ----------
@app.route('/pesanan')
@login_required
def riwayat():
    batalkan_kedaluwarsa()
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT p.id, p.dibuat_pada, p.total, p.status, "
        "(SELECT COALESCE(SUM(jumlah), 0) FROM detail_pesanan d WHERE d.pesanan_id = p.id) "
        "FROM pesanan p WHERE p.user_id=%s ORDER BY p.id DESC LIMIT 100", (session['user_id'],)
    )
    daftar = cur.fetchall()
    cur.close()
    return render_template('pesanan_riwayat.html', daftar=daftar)


@app.route('/pesanan/<int:id>')
@login_required
def pesanan_detail(id):
    batalkan_kedaluwarsa()
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT id, total, status, bukti_bayar, catatan_admin, dibuat_pada, diverifikasi_pada "
        "FROM pesanan WHERE id=%s AND user_id=%s", (id, session['user_id'])
    )
    p = cur.fetchone()
    if not p:
        cur.close()
        flash('Pesanan tidak ditemukan.', 'danger')
        return redirect(url_for('riwayat'))
    cur.execute("SELECT nama_produk, harga, jumlah FROM detail_pesanan WHERE pesanan_id=%s", (id,))
    items = cur.fetchall()
    cur.close()

    batas = p[5] + timedelta(hours=PESANAN_KEDALUWARSA_JAM)
    return render_template('pesanan_detail.html', p=p, items=items, bank=BANK, batas=batas,
                           baru=request.args.get('baru') == '1')


def simpan_bukti(file):
    """Menyimpan bukti transfer (gambar atau PDF) ke uploads/bukti dengan nama acak."""
    if not file or not file.filename:
        return None, 'Pilih file bukti pembayaran dulu.'
    header = file.stream.read(16)
    file.stream.seek(0)
    tipe = deteksi_tipe(header)
    if not tipe and header.startswith(b'%PDF-'):
        tipe = 'pdf'
    if not tipe:
        return None, 'Bukti harus berupa gambar (JPG, PNG, WEBP, GIF) atau PDF.'
    nama = secrets.token_hex(12) + '.' + tipe
    file.save(os.path.join(BUKTI_DIR, nama))
    return nama, None


def hapus_bukti(nama):
    if not nama or not BUKTI_RE.match(nama):
        return
    path = os.path.abspath(os.path.join(BUKTI_DIR, nama))
    if os.path.dirname(path) != BUKTI_DIR:
        return
    try:
        os.remove(path)
    except FileNotFoundError:
        pass


@app.route('/pesanan/<int:id>/bukti', methods=['POST'])
@login_required
def pesanan_bukti(id):
    uid = session['user_id']
    cur = mysql.connection.cursor()
    cur.execute("SELECT status, bukti_bayar FROM pesanan WHERE id=%s AND user_id=%s", (id, uid))
    row = cur.fetchone()
    if not row:
        cur.close()
        flash('Pesanan tidak ditemukan.', 'danger')
        return redirect(url_for('riwayat'))
    if row[0] not in ('menunggu_pembayaran', 'menunggu_verifikasi'):
        cur.close()
        flash('Bukti pembayaran tidak bisa diunggah untuk pesanan ini.', 'danger')
        return redirect(url_for('pesanan_detail', id=id))

    nama, error = simpan_bukti(request.files.get('bukti'))
    if error:
        cur.close()
        flash(error, 'danger')
        return redirect(url_for('pesanan_detail', id=id))

    cur.execute(
        "UPDATE pesanan SET bukti_bayar=%s, status='menunggu_verifikasi' "
        "WHERE id=%s AND user_id=%s AND status IN ('menunggu_pembayaran','menunggu_verifikasi')",
        (nama, id, uid)
    )
    berhasil = cur.rowcount == 1
    mysql.connection.commit()
    cur.close()

    if berhasil:
        hapus_bukti(row[1])        # bukti lama diganti
        catat('bukti_diunggah', username=session.get('username'), pesanan=id)
        flash('Bukti pembayaran terkirim. Admin akan memeriksanya.', 'success')
    else:
        hapus_bukti(nama)
        flash('Pesanan ini sudah tidak bisa menerima bukti pembayaran.', 'danger')
    return redirect(url_for('pesanan_detail', id=id))


@app.route('/pesanan/<int:id>/batal', methods=['POST'])
@login_required
def pesanan_batal(id):
    cur = mysql.connection.cursor()
    berhasil = _batalkan(cur, id, 'Dibatalkan oleh pelanggan', user_id=session['user_id'])
    mysql.connection.commit()
    cur.close()
    if berhasil:
        catat('pesanan_dibatalkan', username=session.get('username'), pesanan=id)
        flash('Pesanan dibatalkan.', 'success')
    else:
        flash('Pesanan ini tidak bisa dibatalkan.', 'danger')
    return redirect(url_for('pesanan_detail', id=id))


@app.route('/bukti/<nama>')
@login_required
def bukti_file(nama):
    """Bukti bayar hanya bisa dilihat pemilik pesanan atau admin."""
    if not BUKTI_RE.match(nama):
        abort(404)
    if session.get('role') != 'admin':
        cur = mysql.connection.cursor()
        cur.execute("SELECT 1 FROM pesanan WHERE bukti_bayar=%s AND user_id=%s", (nama, session['user_id']))
        milik_sendiri = cur.fetchone() is not None
        cur.close()
        if not milik_sendiri:
            abort(404)
    return send_from_directory(BUKTI_DIR, nama)

def cocok_password(tersimpan, masukan):
    if tersimpan and tersimpan.startswith(('scrypt:', 'pbkdf2:')):
        return check_password_hash(tersimpan, masukan)
    return hmac.compare_digest((tersimpan or '').encode('utf-8'), masukan.encode('utf-8'))


def validasi_profil(form):
    alamat = form.get('alamat', '').strip()
    negara = form.get('negara', '').strip()
    telepon = re.sub(r'[\s\-().]', '', form.get('telepon', ''))
    tanggal_lahir = form.get('tanggal_lahir', '').strip()

    if not 5 <= len(alamat) <= 255:
        return None, 'Alamat harus 5-255 karakter.'
    if not NEGARA_RE.match(negara):
        return None, 'Nama negara tidak valid.'
    if not TELEPON_RE.match(telepon):
        return None, 'Nomor telepon harus 8-15 angka (boleh diawali +).'
    try:
        tgl = date.fromisoformat(tanggal_lahir)
    except ValueError:
        return None, 'Tanggal lahir tidak valid.'
    if tgl > date.today():
        return None, 'Tanggal lahir tidak boleh dari masa depan.'
    if tgl.year < 1900:
        return None, 'Tanggal lahir tidak valid.'
    return (alamat, negara, telepon, tgl), None


@app.route('/profil', methods=['GET', 'POST'])
@login_required
def profil():
    uid = session['user_id']

    if request.method == 'POST':
        aksi = request.form.get('aksi')

        if aksi == 'data':
            data, error = validasi_profil(request.form)
            if error:
                flash(error, 'danger')
            else:
                cur = mysql.connection.cursor()
                cur.execute("UPDATE users SET alamat=%s, negara=%s, telepon=%s, tanggal_lahir=%s WHERE id=%s",
                            data + (uid,))
                mysql.connection.commit()
                cur.close()
                catat('profil_diubah', username=session.get('username'))
                flash('Profil diperbarui.', 'success')
                return redirect(url_for('profil'))

        elif aksi == 'password':
            lama = request.form.get('password_lama', '')
            baru = request.form.get('password_baru', '')
            ulang = request.form.get('password_ulang', '')

            cur = mysql.connection.cursor()
            cur.execute("SELECT password FROM users WHERE id=%s", (uid,))
            tersimpan = cur.fetchone()[0]

            if not cocok_password(tersimpan, lama):
                cur.close()
                catat('ganti_password_gagal', username=session.get('username'))
                flash('Password lama salah.', 'danger')
            elif not 8 <= len(baru) <= 128:
                cur.close()
                flash('Password baru minimal 8 karakter.', 'danger')
            elif baru != ulang:
                cur.close()
                flash('Konfirmasi password baru tidak sama.', 'danger')
            elif baru == lama:
                cur.close()
                flash('Password baru harus berbeda dari yang lama.', 'danger')
            else:
                cur.execute("UPDATE users SET password=%s WHERE id=%s", (generate_password_hash(baru), uid))
                mysql.connection.commit()
                cur.close()
                catat('password_diubah', username=session.get('username'))
                flash('Password berhasil diubah.', 'success')
                return redirect(url_for('profil'))

    cur = mysql.connection.cursor()
    cur.execute("SELECT username, email, alamat, negara, telepon, tanggal_lahir FROM users WHERE id=%s", (uid,))
    u = cur.fetchone()
    cur.close()
    return render_template('profil.html', u=u, form=request.form, hari_ini=date.today().isoformat())


if __name__ == '__main__':
    # Debug hanya menyala kalau FLASK_DEBUG=1 diset (jangan dipakai saat online)
    # HOST=0.0.0.0 supaya bisa diakses VM lain. Jangan kombinasikan dengan FLASK_DEBUG=1.
    app.run(host=os.environ.get('HOST', '127.0.0.1'),
            debug=os.environ.get('FLASK_DEBUG') == '1')