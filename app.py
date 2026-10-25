import hmac
import os
import re
import secrets
import smtplib
import time
from datetime import date, datetime, timedelta
from email.message import EmailMessage
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from flask_wtf.csrf import CSRFProtect, CSRFError
from MySQLdb import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

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



def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash('Silakan login dulu.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
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

    pengirim = os.environ.get('SMTP_FROM') or os.environ.get('SMTP_USER', '')
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
            server.starttls()
            server.login(os.environ.get('SMTP_USER', ''), os.environ.get('SMTP_PASSWORD', ''))
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
                        session['pending_email'] = data['email']
                        flash('Kode OTP sudah dikirim ke email kamu.', 'success')
                        return redirect(url_for('verifikasi'))

                    hapus_pending(data['email'])
                    flash('Gagal mengirim email OTP. Coba lagi nanti.', 'danger')

    elif aksi == 'login':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        key = kunci_percobaan(username)

        if terkunci(key):
            flash('Terlalu banyak percobaan gagal. Coba lagi beberapa menit lagi.', 'danger')
            return render_template('index.html', form=request.form, hari_ini=date.today().isoformat())

        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT id, username, password, role FROM users WHERE username=%s",
            (username,)
        )
        user = cur.fetchone()

        valid = False
        if user:
            tersimpan = user[2]
            if tersimpan.startswith(('scrypt:', 'pbkdf2:')):
                valid = check_password_hash(tersimpan, password)
            else:
                valid = hmac.compare_digest(tersimpan.encode('utf-8'), password.encode('utf-8'))
                if valid:
                    cur.execute(
                        "UPDATE users SET password=%s WHERE id=%s",
                        (generate_password_hash(password), user[0])
                    )
                    mysql.connection.commit()
        cur.close()

        if valid:
            percobaan.pop(key, None)
            session.clear()               
            session.permanent = True
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[3]
            flash(f'Selamat datang {user[1]}!', 'success')

            if user[3] == 'admin':
                return redirect(url_for('admin'))
            return redirect(url_for('home'))

        catat_gagal(key)
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

@app.route('/home')
@login_required
def home():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nama, deskripsi, harga, gambar, stok FROM produk")
    rows = cur.fetchall()
    cur.close()

    produk = [
        {
            'id': str(r[0]),
            'name': r[1],
            'desc': r[2],
            'price': r[3],
            'img': url_for('static', filename='img/' + r[4]) if r[4] else '',
            'stok': int(r[5]),
        }
        for r in rows
    ]
    return render_template('home.html', produk=produk)


def validasi_produk(form):
    """Mengembalikan ((nama, deskripsi, harga, stok), None) atau (None, pesan_error)."""
    nama = form.get('nama', '').strip()
    deskripsi = form.get('deskripsi', '').strip()
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
    return (nama, deskripsi, harga, stok), None


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
    return redirect(url_for('admin'))


@app.route('/admin')
@admin_required
def admin():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nama, deskripsi, harga, gambar, stok FROM produk ORDER BY id DESC")
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

        nama, deskripsi, harga, stok = data
        try:
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO produk (nama, deskripsi, harga, gambar, stok) VALUES (%s,%s,%s,%s,%s)",
                (nama, deskripsi, harga, nama_file or '', stok)
            )
            mysql.connection.commit()
            cur.close()
        except Exception:
            hapus_gambar(nama_file)   # batalkan file yang sudah terlanjur tersimpan
            raise

        flash('Produk berhasil ditambahkan.', 'success')
        return redirect(url_for('admin'))

    return render_template('admin_form.html', p=None, judul='Tambah Produk')


@app.route('/admin/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit(id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nama, deskripsi, harga, gambar, stok FROM produk WHERE id=%s", (id,))
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
        nama, deskripsi, harga, stok = data
        try:
            cur = mysql.connection.cursor()
            cur.execute(
                "UPDATE produk SET nama=%s, deskripsi=%s, harga=%s, gambar=%s, stok=%s WHERE id=%s",
                (nama, deskripsi, harga, gambar_baru, stok, id)
            )
            mysql.connection.commit()
            cur.close()
        except Exception:
            hapus_gambar(nama_file)
            raise

        if nama_file:
            hapus_gambar(gambar_lama)   # gambar lama diganti, hapus filenya

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
        hapus_gambar(row[0])  

    flash('Produk dihapus.', 'success')
    return redirect(url_for('admin'))


if __name__ == '__main__':
    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')