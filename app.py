from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_mysqldb import MySQL
from functools import wraps

app = Flask(__name__)
app.secret_key = "rahasia123"

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flask_login'
mysql = MySQL(app)


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Halaman ini hanya untuk admin.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


@app.route('/', methods=['GET', 'POST'])
def login():

    if request.form.get('action') == 'register':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute("SELECT id FROM users WHERE username=%s", (username,))
        user = cur.fetchone()

        if user:
            flash('Username sudah digunakan!', 'danger')
        else:
            cur.execute(
                "INSERT INTO users(username, password) VALUES(%s,%s)",
                (username, password)
            )
            mysql.connection.commit()
            flash('Registrasi berhasil! Silakan login.', 'success')

        cur.close()

    elif request.form.get('action') == 'login':
        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT id, username, role FROM users WHERE username=%s AND password=%s",
            (username, password)
        )
        user = cur.fetchone()
        cur.close()

        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[2]
            flash(f'Selamat datang {username}!', 'success')

            if user[2] == 'admin':
                return redirect(url_for('admin'))
            return redirect(url_for('home'))
        else:
            flash('Username atau password salah!', 'danger')

    return render_template('index.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/home')
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
        nama = request.form['nama'].strip()
        deskripsi = request.form['deskripsi'].strip()
        gambar = request.form['gambar'].strip()
        try:
            harga = int(request.form['harga'])
            stok = int(request.form['stok'])
        except ValueError:
            flash('Harga dan stok harus berupa angka.', 'danger')
            return render_template('admin_form.html', p=None, judul='Tambah Produk')

        if not nama or harga < 0 or stok < 0:
            flash('Nama wajib diisi, harga dan stok tidak boleh negatif.', 'danger')
            return render_template('admin_form.html', p=None, judul='Tambah Produk')

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO produk (nama, deskripsi, harga, gambar, stok) VALUES (%s,%s,%s,%s,%s)",
            (nama, deskripsi, harga, gambar, stok)
        )
        mysql.connection.commit()
        cur.close()
        flash('Produk berhasil ditambahkan.', 'success')
        return redirect(url_for('admin'))

    return render_template('admin_form.html', p=None, judul='Tambah Produk')


@app.route('/admin/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def admin_edit(id):
    cur = mysql.connection.cursor()

    if request.method == 'POST':
        nama = request.form['nama'].strip()
        deskripsi = request.form['deskripsi'].strip()
        gambar = request.form['gambar'].strip()
        try:
            harga = int(request.form['harga'])
            stok = int(request.form['stok'])
        except ValueError:
            cur.close()
            flash('Harga dan stok harus berupa angka.', 'danger')
            return redirect(url_for('admin_edit', id=id))

        cur.execute(
            "UPDATE produk SET nama=%s, deskripsi=%s, harga=%s, gambar=%s, stok=%s WHERE id=%s",
            (nama, deskripsi, harga, gambar, stok, id)
        )
        mysql.connection.commit()
        cur.close()
        flash('Produk berhasil diperbarui.', 'success')
        return redirect(url_for('admin'))

    cur.execute("SELECT id, nama, deskripsi, harga, gambar, stok FROM produk WHERE id=%s", (id,))
    p = cur.fetchone()
    cur.close()
    if not p:
        flash('Produk tidak ditemukan.', 'danger')
        return redirect(url_for('admin'))
    return render_template('admin_form.html', p=p, judul='Edit Produk')


@app.route('/admin/hapus/<int:id>', methods=['POST'])
@admin_required
def admin_hapus(id):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM produk WHERE id=%s", (id,))
    mysql.connection.commit()
    cur.close()
    flash('Produk dihapus.', 'success')
    return redirect(url_for('admin'))


if __name__ == '__main__':
    app.run(debug=True)