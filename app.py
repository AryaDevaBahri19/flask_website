from flask import Flask, render_template, request, redirect, url_for, flash
from flask_mysqldb import MySQL
import time

app = Flask(__name__)
app.secret_key = "rahasia123"

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'flask_login'
mysql = MySQL(app)


@app.route('/', methods=['GET', 'POST'])
def login():

    if request.form.get('action') == 'register':
        username = request.form['username']
        password = request.form['password']
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT * FROM users WHERE username=%s",
            (username,)
        )
        user = cur.fetchone()
        if user:
            flash('Username sudah digunakan!', 'danger')
        else:
            cur.execute(
                "INSERT INTO users(username, password) VALUES(%s,%s)",
                (username, password)
            )
            mysql.connection.commit()
            flash('Registrasi berhasil!', 'success')
            time.sleep(3)
            return redirect(url_for('home'))

        cur.close()

    elif request.form.get('action') == 'login':

        username = request.form['username']
        password = request.form['password']

        cur = mysql.connection.cursor()

        cur.execute(
            "SELECT * FROM users WHERE username=%s AND password=%s",
            (username, password)
        )

        user = cur.fetchone()

        if user:
            flash(f'Selamat datang {username}!', 'success')
            time.sleep(3)
            return redirect (url_for('home'))

        else:
            flash('Username atau password salah!', 'danger')

        cur.close()
    return render_template('index.html')


@app.route('/home')
def home():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id, nama, deskripsi, harga, gambar FROM produk")
    rows = cur.fetchall()
    cur.close()

    produk = [
        {
            'id': str(r[0]),
            'name': r[1],
            'desc': r[2],
            'price': r[3],
            'img': url_for('static', filename='img/' + r[4]) if r[4] else ''
        }
        for r in rows
    ]
    return render_template('home.html', produk=produk)

if __name__ == '__main__':
    app.run(debug=True)