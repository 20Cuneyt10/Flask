import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)
app.secret_key = os.urandom(24) # Gerçek uygulamalarda bunu bir ortam değişkeninden alın.

DATABASE = 'database.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row # Sütun adlarıyla erişim için
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

        # İlk yönetici hesabını kontrol et ve yoksa ekle
        cursor = db.execute("SELECT * FROM users WHERE username = ?", ('admingizli',))
        admin_exists = cursor.fetchone()
        if not admin_exists:
            admin_password_hash = generate_password_hash("noteasytodothis123") 
            db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       ('admingizli', admin_password_hash, 'admin'))
            db.commit()
            print("Varsayılan yönetici hesabı oluşturuldu: myaccount / adminpass123")

# --- Yardımcı Fonksiyonlar (Değişiklik Yok) ---
def is_logged_in():
    return "username" in session

def is_admin():
    return is_logged_in() and session.get("role") == "admin"

def is_misafir():
    return is_logged_in() and session.get("role") == "misafir"

# --- Rotalar ---
@app.route('/')
def home():
    if not is_logged_in():
        return redirect(url_for('login'))
    if is_admin():
        return redirect(url_for('admin_dashboard'))
    elif is_misafir():
        return redirect(url_for('misafir_dashboard'))
    flash("Bilinmeyen rol veya oturum açılmamış.", "danger")
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        db = get_db()
        cursor = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash('Giriş başarılı!', 'success')
            if user["role"] == "admin":
                return redirect(url_for('admin_dashboard'))
            elif user["role"] == "misafir":
                return redirect(url_for('misafir_dashboard'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre. Kayıtlı olmayan kullanıcılar giriş yapamaz.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('role', None)
    flash('Başarıyla çıkış yaptınız.', 'info')
    return redirect(url_for('login'))

@app.route('/admin_dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if not is_admin():
        flash('Bu sayfaya erişim izniniz yok.', 'danger')
        return redirect(url_for('login'))

    db = get_db()
    if request.method == 'POST':
        misafir_username = request.form.get('misafir_username')
        misafir_password = request.form.get('misafir_password')

        if not misafir_username or not misafir_password:
            flash('Misafir kullanıcı adı ve şifresi boş olamaz.', 'warning')
        else:
            cursor = db.execute("SELECT * FROM users WHERE username = ?", (misafir_username,))
            existing_user = cursor.fetchone()
            if existing_user:
                flash(f'"{misafir_username}" kullanıcı adı zaten mevcut.', 'warning')
            else:
                hashed_password = generate_password_hash(misafir_password)
                db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                           (misafir_username, hashed_password, 'misafir'))
                db.commit()
                flash(f'Misafir hesabı "{misafir_username}" başarıyla oluşturuldu!', 'success')
        return redirect(url_for('admin_dashboard'))

    cursor = db.execute("SELECT username, role FROM users WHERE role = 'misafir'")
    misafir_accounts = cursor.fetchall()
    return render_template('admin_dashboard.html', misafir_accounts=misafir_accounts)

@app.route('/misafir_dashboard')
def misafir_dashboard():
    if not is_misafir():
        flash('Bu sayfaya erişim izniniz yok veya oturum açmadınız.', 'danger')
        return redirect(url_for('login'))
    return render_template('misafir_dashboard.html', username=session.get("username"))

@app.route('/tarih')
def tarih_page():
    if not is_logged_in():
        flash('Bu sayfaya erişmek için lütfen giriş yapın.', 'warning')
        return redirect(url_for('login'))
    return render_template('tarih.html')

# Flask ile çalışırken g (global application context) objesini kullanmak daha doğru
from flask import g

if __name__ == '__main__':
    init_db() # Uygulama ilk çalıştığında veritabanını ve yönetici hesabını oluşturur
    print("--- Veritabanı Hazır ---")
    print("--- Uygulama Başlatılıyor ---")
    app.run(debug=True)
