import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Flask uygulamasını başlat
app = Flask(__name__)

# GİZLİ ANAHTAR: Render'da ortam değişkeni olarak ayarlanmalı
# Yerel geliştirme için bir varsayılan değer de sağlayabilirsiniz.
app.secret_key = os.environ.get('SECRET_KEY', 'cok_guclu_bir_yerel_gizli_anahtar_olmalı_burada')

# Veritabanı dosyasının adı (proje kök dizininde oluşturulacak)
DATABASE = 'database.db'

def get_db():
    """Mevcut uygulama bağlamı için veritabanı bağlantısını açar veya döndürür."""
    db = getattr(g, '_database', None)
    if db is None:
        # Veritabanı yolunu app.root_path'e göre belirle
        # app.root_path, flask_app.py (veya app.py) dosyasının bulunduğu dizindir.
        db_path = os.path.join(app.root_path, DATABASE)
        db = g._database = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row # Sütun adlarıyla erişim için
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Uygulama bağlamı sona erdiğinde veritabanı bağlantısını kapatır."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Veritabanı şemasını (schema.sql) kullanarak tabloları oluşturur ve
       varsayılan bir yönetici kullanıcı ekler (eğer mevcut değilse)."""
    # Bu fonksiyonun bir uygulama bağlamı içinde çağrılması gerekir.
    # with app.app_context(): # Zaten ensure_db_initialized içindeki app_context'ten çağrılacak
    db = get_db()
    # schema.sql dosyasının flask_app.py ile aynı dizinde olduğundan emin olun
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()

    # Varsayılan yönetici hesabını kontrol et ve yoksa ekle
    # Kendi istediğiniz yönetici kullanıcı adını kullanın
    admin_username_to_check = os.environ.get('ADMIN_USERNAME', 'myaccount')
    cursor = db.execute("SELECT * FROM users WHERE username = ?", (admin_username_to_check,))
    admin_exists = cursor.fetchone()

    if not admin_exists:
        # Ortam değişkeninden yönetici şifresini alın veya bir varsayılan (güçlü) şifre kullanın
        # CANLI ORTAMDA KESİNLİKLE GÜÇLÜ BİR ŞİFRE KULLANIN VE ORTAM DEĞİŞKENİNDEN ALIN!
        admin_password = os.environ.get('ADMIN_PASSWORD', 'GucluBirSifreBuraya123!')
        if admin_password == 'GucluBirSifreBuraya123!':
            print(f"UYARI: Varsayılan ADMIN_PASSWORD kullanılıyor. Lütfen Render'da bir ortam değişkeni ayarlayın.")

        admin_password_hash = generate_password_hash(admin_password)
        db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                   (admin_username_to_check, admin_password_hash, 'admin'))
        db.commit()
        print(f"Varsayılan yönetici hesabı ('{admin_username_to_check}') oluşturuldu.")
    else:
        print(f"Yönetici hesabı ('{admin_username_to_check}') zaten mevcut.")


# --- Veritabanının başlatıldığından emin olmak için fonksiyon ---
def ensure_db_initialized():
    """Uygulama ilk yüklendiğinde veritabanının var olup olmadığını kontrol eder
       ve gerekirse init_db() fonksiyonunu çağırır."""
    # Bu yol, Gunicorn'un çalıştığı yere göre (genellikle proje kök dizini) görecelidir.
    db_file_path = os.path.join(app.root_path, DATABASE) # app.root_path ile daha güvenli
    if not os.path.exists(db_file_path):
        print(f"'{DATABASE}' bulunamadı (beklenen yol: {db_file_path}). Veritabanı başlatılıyor...")
        # init_db() bir uygulama bağlamı gerektirir.
        with app.app_context():
            init_db()
            print("Veritabanı başarıyla başlatıldı.")
    else:
        print(f"'{DATABASE}' zaten mevcut (yol: {db_file_path}).")

# Bu satır, Gunicorn modülü ilk yüklediğinde çalışır.
ensure_db_initialized()

# --- Yardımcı Fonksiyonlar ---
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

# Gunicorn bu bloğu çalıştırmayacağı için `if __name__ == '__main__':` bloğunu
# ve içindeki app.run()'ı kaldırabilir veya yorum satırı yapabilirsiniz.
# Yerel geliştirme için tutmak isterseniz, debug modunun False olduğundan emin olun.
# if __name__ == '__main__':
#     # ensure_db_initialized() # Bu zaten modül yüklendiğinde çağrılıyor
#     print("Yerel geliştirme sunucusu başlatılıyor...")
#     app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8080)) ,debug=False) # Render için port ayarı