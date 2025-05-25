import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import os
import datetime # For timestamps

# Flask application setup
app = Flask(__name__)

# SECRET_KEY: Hardcoded here.
# KESİNLİKLE BU DEĞERİ KENDİ GÜÇLÜ VE RASTGELE ANAHTARINIZLA DEĞİŞTİRİN!
# Terminalde python -c "import os; print(os.urandom(24).hex())" ile üretebilirsiniz.
app.secret_key = 'SizinCokGucluVeTahminEdilemezGizliAnahtarınızBuraya123!@#'

# Database file name
DATABASE = 'database.db'

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    db = getattr(g, '_database', None)
    if db is None:
        db_path = os.path.join(app.root_path, DATABASE)
        db = g._database = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row  # Access columns by name
    return db

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database using schema.sql and adds a default admin user
    if one doesn't exist. This function should be called within an app context.
    """
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

        # Admin credentials are hardcoded here.
        # KENDİ YÖNETİCİ KULLANICI ADINIZI VE GÜÇLÜ ŞİFRENİZİ YAZIN!
        admin_username_to_create = 'admingizli'
        admin_password_for_hash = 'GucluSifre123!@#'

        cursor = db.execute("SELECT id FROM users WHERE username = ?", (admin_username_to_create,))
        admin_exists = cursor.fetchone()

        if not admin_exists:
            admin_password_hash = generate_password_hash(admin_password_for_hash)
            db.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       (admin_username_to_create, admin_password_hash, 'admin'))
            db.commit()
            print(f"Default admin account ('{admin_username_to_create}') created with the hardcoded password.")
        else:
            print(f"Admin account ('{admin_username_to_create}') already exists.")

# --- Helper Functions ---
def is_logged_in():
    return "username" in session

def is_admin():
    return is_logged_in() and session.get("role") == "admin"

def is_misafir():
    return is_logged_in() and session.get("role") == "misafir"

# --- Routes ---
@app.route('/')
def home():
    if not is_logged_in():
        return redirect(url_for('login'))
    if is_admin():
        return redirect(url_for('admin_dashboard'))
    elif is_misafir():
        return redirect(url_for('misafir_dashboard'))
    flash("Unknown role or not logged in.", "danger")
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr
        current_time_dt = datetime.datetime.now()
        current_time_str = current_time_dt.strftime("%Y-%m-%d %H:%M:%S")

        print(f"Login Attempt: Time={current_time_str}, IP={ip_address}, Username='{username}'")

        db = get_db()
        cursor = db.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        login_success = False
        if user and check_password_hash(user["password_hash"], password):
            login_success = True
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash('Giriş başarılı!', 'success')
            print(f"Successful Login: Time={current_time_str}, IP={ip_address}, Username='{username}'")
        else:
            flash('Geçersiz kullanıcı adı veya şifre. Kayıtlı olmayan kullanıcılar giriş yapamaz.', 'danger')
            print(f"Failed Login: Time={current_time_str}, IP={ip_address}, Username='{username}'")

        try:
            db.execute("INSERT INTO login_attempts (timestamp, ip_address, attempted_username, success) VALUES (?, ?, ?, ?)",
                       (current_time_dt, ip_address, username, login_success))
            db.commit()
        except Exception as e:
            print(f"Error logging login attempt to DB: {e}")

        if login_success:
            if user["role"] == "admin":
                return redirect(url_for('admin_dashboard'))
            elif user["role"] == "misafir":
                return redirect(url_for('misafir_dashboard'))
        else:
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
    if request.method == 'POST': # Handles adding new misafir accounts
        misafir_username = request.form.get('misafir_username')
        misafir_password = request.form.get('misafir_password')

        if not misafir_username or not misafir_password:
            flash('Misafir kullanıcı adı ve şifresi boş olamaz.', 'warning')
        else:
            cursor = db.execute("SELECT id FROM users WHERE username = ?", (misafir_username,))
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

    cursor_misafir = db.execute("SELECT id, username, role FROM users WHERE role = 'misafir'")
    misafir_accounts = cursor_misafir.fetchall()

    cursor_attempts = db.execute(
        "SELECT timestamp, ip_address, attempted_username, success FROM login_attempts ORDER BY timestamp DESC LIMIT 20"
    )
    login_attempts_data = cursor_attempts.fetchall()

    return render_template('admin_dashboard.html', misafir_accounts=misafir_accounts, login_attempts=login_attempts_data)

@app.route('/delete_misafir/<string:username_to_delete>', methods=['POST'])
def delete_misafir(username_to_delete):
    if not is_admin():
        flash('Bu işlem için yetkiniz yok.', 'danger')
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.execute("SELECT id FROM users WHERE username = ? AND role = 'misafir'", (username_to_delete,))
    user_to_delete = cursor.fetchone()

    if user_to_delete:
        db.execute("DELETE FROM users WHERE username = ? AND role = 'misafir'", (username_to_delete,))
        db.commit()
        flash(f"'{username_to_delete}' adlı misafir kullanıcı başarıyla silindi.", 'success')
    else:
        flash(f"'{username_to_delete}' adlı misafir kullanıcı bulunamadı veya silme yetkiniz yok.", 'warning')

    return redirect(url_for('admin_dashboard'))

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

# This block is for local development only.
# PythonAnywhere uses a WSGI server and doesn't run this block.
if __name__ == '__main__':
    # For local development, you might want to initialize the DB if it doesn't exist.
    # On PythonAnywhere, you run init_db() manually via the console the first time.
    with app.app_context():
        db_file = os.path.join(app.root_path, DATABASE)
        if not os.path.exists(db_file):
            print("Local database not found, initializing...")
            init_db()
            print("Local database initialized.")
    print("Yerel geliştirme sunucusu başlatılıyor http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
