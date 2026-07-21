import sqlite3
import os
import hashlib
import pyotp
import qrcode
import logging
import requests
from flask import Flask, request, g, redirect, render_template, session, url_for, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from urllib.parse import urlparse

app = Flask(__name__)

# ==================================================
# Elegir App vulnerable o segura
# ==================================================
class SecurityConfig:
    # Modo general seguro (SECURE_MODE = True) o vulnerable (SECURE_MODE = False)
    SECURE_MODE = True
    # Establecer una secret key estática (SECRET_KEY_PROTECTION = False) o dinámica (SECRET_KEY_PROTECTION = True)
    SECRET_KEY_PROTECTION = False
    # Permitir acceder a la cookie de sesión por JS (SESSION_COOKIE_PROTECTION = False) o no (SESSION_COOKIE_PROTECTION = True)
    SESSION_COOKIE_PROTECTION = False
    # Establecer que la sesión sea casi permanente (SESSION_LIFETIME_PROTECTION = False) o no (SESSION_LIFETIME_PROTECTION = True)
    SESSION_LIFETIME_PROTECTION = SECURE_MODE
    # Usar contraseñas en texto plano (PASSWORD_HASHING = False) o hasheadas con scrypt (PASSWORD_HASHING = True y CRYPTO_PROTECTION = True)
    PASSWORD_HASHING = False
    # Usar contraseñas sin salt (CRYPTO_PROTECTION = False y PASSWORD_HASHING = True) o hasheadas con scrypt (CRYPTO_PROTECTION = True y PASSWORD_HASHING = True)
    CRYPTO_PROTECTION = SECURE_MODE
    # Permitir SQL_Injection (SQL_INJECTION_PROTECTION = False) o no (SQL_INJECTION_PROTECTION = True)
    SQL_INJECTION_PROTECTION = SECURE_MODE
    # Mensaje de login inseguro (LOGIN_MESSAGE_PROTECTION = False) o seguro (LOGIN_MESSAGE_PROTECTION = True) cuando se falle
    LOGIN_MESSAGE_PROTECTION = SECURE_MODE
    # Permitir descargar cualquier archivo (FILE_ACCESS_PROTECTION = False) o no (FILE_ACCESS_PROTECTION = True)
    FILE_ACCESS_PROTECTION = SECURE_MODE
    # Permitir acceso sin 2FA (TWO_FACTOR_AUTHENTICATION = False) o con 2FA (TWO_FACTOR_AUTHENTICATION = True)
    TWO_FACTOR_AUTHENTICATION = False
    # Permitir acceder a cualquier dirección url (SSRF_PROTECTION = False) o no (SSRF_PROTECTION = True)
    SSRF_PROTECTION = SECURE_MODE
    # Lanzar la app con protocolo HTTP (HTTPS_PROTECTION = False) o HTTPS (HTTPS_PROTECTION = True)
    HTTPS_PROTECTION = False

# ==================================================
# Monitoreo de logs
# ==================================================
security_logger = logging.getLogger("security")
security_logger.setLevel(logging.WARNING)
handler = logging.FileHandler("security.log")
formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)
security_logger.addHandler(handler)

# ==================================================
# SECRET KEY CONFIGURATION
# ==================================================
if SecurityConfig.SECRET_KEY_PROTECTION:
    # CORREGIDO: clave aleatoria y segura
    app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)

else:
    # VULNERABLE: clave fija y débil
    app.secret_key = 'dev-secret-key'

# ==================================================
# SESSION COOKIE SECURITY
# ==================================================
if SecurityConfig.SESSION_COOKIE_PROTECTION:
    # CORREGIDO: cookie inaccesible
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True
    )

else:
    # VULNERABLE: cookie accesible por JavaScript (XSS)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=False
    )

# ==================================================
# SESSION LIFETIME CONFIGURATION
# ==================================================
if SecurityConfig.SESSION_LIFETIME_PROTECTION:
    # CORREGIDO: sesión caduca tras 5 minutos de inactividad
    app.config.update(
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=5)
    )

else:
    # VULNERABLE: sesión demasiado larga o persistente
    app.config.update(
        PERMANENT_SESSION_LIFETIME=timedelta(days=365)
    )

# ==================================================
# Métodos para gestionar la BD
# ==================================================
DATABASE = os.path.join(os.path.dirname(__file__), 'vulnapp.db')

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

#----------------------------------------------------------------------------------------------------------------------------------
# ==================================================
# Endpoints de la aplicación web
# ==================================================

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        try:
            if not SecurityConfig.PASSWORD_HASHING:
                # Texto plano
                stored_password = password
            elif SecurityConfig.CRYPTO_PROTECTION:
                # Werkzeug scrypt
                stored_password = generate_password_hash(password)
            else:
                # MD5
                stored_password = hashlib.md5(password.encode()).hexdigest()
            
            if SecurityConfig.TWO_FACTOR_AUTHENTICATION:
                # Se genera el secreto para el 2FA
                otp_secret = pyotp.random_base32()
            else:
                otp_secret = None

            # ==============================
            # VULNERABLE: Posible SQL INJECTION
            # ==============================
            if not SecurityConfig.SQL_INJECTION_PROTECTION:
                query = f"INSERT INTO users (username, password, otp_secret) VALUES ('{username}', '{stored_password}', '{otp_secret}')"
                get_db().execute(query)

            # ==============================
            # CORREGIDO: Aplicando parametrización
            # ==============================
            else:
                query = "INSERT INTO users (username, password, otp_secret) VALUES (?, ?, ?)"
                get_db().execute(query, (username, stored_password, otp_secret))

            get_db().commit()

            if SecurityConfig.TWO_FACTOR_AUTHENTICATION:
                uri = pyotp.TOTP(otp_secret).provisioning_uri(
                    name=username,
                    issuer_name="VulnApp"
                )
                img = qrcode.make(uri)
                qr_folder = os.path.join(app.static_folder, "QRs_users")
                os.makedirs(qr_folder, exist_ok=True)
                img.save(os.path.join(qr_folder, f"{username}_qr.png"))
                return render_template("setup2fa.html", username=username, qr=f"QRs_users/{username}_qr.png")
            
            msg = f"Usuario {username} creado correctamente."

        except Exception as e:
            msg = "Error: " + str(e)
    return render_template('register.html', msg=msg)

@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        try:
            # ==================================================
            # VULNERABLE: Posible SQL INJECTION
            # ==================================================
            if not SecurityConfig.SQL_INJECTION_PROTECTION:         # Si SQL_INJECTION_PROTECTION = False, usuarios con hashing no funcionan
                # Consulta vulnerable
                query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
                cur = get_db().execute(query)

            # ==================================================
            # CORREGIDO: Aplicando parametrización
            # ==================================================
            else:
                # Consulta segura
                if not SecurityConfig.PASSWORD_HASHING:
                    query = "SELECT id, username FROM users WHERE username = ? AND password = ?"
                    cur = get_db().execute(query, (username, password))
                else:
                    query = "SELECT id, username, password FROM users WHERE username = ?"
                    cur = get_db().execute(query, (username,))
            user = cur.fetchone()
            cur.close()

            # ==================================================
            # AUTENTICACIÓN: Con o sin aplicar Hashing
            # ==================================================
            authenticated = False

            if not SecurityConfig.PASSWORD_HASHING or not SecurityConfig.SQL_INJECTION_PROTECTION:
                # Texto plano
                if user:
                    authenticated = True
            elif SecurityConfig.CRYPTO_PROTECTION:
                # Werkzeug scrypt
                if user and check_password_hash(user[2], password):
                    authenticated = True
            else:
                # MD5
                hashed = hashlib.md5(password.encode()).hexdigest()
                if user and user[2] == hashed:
                    authenticated = True

            # ==================================================
            # LOGIN CORRECTO
            # ==================================================
            if authenticated:
                if SecurityConfig.TWO_FACTOR_AUTHENTICATION:
                    session["pending_user"] = user[0]
                    session["username"] = user[1]
                    return redirect(url_for("verify_2fa"))
                else:
                    session.permanent = True                    # Pone en funcionamiento el lifetime de la sesión
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    return redirect(url_for('dashboard'))
            
            # ==================================================
            # LOGIN INCORRECTO
            # ==================================================
            else:
                if SecurityConfig.LOGIN_MESSAGE_PROTECTION:
                    msg = "Login fallido."
                else:
                    # Vulnerable: refleja datos introducidos
                    msg = "Login fallido para: " + username

        except Exception as e:
            msg = "Error: " + str(e)
    return render_template('login.html', msg=msg)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        session.clear()
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/file')
def file():
    # ==================================================
    # VULNERABLE: Permite descargar cualquier archivo y sin autenticación
    # ==================================================
    if not SecurityConfig.FILE_ACCESS_PROTECTION:
        filename = request.args.get('name', '')
        # Sin autenticación
        # Sin validación
        # Sin restricciones de ruta
        return send_file(filename, as_attachment=True)

    # ==================================================
    # CORREGIDO: Solo permite descargar manual.txt y se requiere autenticación
    # ==================================================
    # Requerir autenticación
    if 'user_id' not in session:
        return redirect(url_for('login'))
    filename = request.args.get('name', '')

    # Lista blanca de archivos permitidos
    allowed_files = {'manual.txt': os.path.join(os.path.dirname(__file__), 'manual.txt')}
    if filename not in allowed_files:
        security_logger.warning(
            f"[A01 DETECTADO] Intento de acceso no autorizado "
            f"al archivo '{filename}' desde IP {request.remote_addr}"
        )
        abort(403)

    return send_file(allowed_files[filename], as_attachment=True)

@app.route('/users')
def users():
    if 'user_id' not in session:
        session.clear()
        return redirect(url_for('login'))
    cur = get_db().execute("SELECT id, username FROM users")
    users = cur.fetchall()
    cur.close()
    return render_template('users.html', users=users)

@app.route("/verify-2fa", methods=["GET","POST"])
def verify_2fa():
    if "pending_user" not in session:
        return redirect(url_for("login"))
    msg = ""
    if request.method == "POST":
        code = request.form["code"]
        cur = get_db().execute(
            "SELECT otp_secret FROM users WHERE id=?",
            (session["pending_user"],)
        )
        secret = cur.fetchone()[0]
        cur.close()
        if not secret:
            abort(404)
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            session["user_id"] = session["pending_user"]
            session.pop("pending_user")
            session.permanent = True
            return redirect(url_for("dashboard"))
        msg = "Código de autenticación incorrecto"
    return render_template("verify2fa.html", msg=msg)

@app.route('/fetch')
def fetch():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    url = request.args.get('url', '')

    # ==================================================
    # VULNERABLE: Permite acceder a cualquier URL (Incluido localhost)
    # ==================================================
    if not SecurityConfig.SSRF_PROTECTION:
        response = requests.get(url)
        return response.text

    # ==================================================
    # CORREGIDO: Bloquea algunos hosts sensibles
    # ==================================================
    parsed = urlparse(url)
    blocked_hosts = [
        "127.0.0.1",
        "localhost"
    ]
    if parsed.hostname in blocked_hosts:
        security_logger.warning(
            f"[A10 DETECTADO] Intento de SSRF hacia "
            f"'{parsed.hostname}' desde IP {request.remote_addr}"
        )
        abort(403)

    response = requests.get(url, timeout=5)
    return response.text

@app.route('/internal')
def internal():
    # Solo accesible desde localhost
    if request.remote_addr != '127.0.0.1':
        abort(403)
    return """
    <h2>Panel interno</h2>
    <p>Backup database: vulnapp.db</p>
    <p>Admin token: SECRET-ADMIN-KEY</p>
    """

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

#----------------------------------------------------------------------------------------------------------------------------------
# ==================================================
# Main de la app
# ==================================================
if __name__ == '__main__':
    # Crear la BD si no existe a partir de schema.sql
    if not os.path.exists(DATABASE):
        with sqlite3.connect(DATABASE) as conn:
            with open('schema.sql', 'r', encoding='utf-8') as f:
                conn.executescript(f.read())
        print("Base de datos creada: vulnapp.db")

    # ==================================================
    # VULNERABLE: Protocolo HTTP
    # ==================================================
    if not SecurityConfig.HTTPS_PROTECTION:
        print("[MODO VULNERABLE] Aplicación ejecutándose en HTTP")
        app.run(host='0.0.0.0', port=8000, debug=True)

    # ==================================================
    # CORREGIDO: Protocolo HTTPS con certificados
    # ==================================================
    else:
        print("[MODO SEGURO] Aplicación ejecutándose en HTTPS")
        app.run(host='0.0.0.0', port=8000, debug=True, ssl_context=('cert.pem', 'key.pem'))