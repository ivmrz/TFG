import sqlite3
import os
import hashlib
import pyotp
import qrcode
import re
import logging
import requests
from flask import Flask, request, g, redirect, render_template, session, url_for, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime
from urllib.parse import urlparse

print("===================================")
print("INICIANDO APLICACIÓN")
print("===================================")

app = Flask(__name__)

# ==================================
# Elegir VulnApp vulnerable o segura
# ==================================
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
    # Permitir intentos de login ilimitados (LOGIN_ATTEMPTS_PROTECTION = False) o limitados (LOGIN_ATTEMPTS_PROTECTION = True)
    LOGIN_ATTEMPTS_PROTECTION = SECURE_MODE
    # Permitir contraseñas inseguras (SPASSWORD_POLICY_PROTECTION = False) o robustas (PASSWORD_POLICY_PROTECTION = True)
    PASSWORD_POLICY_PROTECTION = SECURE_MODE
    # Permitir acceder a cualquier dirección url (SSRF_PROTECTION = False) o no (SSRF_PROTECTION = True)
    SSRF_PROTECTION = SECURE_MODE
    # Lanzar la app con protocolo HTTP (HTTPS_PROTECTION = False) o HTTPS (HTTPS_PROTECTION = True)
    HTTPS_PROTECTION = False

#----------------------------------------------------------------------------------------------------------------------------------
# ESTRUCTURA PARA EL MONITOREO DE INTENTOS INICIO SESIÓN

login_attempts = {}

#----------------------------------------------------------------------------------------------------------------------------------
# MONITOREO DE LOGS

security_logger = logging.getLogger("security")
security_logger.setLevel(logging.WARNING)
handler = logging.FileHandler("security.log")
formatter = logging.Formatter(
    '%(asctime)s - %(levelname)s - %(message)s'
)
handler.setFormatter(formatter)
security_logger.addHandler(handler)

#----------------------------------------------------------------------------------------------------------------------------------
# SECRET KEY CONFIGURATION

if SecurityConfig.SECRET_KEY_PROTECTION:
    # ===================================
    # CORREGIDO: clave aleatoria y segura
    # ===================================
    app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)

else:
    # ==============================
    # VULNERABLE: clave fija y débil
    # ==============================
    app.secret_key = 'dev-secret-key'

#----------------------------------------------------------------------------------------------------------------------------------
# SESSION COOKIE SECURITY

if SecurityConfig.SESSION_COOKIE_PROTECTION:
    # =============================
    # CORREGIDO: cookie inaccesible
    # =============================
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True
    )

else:
    # =================================================
    # VULNERABLE: cookie accesible por JavaScript (XSS)
    # =================================================
    app.config.update(
        SESSION_COOKIE_HTTPONLY=False
    )

#----------------------------------------------------------------------------------------------------------------------------------
# SESSION LIFETIME CONFIGURATION

if SecurityConfig.SESSION_LIFETIME_PROTECTION:
    # ======================================================
    # CORREGIDO: sesión caduca tras 5 minutos de inactividad
    # ======================================================
    app.config.update(
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=5)
    )

else:
    # ================================================
    # VULNERABLE: sesión demasiado larga o persistente
    # ================================================
    app.config.update(
        PERMANENT_SESSION_LIFETIME=timedelta(days=365)
    )

#----------------------------------------------------------------------------------------------------------------------------------
# MÉTODOS PARA GESTIONAR LA BD

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
# ==============================
# Endpoints de la aplicación web
# ==============================

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    msg_type= "info"
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        try:
            # Política de contraseñas
            if SecurityConfig.PASSWORD_POLICY_PROTECTION:
                # ===============================
                # CORREGIDO: Contraseñas robustas
                # ===============================
                if len(password) < 8:
                    raise Exception("La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial.")
                if not re.search(r"[A-Z]", password):
                    raise Exception("La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial.")
                if not re.search(r"[a-z]", password):
                    raise Exception("La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial.")
                if not re.search(r"\d", password):
                    raise Exception("La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial.")
                if not re.search(r"[!@#$%^&*(),.?\"-_:{}|<>]", password):
                    raise Exception("La contraseña debe tener al menos 8 caracteres, una mayúscula, una minúscula, un número y un carácter especial.")
            
            # Comprobar si el nombre de usuario ya existe
            cur = get_db().execute(
                "SELECT 1 FROM users WHERE username = ?",
                (username,)
            )
            if cur.fetchone():
                cur.close()
                msg = "Nombre de usuario no disponible."
                msg_type = "danger"
                return render_template("register.html", msg=msg, msg_type=msg_type)
            cur.close()

            # Almacenamiento de contraseñas
            if not SecurityConfig.PASSWORD_HASHING:
                # =======================
                # VULNERABLE: Texto plano
                # =======================
                stored_password = password
            elif SecurityConfig.CRYPTO_PROTECTION:
                # ==========================
                # CORREGIDO: Werkzeug scrypt
                # ==========================
                stored_password = generate_password_hash(password)
            else:
                # ===============
                # VULNERABLE: MD5
                # ===============
                stored_password = hashlib.md5(password.encode()).hexdigest()
            
            # 2 Factor Authentication
            if SecurityConfig.TWO_FACTOR_AUTHENTICATION:
                # ===========================================
                # CORREGIDO: Se genera el secreto para el 2FA
                # ===========================================
                otp_secret = pyotp.random_base32()
            else:
                # ==============================================
                # VULNERABLE: No hay otp_secret -> no existe 2FA
                # ==============================================
                otp_secret = None

            # Consulta para añadir usuario, contraseña y otp_secret a la Base de Datos
            if not SecurityConfig.SQL_INJECTION_PROTECTION:
                # =================================
                # VULNERABLE: Posible SQL INJECTION
                # =================================
                query = f"INSERT INTO users (username, password, otp_secret) VALUES ('{username}', '{stored_password}', '{otp_secret}')"
                get_db().execute(query)
            else:
                # ====================================
                # CORREGIDO: Aplicando parametrización
                # ====================================
                query = "INSERT INTO users (username, password, otp_secret) VALUES (?, ?, ?)"
                get_db().execute(query, (username, stored_password, otp_secret))

            get_db().commit()

            # 2 Factor Authentication
            if SecurityConfig.TWO_FACTOR_AUTHENTICATION:
                uri = pyotp.TOTP(otp_secret).provisioning_uri(
                    name=username,
                    issuer_name="VulnApp"
                )
                img = qrcode.make(uri)
                qr_folder = os.path.join(app.static_folder, "QRs_users")
                os.makedirs(qr_folder, exist_ok=True)
                img.save(os.path.join(qr_folder, f"{username}_qr.png"))
                # Redirige al usuario a la pestaña con su QR personal para activar 2FA
                return render_template("setup2fa.html", username=username, qr=f"QRs_users/{username}_qr.png")
            
            msg = f"Usuario {username} creado correctamente."
            msg_type = "success"

        except Exception as e:
            msg = str(e)
            msg_type = "danger"
    return render_template('register.html', msg=msg, msg_type=msg_type)

@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        try:
            # Control de intentos para inicio de sesión por usuario
            if SecurityConfig.LOGIN_ATTEMPTS_PROTECTION:
                # ==================================================
                # CORREGIDO: Límite de intentos de inicio de sesión
                # ==================================================
                if username in login_attempts:
                    attempts, blocked_until = login_attempts[username]
                    if blocked_until and datetime.now() < blocked_until:
                        remaining = int((blocked_until - datetime.now()).total_seconds())
                        msg = f"Cuenta bloqueada. Inténtelo de nuevo en {remaining} segundos."
                        return render_template("login.html", msg=msg)
                    if blocked_until and datetime.now() >= blocked_until:
                        # Reinicia el contador de intentos para el usuario
                        login_attempts.pop(username, None)

            # Consulta para comprobar el login del usuario
            if not SecurityConfig.SQL_INJECTION_PROTECTION:     # Si SQL_INJECTION_PROTECTION = False, usuarios con hashing no funcionan
                # =================================
                # VULNERABLE: Posible SQL INJECTION
                # =================================
                query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
                cur = get_db().execute(query)
            else:
                # ====================================
                # CORREGIDO: Aplicando parametrización
                # ====================================
                if not SecurityConfig.PASSWORD_HASHING:
                    query = "SELECT id, username FROM users WHERE username = ? AND password = ?"
                    cur = get_db().execute(query, (username, password))
                else:
                    query = "SELECT id, username, password FROM users WHERE username = ?"
                    cur = get_db().execute(query, (username,))
            user = cur.fetchone()
            cur.close()

            # Comprobación de la contraseña introducida para la autenticación
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

            # Login correcto en la aplicación
            if authenticated:
                # Si LOGIN_ATTEMPTS_PROTECTION está activado
                if SecurityConfig.LOGIN_ATTEMPTS_PROTECTION:
                    # Reinicia el contador de intentos para el usuario
                    login_attempts.pop(username, None)

                # Si 2FA está activado
                if SecurityConfig.TWO_FACTOR_AUTHENTICATION:
                    session["pending_user"] = user[0]
                    session["username"] = user[1]
                    # Se redirige al panel de verificación 2FA
                    return redirect(url_for("verify_2fa"))
                # Si 2FA no está activado
                else:
                    session.permanent = True                    # Pone en funcionamiento el lifetime de la sesión
                    session['user_id'] = user[0]
                    session['username'] = user[1]
                    # Se redirige al dashboard
                    return redirect(url_for('dashboard'))
            
            # Login incorrecto en la aplicación
            else:
                # Si LOGIN_ATTEMPTS_PROTECTION está activado
                if SecurityConfig.LOGIN_ATTEMPTS_PROTECTION:
                    # Se suma +1 al número de intentos del usuario
                    attempts, blocked_until = login_attempts.get(username, (0, None))
                    attempts += 1
                    # Si los intentos superan 5, se bloquea el login durante 5 minutos para ese usuario
                    if attempts >= 5:
                        blocked_until = datetime.now() + timedelta(minutes=5)
                        # Se registra el warning en el archivo de logs
                        security_logger.warning(
                            f"[A07 DETECTADO] Cuenta '{username}' bloqueada tras 5 intentos fallidos desde la IP {request.remote_addr}"
                        )
                        msg = "Demasiados intentos. Cuenta bloqueada durante 5 minutos."
                    # Si no los supera, se indica cuántos lleva realizados
                    else:
                        msg = f"Login fallido. Intento {attempts}/5"
                    login_attempts[username] = (attempts, blocked_until)
                # Si LOGIN_ATTEMPTS_PROTECTION no está activado
                else:   
                    if SecurityConfig.LOGIN_MESSAGE_PROTECTION:
                        # =====================================================
                        # CORREGIDO: No se muestra ninguna información sensible
                        # =====================================================
                        msg = "Login fallido."
                    else:
                        # ======================================
                        # VULNERABLE: Refleja datos introducidos
                        # ======================================
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
    if not SecurityConfig.FILE_ACCESS_PROTECTION:
        # ===================================================================================================
        # VULNERABLE: Permite descargar cualquier archivo sin autenticación, validación o restricción de ruta
        # ===================================================================================================
        filename = request.args.get('name', '')
        return send_file(filename, as_attachment=True)

    # ========================================================================
    # CORREGIDO: Solo permite descargar manual.txt y se requiere autenticación
    # ========================================================================
    if 'user_id' not in session:
        return redirect(url_for('login'))
    filename = request.args.get('name', '')

    # Lista blanca de archivos permitidos
    allowed_files = {'manual.txt': os.path.join(os.path.dirname(__file__), 'manual.txt')}
    # Si se intenta acceder a un archivo no deseado, se registra el warning en el archivo de logs
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
    # Genera la página con la tabla de usuarios de la BD
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
        # Código introducido por el usuario
        code = request.form["code"]
        # Obtiene el secreto asociado al usuario de la BD
        cur = get_db().execute(
            "SELECT otp_secret FROM users WHERE id=?",
            (session["pending_user"],)
        )
        secret = cur.fetchone()[0]
        cur.close()
        # Si no hay un secreto configurado para el usuario, se devuelve error
        if not secret:
            abort(404)
        # Crea el objeto que representa el autenticador TOTP asociado al secreto del usuario 
        totp = pyotp.TOTP(secret)
        # Verifica si el código del usuario es válido
        if totp.verify(code):
            # Inicia la sesión correctamente
            session["user_id"] = session["pending_user"]
            session.pop("pending_user")
            session.permanent = True                            # Pone en funcionamiento el lifetime de la sesión
            return redirect(url_for("dashboard"))
        msg = "Código de autenticación incorrecto"
    return render_template("verify2fa.html", msg=msg)

@app.route('/fetch')
def fetch():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    url = request.args.get('url', '')

    if not SecurityConfig.SSRF_PROTECTION:
        # ================================================================
        # VULNERABLE: Permite acceder a cualquier URL (Incluido localhost)
        # ================================================================
        response = requests.get(url)
        return response.text

    # ==========================================
    # CORREGIDO: Bloquea algunos hosts sensibles
    # ==========================================
    parsed = urlparse(url)
    blocked_hosts = [
        "127.0.0.1",
        "localhost"
    ]
    # Si se intenta acceder con un host no deseado, se registra el warning en el archivo de logs
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
    <p>Admin token: dev-secret-key</p>
    """

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

#----------------------------------------------------------------------------------------------------------------------------------
# ==============
# Main de la app
# ==============

if __name__ == '__main__':
    # Crear la BD si no existe a partir de schema.sql
    if not os.path.exists(DATABASE):
        with sqlite3.connect(DATABASE) as conn:
            with open('schema.sql', 'r', encoding='utf-8') as f:
                conn.executescript(f.read())
        print("Base de datos creada: vulnapp.db")
    # Lanza la web con HTTP o HTTPS
    if not SecurityConfig.HTTPS_PROTECTION:
        # ==========================
        # VULNERABLE: Protocolo HTTP
        # ==========================
        print("[MODO VULNERABLE] Aplicación ejecutándose en HTTP")
        app.run(host='0.0.0.0', port=8000, debug=True)

    else:
        # ===========================================
        # CORREGIDO: Protocolo HTTPS con certificados
        # ===========================================
        print("[MODO SEGURO] Aplicación ejecutándose en HTTPS")
        app.run(host='0.0.0.0', port=8000, debug=True, ssl_context=('cert.pem', 'key.pem'))

#----------------------------------------------------------------------------------------------------------------------------------