from flask import Flask, request, g, redirect, render_template, session, url_for
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'dev-secret-key'  # vulnerable: clave fija y corta

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

@app.route('/', methods=['GET','POST'])
def login():
    msg = ''
    if request.method == 'POST':
        username = request.form.get('username','')
        password = request.form.get('password','')
#----------------------------------------------------------------------------------------------------------------------------------
        # VULNERABLE: concatenación directa -> SQL injection
        query = f"SELECT id, username FROM users WHERE username = '{username}' AND password = '{password}'"
        cur = get_db().execute(query)
        user = cur.fetchone()
        cur.close()
        
        # CORREGIDO (NO VULNERABLE):
        # 1. Parametrización -> NO SQL injection
        # 2. Se obtiene el hash de la contraseña
        # query = "SELECT id, username, password FROM users WHERE username = ?"
        # cur = get_db().execute(query, (username,))
        # user = cur.fetchone()
        # cur.close()
#----------------------------------------------------------------------------------------------------------------------------------
#----------------------------------------------------------------------------------------------------------------------------------
        # VULNERABLE:
        if user:
            # VULNERABLE: sesión simple, sin flags de seguridad
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('dashboard'))
        else:
            # VULNERABLE: refleja el username en el mensaje -> XSS posible
            msg = "Login fallido para: " + username

        # CORREGIDO (NO VULNERABLE): Si el usuario existe y el hash coincide
        # if user and check_password_hash(user[2], password):
        #     session['user_id'] = user[0]
        #     session['username'] = user[1]
        #     return redirect(url_for('dashboard'))
        # else:
        #     # Evitar XSS: NO reflejar el nombre de usuario en el mensaje
        #     msg = "Login fallido."
#----------------------------------------------------------------------------------------------------------------------------------
    return render_template('login.html', msg=msg)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # VULNERABLE: muestra el username sin escape consciente (template puede ser vulnerable)
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
#----------------------------------------------------------------------------------------------------------------------------------   
        # VULNERABLE: sin sanitizar ni hash
        query = f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"
        try: 
            get_db().execute(query) 
            get_db().commit() 
            msg = f"Usuario {username} creado correctamente."
        
        # CORREGIDO (NO VULNERABLE): usar hash y parametrización
        # hashed_password = generate_password_hash(password)
        # try:
        #     query = "INSERT INTO users (username, password) VALUES (?, ?)"
        #     get_db().execute(query, (username, hashed_password))
        #     get_db().commit()
        #     msg = f"Usuario {username} creado correctamente."
#----------------------------------------------------------------------------------------------------------------------------------
        except Exception as e:
            msg = "Error: " + str(e)
    return render_template('register.html', msg=msg)

if __name__ == '__main__':
    # Si la BD no existe, crearla a partir de schema.sql
    if not os.path.exists(DATABASE):
        import sqlite3
        with sqlite3.connect(DATABASE) as conn:
            with open('schema.sql', 'r', encoding='utf-8') as f:
                conn.executescript(f.read())
        print("Base de datos creada: vulnapp.db")

#----------------------------------------------------------------------------------------------------------------------------------
    # Vulnerable: HTTP
    app.run(host='0.0.0.0', port=8000, debug=True)
    
    # NO VULNERABLE: HTTPS (con certificados)
    # app.run(host='0.0.0.0', port=5000, debug=True, ssl_context=('cert.pem', 'key.pem'))
#----------------------------------------------------------------------------------------------------------------------------------