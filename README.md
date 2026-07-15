# VulnApp – Entorno vulnerable para estudio de OWASP Top 10

VulnApp es una aplicación web desarrollada con Flask cuyo objetivo es servir como entorno controlado para el estudio y explotación de vulnerabilidades incluidas en el OWASP Top 10 2021.

Este proyecto ha sido diseñado con fines educativos dentro del contexto de un Trabajo de Fin de Grado en Ingeniería Informática, centrado en el análisis de vulnerabilidades web y su mitigación.

## Aviso importante

Esta aplicación contiene vulnerabilidades intencionadas.

No debe desplegarse en entornos de producción ni exponerse a Internet.

## Objetivos del proyecto

- Estudiar vulnerabilidades del OWASP Top 10
- Implementar escenarios reales de ataque en entorno controlado
- Analizar y aplicar mitigaciones de seguridad
- Documentar pruebas de explotación y corrección

## Vulnerabilidades incluidas

- A01 – Broken Access Control
- A02 – Cryptographic Failures
- A03 – Injection
- A04 – Insecure Design
- A06 – Vulnerable and Outdated Components
- A07 – Identification and Authentication Failures
- A09 – Security Logging and Monitoring Failures
- A10 – Server-Side Request Forgery

## Tecnologías utilizadas

- Python 3.x
- Flask
- SQLite
- Requests
- HTML / Bootstrap
- Jinja2
- Qrcode

## Instalación y ejecución

Con el repositorio clonado o descargado realice los siguientes pasos en orden:

- Primero ejecute "python -m venv venv"
- Si está en Linux/Mac ejecute "source venv/bin/activate"
- Si está en Windows ejecute en su lugar "venv\Scripts\activate"
- Ahora ejecute "pip install -r requirements.txt"
- Por último ejecute "python VulnApp.py" con la configuración deseada

La aplicación estará disponible en: http://localhost:8000 o https://localhost:8000

## Usuarios por defecto
NOTA:  Debe tener las variables PASSWORD_HASHING y TWO_FACTOR_AUTHENTICATION = False

admin / admin123                            
user / password

## Modo seguro

La aplicación incluye versiones corregidas de las vulnerabilidades para su comparación y estudio.

## Estructura del proyecto

```
TFG/
│
├── Pruebas/
│ ├── A05_evil.html
│ ├── Ejemplo análisis profesional de CVEs.xlsx
│ ├── MD5_cracker.py
│ └── Prueba_A08_Software and Data Integrity Failures.txt
├── SecLists/
├── static/
│ ├── QRs_users/
│ └── style.css
├── templates/
│ ├── base.html
│ ├── dashboard.html
│ ├── login.html
│ ├── register.html
│ ├── setup2fa.html
│ ├── users.html
│ └── verify2fa.html
├── README.md
├── VulnApp.py
├── cert.pem
├── key.pem
├── manual.txt
├── requirements.txt
├── schema.sql
├── security.log
└── vulnapp.db
```

## Autor

Nombre: Iván Merchán Ruiz

NIA: 100451135

Correo: 100451135@alumnos.uc3m.es