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

## Instalación y ejecución

Con el repositorio clonado o descargado:

- python -m venv venv
- source venv/bin/activate   # Linux/Mac
- venv\Scripts\activate      # Windows
- pip install -r requirements.txt
- python VulnApp.py

La aplicación estará disponible en: http://localhost:8000 o https://localhost:8000

## Usuarios por defecto

admin / admin123

user / password

## Modo seguro

La aplicación incluye versiones corregidas de las vulnerabilidades para su comparación y estudio.

## Estructura del proyecto

TFG/

│

├── SecLists/

├── static/

    ├── style.css

├── templates/

    ├── base.html

    ├── dashboard.html

    ├── login.html

    ├── register.html

    ├── users.html

├── README.md

├── VulnApp.py

├── cert.pem

├── key.pem

├── manual.txt

├── requirements.txt

├── schema.sql

├── security.log

└── vulnapp.db

## Autor

Nombre: Iván Merchán Ruiz

NIA: 100451135

Correo: 100451135@alumnos.uc3m.es