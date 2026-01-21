IMPORTANTE: SE CONSIDERA QUE SE ESTÁ TRABAJANDO EN UNA TERMINAL DE POWERSHELL WINDOWS EN VISUAL STUDIO CODE

EJECUCIÓN:
Para iniciar el venv, en la ruta de la carpeta donde está el programa ejecutar:
- "Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force"
- ".\venv\Scripts\Activate.ps1"
Para ejecutar la app hacer "python3 app.py" e ir a la página en el buscador "https://192.168.0.99:8000/" o "http://192.168.0.99:8000/"
Para desactivar el venv ejecutar "deactivate"

NOTAS:
Para instalar los requirements hacer dentro del venv "pip install -r requirements.txt"
