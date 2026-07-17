import requests

url = "http://127.0.0.1:8000"
#url = "https://127.0.0.1:8000"

print("Comenzando sobrecarga.")
for i in range(1000):
    requests.post(
        url,
        data={
            "username": "admin",
            "password": f"pass{i}"
        }
    )
print("Sobrecarga finalizada.")