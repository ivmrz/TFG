import hashlib
from pathlib import Path

rockyou = Path.home() / "Escritorio" / "rockyou.txt"

target = "1bc29b36f623ba82aaf6724fd3b16718"

with open(rockyou, "r", encoding="latin-1") as f:
    for line in f:
        word = line.strip()
        if hashlib.md5(word.encode()).hexdigest() == target:
            print("Password encontrada:", word)
            break