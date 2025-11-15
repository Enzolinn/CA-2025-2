import os
import subprocess
import sys
import venv
from pathlib import Path

# Caminho base
BASE_DIR = Path(__file__).resolve().parent
VENV_DIR = BASE_DIR / "venv"

# 1️⃣ Cria ambiente virtual se não existir
if not VENV_DIR.exists():
    print("📦 Criando ambiente virtual (venv)...")
    venv.create(VENV_DIR, with_pip=True)
else:
    print("✅ Ambiente virtual já existe.")

# Caminho do executável Python dentro do venv
python_exec = VENV_DIR / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

# 2️⃣ Instala dependências do requirements.txt
print("📦 Instalando dependências...")
subprocess.run([str(python_exec), "-m", "pip", "install", "-r", "requirements.txt"], check=True)

# 3️⃣ Executa a API
print("\n🚀 Iniciando API de músicas segura (CTRL+C para parar)...\n")
subprocess.run([str(python_exec), "app.py"])
