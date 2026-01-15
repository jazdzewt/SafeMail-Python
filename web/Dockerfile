FROM python:3.11-slim

WORKDIR /app

# Tworzymy grupę 'appuser' i użytkownika 'appuser'
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Instalacja zależności systemowych (potrzebne dla kryptografii)
RUN apt-get update && apt-get install -y gcc libffi-dev musl-dev gosu && rm -rf /var/lib/apt/lists/*

# Instalacja bibliotek Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopiowanie kodu aplikacji
COPY . .

# 3. Zamiast skryptu entrypoint używamy polecenia w jednej linii
# Najpierw naprawiamy uprawnienia (jako root), potem przełączamy użytkownika (gosu) i uruchamiamy serwer

#CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
CMD ["sh", "-c", "mkdir -p /app/instance && chown -R appuser:appuser /app/instance && exec gosu appuser gunicorn -w 4 -b 0.0.0.0:5000 app:app"]