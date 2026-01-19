FROM python:3.11-slim

WORKDIR /app

# Tworzymy grupę appuser i użytkownika appuser
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Instalacja zależności systemowych
RUN apt-get update && apt-get install -y gcc libffi-dev musl-dev gosu && rm -rf /var/lib/apt/lists/*

# Instalacja bibliotek Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopiowanie kodu aplikacji
COPY . .

# Zmieniamy uprawnienia /app/instance i uruchamiamy gunicorn jako użytkownik appuser
CMD ["sh", "-c", "chown -R appuser:appuser /app/instance && exec gosu appuser gunicorn -w 4 -b 0.0.0.0:5000 app:app"]