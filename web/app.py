from flask import Flask
import os

def get_secret(secret_name):
    # 1. Najpierw próbujemy Docker Secrets (plik)
    try:
        with open(f'/run/secrets/{secret_name}', 'r') as file:
            return file.read().strip()
    except IOError:
        # 2. Jak nie ma pliku, szukamy w zmiennych (dla kompatybilności)
        key = os.environ.get(secret_name.upper())
        if key:
            return key
            
    # 3. Jeśli nigdzie nie ma klucza - STOP! Nie uruchamiaj aplikacji
    raise ValueError(f"CRITICAL ERROR: No Secret '{secret_name}'!")


app = Flask(__name__)
app.config['SECRET_KEY'] = get_secret('flask_key_file')

@app.route('/')
def hello():
    return "<h1>Hello World!!!</h1>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)