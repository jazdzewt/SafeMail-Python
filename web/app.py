from flask import Flask
import os

def get_secret(secret_name, default=None):
    # 1. Najpierw próbujemy Docker Secrets (plik)
    try:
        with open(f'/run/secrets/{secret_name}', 'r') as file:
            return file.read().strip()
    except IOError:
        # 2. Jak nie ma pliku, szukamy w zmiennych (dla kompatybilności)
        return os.environ.get(secret_name.upper(), default)


app = Flask(__name__)
app.config['SECRET_KEY'] = get_secret('flask_key_file', 'klucz_zapasowy_dev')

@app.route('/')
def hello():
    return "<h1>Hello World!!!</h1>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)