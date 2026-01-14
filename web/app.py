from flask import Flask

from config import Config
from models import db, User
from crypto_utils import hash_password, verify_password, generate_key_pair
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

app.config.from_object(Config)

db.init_app(app)

csrf = CSRFProtect(app)

with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"Database already exists or another process created it: {e}")

@app.route('/')
def hello():
    return "<h1>Hello World!!!</h1>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)