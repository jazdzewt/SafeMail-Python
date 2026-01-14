import io
import base64
import pyotp
import qrcode

from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config
from models import db, User
from forms import RegistrationForm, LoginForm
from crypto_utils import hash_password, generate_key_pair, encrypt_data

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
csrf = CSRFProtect(app)
'''
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
'''
with app.app_context():
    try:
        db.create_all()
    except Exception as e:
        print(f"Database already exists or another process created it: {e}")

@app.route('/')
def hello():
    return "<h1>Hello World!!!</h1>"

@app.route('/register', methods=['GET', 'POST'])
#@limiter.limit("10 per day")
def register():
    form = RegistrationForm()
    
    # Ta jedna linijka robi 3 rzeczy:
    # 1. Sprawdza czy to POST.
    # 2. Sprawdza czy TOKEN CSRF jest poprawny (bezpieczeństwo!).
    # 3. Sprawdza czy pola spełniają wymogi (np. długość hasła).
    if form.validate_on_submit():
        # Tu już masz pewność, że dane są bezpieczne i poprawne
        username = form.username.data
        password = form.password.data
        
        # ... (reszta Twojego kodu: sprawdzanie usera, generowanie kluczy RSA) ...
        # np:
        # Sprawdzenie czy użytkownik już istnieje (SQLAlchemy protect against SQL Injection)
        if User.query.filter_by(username=username).first():
            flash('Nazwa użytkownika zajęta.', 'danger')
        else:
            try:
                # Hashowanie hasła
                hashed_pw = hash_password(password)
                
                # Generowanie pary kluczy RSA (szyfrowanie klucza prywatnego hasłem usera)
                enc_priv_key, pub_key = generate_key_pair(password)

                # Generowanie sekretu TOTP (2FA)
                totp_secret = pyotp.random_base32()
                # Szyfrowanie sekretu TOTP hasłem użytkownika
                # Musimy zapisać wersję zaszyfrowaną w bazie (bytes -> hex/string)
                enc_totp_secret = encrypt_data(totp_secret, password)
                
                # Zapis do bazy
                # Ważne: klucze są w bytes, a baza (Text) woli stringi, więc decode('utf-8')
                # enc_totp_secret przekażemy jako hex aby uniknąć problemów z kodowaniem
                new_user = User(
                    username=username,
                    password_hash=hashed_pw,
                    public_key=pub_key.decode('utf-8'),
                    encrypted_private_key=enc_priv_key.decode('utf-8'),
                    encrypted_totp_secret=enc_totp_secret.hex() # Zapisujemy jako hex, bo to raw bytes (salt+token)
                )
                
                db.session.add(new_user)
                db.session.commit()
                
                # Generowanie kodu QR do wyświetlenia
                totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="CyberProject")
                
                qr = qrcode.make(totp_uri)
                buffered = io.BytesIO()
                qr.save(buffered)
                qr_b64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
                
                flash('Konto założone!', 'success')
                
                # Renderujemy stronę sukcesu z kodem QR - NIE PRZEKIEROWUJEMY od razu
                return render_template('register_success.html', qr_code=qr_b64, secret=totp_secret)
                
            except Exception as e:
                db.session.rollback()
                flash(f'Wystąpił błąd podczas rejestracji: {str(e)}', 'danger')
                print(f"Error during registration: {e}")
            
    # Jeśli walidacja nie przeszła, Flask sam wyświetli błędy w HTML
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():  # <--- Ta nazwa 'login' jest kluczowa, jej szuka url_for
    form = LoginForm()
    
    if form.validate_on_submit():
        # Tutaj dodamy logikę sprawdzania hasła za chwilę
        # Na razie niech po prostu wyświetli, że formularz przesłano
        flash('Próba logowania...', 'info')
        
    return render_template('login.html', form=form)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)