from flask import Flask, render_template, request, redirect, url_for, flash, session

from config import Config
from models import db, User
from forms import RegistrationForm, LoginForm
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


@app.route('/register', methods=['GET', 'POST'])
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
                
                # Zapis do bazy
                # Ważne: klucze są w bytes, a baza (Text) woli stringi, więc decode('utf-8')
                new_user = User(
                    username=username,
                    password_hash=hashed_pw,
                    public_key=pub_key.decode('utf-8'),
                    encrypted_private_key=enc_priv_key.decode('utf-8')
                )
                
                db.session.add(new_user)
                db.session.commit()
                
                flash('Konto założone! Możesz się zalogować.', 'success')
                return redirect(url_for('login'))
                
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