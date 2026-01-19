import io
import os
import base64
import pyotp
import qrcode
import time
import random
import logging

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort #, make_response
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.middleware.proxy_fix import ProxyFix

from config import Config
from models import db, User, Message, Attachment
from forms import RegistrationForm, LoginForm, MessageForm
from utils import validate_file, validate_uuid
from crypto_utils import hash_password, verify_password, generate_key_pair, encrypt_totp, decrypt_totp, decrypt_private_key, encrypt_aes_gcm, encrypt_rsa, sign_rsa, decrypt_aes_gcm, decrypt_rsa, verify_signature_rsa

app = Flask(__name__)
# Wczytujemy konfigrację z pliku config.py
app.config.from_object(Config)
# Łączymy się z bazą danych
db.init_app(app)
# Włączamy ochronę przed CSRF, przy 'POST' sprawdza czy token CSRF jest poprawny (generuje losowy ciag znakow i podpisuje go FLASK_SECRET_KEY), 
# token znajduję się w ciasteczku oraz w formularzu
csrf = CSRFProtect(app)

# Konfiguracja ProxyFix, aby Flask ufał nagłówkom z Nginxa (X-Forwarded-Proto itp.)
# x_for=1 - bierze ostatni adres z listy i uznaje go za adres klienta
# x_proto=1 - mowi zeby Flask sluchal sie tego https
# x_host=1 - mowi zeby Flask ufał temu co nginx twierdzi ze jest domeną
# x_port=1 - mowi zeby Flask ufał temu co nginx twierdzi ze jest portem
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Tworzymy instancję LoginManagera
login_manager = LoginManager()
# Inicjalizujemy LoginManagera dla aplikacji
login_manager.init_app(app)
# Ustawiamy widok logowania (gdy uzytkownik nie jest zalogowany)
login_manager.login_view = 'login'

# Definiujemy funkcję, ktora mowi flaskowi kto aktualnie jest zalogowany 
# przekazuje id uzytkownika do bazy danych i zwraca obiekt uzytkownika
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
limiter = Limiter(
    # Uzywamy adresu IP klienta
    get_remote_address,
    # Przypisujemy do konkretnej instancji Flaska
    app=app,
    default_limits=["200 per day", "50 per hour"],
    # Domyślnie używamy RAM'u do przechowywania liczników
    storage_uri="memory://"
)
with app.app_context():
    try:
        # SQLAlchemy tworzy tabele w bazie danych
        db.create_all()
    except Exception as e:
        app.logger.warning(f"Baza danych juz istnieje lub inny proces ją stworzył!: {e}")

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("10 per day")
def register():
    form = RegistrationForm()
    
    # Walidujemy formularz (Sprawdzamy czy POST, czy Token CSRF jest poprawny i czy pola spełniają wymogi)
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Sprawdzenie czy użytkownik już istnieje
        if User.query.filter_by(username=username).first():
            flash('Błąd podczas rejestracji!', 'danger')
        else:
            try:
                # Hashowanie hasła
                hashed_pw = hash_password(password)
                
                # Generowanie pary kluczy RSA (klucz prywatny już zaszyfrowany hasłem użytkownika)
                enc_priv_key, pub_key = generate_key_pair(password)

                # Generowanie sekretu TOTP 
                totp_secret = pyotp.random_base32()
                # Szyfrowanie sekretu TOTP hasłem użytkownika
                enc_totp_secret = encrypt_totp(totp_secret, password)
                
                # Zapisujemy do bazy danych nowego użytkownika
                # klucze są w bytes, a w bazie danych są Stringi więc używamy decode('utf-8')
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
                time.sleep(random.uniform(1.0, 2.0))
                return render_template('register_success.html', qr_code=qr_b64, secret=totp_secret)
                
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Błąd podczas rejestracji: {e}")
                flash('Błąd podczas rejestracji!', 'danger')
            
    # Jeśli walidacja nie przeszła, Flask sam wyświetli błędy w HTML
    time.sleep(random.uniform(1.0, 2.0))

    return render_template('register.html', form=form)

@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("15 per hour")
@limiter.limit("60 per day")
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        # Sprawdzamy czy user istnieje
        if user:
            # Sprawdzamy hasło
            if verify_password(user.password_hash, form.password.data):
                
                # Odszyfrowywujemy sekret 2FA hasłem użytkownika
                decrypted_totp_secret = decrypt_totp(bytes.fromhex(user.encrypted_totp_secret), form.password.data)
                
                if decrypted_totp_secret:
                    # Weryfikacja kodu TOTP
                    totp = pyotp.TOTP(decrypted_totp_secret)
                    if totp.verify(form.totp_code.data):
                        # logowanie
                        login_user(user)
                        # Zapisujemy user_id do sesji (ciasteczko)
                        return redirect(url_for('dashboard'))
                    else:
                        flash('Nieprawidłowy kod 2FA.', 'danger')
                else:
                    flash('Błąd 2FA.', 'danger')
            else:
                 flash('Nieprawidłowy login lub hasło.', 'danger')
        else:
             flash('Nieprawidłowy login lub hasło.', 'danger')
        
    time.sleep(random.uniform(1.0, 2.0))
        
    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    # Pobierz wiadomości dla zalogowanego użytkownika
    received_messages = Message.query.filter_by(receiver_id=current_user.id).order_by(Message.timestamp.desc()).all()
    # Pobierz nazwy nadawców
    messages_data = []
    for msg in received_messages:
        sender = User.query.get(msg.sender_id)
        messages_data.append({
            'sender': sender.username if sender else "Nieznany",
            'timestamp': msg.timestamp,
            'id': msg.id,
            'topic': msg.topic,
            'is_read': msg.is_read
        })
    return render_template('dashboard.html', name=current_user.username, messages=messages_data)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('Wylogowano.', 'info')
    return redirect(url_for('login'))

@app.route('/send', methods=['GET', 'POST'])
@login_required
@limiter.limit("2 per minute")
@limiter.limit("15 per hour")
@limiter.limit("50 per day")
def send_message():
    form = MessageForm()
    # Populate the recipient choices dynamically
    users = User.query.all()
    # Exclude current user from choices
    form.recipient.choices = [(u.id, u.username) for u in users if u.id != current_user.id]

    if form.validate_on_submit():
        recipient_ids = form.recipient.data
        if not recipient_ids:
             flash('Musisz wybrać co najmniej jednego odbiorcę.', 'warning')
             return render_template('create_message.html', form=form)


        content = form.content.data.encode('utf-8')
        password = form.password_confirm.data
        
        # 1. Verify password & Unlock Private Key (Sender)
        if not verify_password(current_user.password_hash, password):
             flash('Nieprawidłowe hasło (potrzebne do podpisu).', 'danger')
             return render_template('create_message.html', form=form)
        
        try:
             # Decrypt Sender's Private Key
             sender_priv_key_pem_enc = current_user.encrypted_private_key # stored as text
             
             sender_priv_key_obj = decrypt_private_key(sender_priv_key_pem_enc.encode('utf-8'), password)
             if not sender_priv_key_obj:
                 flash('Błąd dekodowania klucza prywatnego.', 'danger')
                 return render_template('create_message.html', form=form)

             # 2. Prepare Encryption (ONCE for all recipients)
             session_key = os.urandom(32) # 256-bit AES key
             
             # Encrypt Body (AES)
             ciphertext, nonce, tag, session_key = encrypt_aes_gcm(session_key, content)
             
             # Start building sign_data with body parts
             sign_data = nonce + ciphertext + tag

             # Przygotowanie załączników (raz)
             encrypted_attachments = []


             if form.files.data:
                 for file_storage in form.files.data:
                     # Check if file is empty (browser sometimes sends empty field)
                     if file_storage.filename == '':
                         continue
                         
                     clean_filename = validate_file(file_storage)
                     if clean_filename is False:
                          flash(f'Niedozwolone rozszerzenie pliku: {file_storage.filename}', 'danger')
                          return render_template('create_message.html', form=form)
                     
                     if clean_filename:
                          file_bytes = file_storage.read()
                          # Szyfrowanie pliku kluczem sesyjnym
                          att_ciphertext, att_nonce, att_tag, _ = encrypt_aes_gcm(session_key, file_bytes)
                          
                          encrypted_attachments.append({
                              'filename': clean_filename,
                              'blob': att_ciphertext,
                              'nonce': att_nonce,
                              'tag': att_tag
                          })

             # SORTUJEMY załączniki po TAGu (jest identyczny dla każdego odbiorcy), aby kolejność była deterministyczna
             encrypted_attachments.sort(key=lambda x: x['tag'])

             # Append sorted attachment parts to sign_data
             for att in encrypted_attachments:
                 sign_data += att['nonce'] + att['blob'] + att['tag']

             # Sign the Ciphertext (nonce + ciphertext + tag + [att_nonce + att_ciphertext + att_tag]...)
             signature = sign_rsa(sender_priv_key_obj, sign_data)

             # 3. Loop through Recipients and Save Messages
             sent_count = 0
             for r_id in recipient_ids:
                 recipient = User.query.get(r_id)
                 if not recipient:
                     continue

                 recipient_pub_key_pem = recipient.public_key
                 
                 # Encrypt Session Key for THIS Recipient (RSA)
                 enc_key_recipient = encrypt_rsa(recipient_pub_key_pem, session_key)
                 
                 msg = Message(
                     sender_id=current_user.id,
                     receiver_id=recipient.id,
                     topic=form.topic.data,
                     encrypted_body=ciphertext,
                     body_nonce=nonce,                 
                     tag=tag,
                     enc_session_key_recipient=enc_key_recipient,
                     signature=signature
                 )
                 db.session.add(msg)
                 db.session.flush() # To get msg.id if needed
                 
                 # Add attachments
                 for att_data in encrypted_attachments:
                     attachment = Attachment(
                         message_id=msg.id,
                         filename=att_data['filename'],
                         encrypted_blob=att_data['blob'],
                         nonce=att_data['nonce'],
                         tag=att_data['tag']
                     )
                     db.session.add(attachment)
                 
                 sent_count += 1
             
             if sent_count > 0:
                 db.session.commit()
                 flash(f'Wiadomość wysłana do {sent_count} odbiorców!', 'success')
                 return redirect(url_for('dashboard'))
             else:
                 flash('Nie udało się wysłać wiadomości do żadnego odbiorcy.', 'warning')

        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Błąd wysyłania: {e}")
            flash('Błąd wysyłania!', 'danger')
            
    return render_template('create_message.html', form=form)

@app.route('/view_message/<string:message_id>', methods=['GET', 'POST'])
@login_required
def view_message(message_id):

    if not validate_uuid(message_id):
        abort(400)
    
    msg = Message.query.get_or_404(message_id)
    
    # jesli ktos nie jest odbiorca nie widzi strony (błąd 403 http - Forbidden)
    if msg.receiver_id != current_user.id:
         abort(403)

    sender = User.query.get(msg.sender_id)
    sender_name = sender.username if sender else "Nieznany"

    decrypted_body = None
    
    if request.method == 'POST':
        if msg.receiver_id != current_user.id:
             flash('Tylko odbiorca może odszyfrować wiadomość.', 'danger')
        else:
            password = request.form.get('password')
            if not password:
                flash('Podaj hasło.', 'danger')
            else:
                if not verify_password(current_user.password_hash, password):
                    flash('Nieprawidłowe hasło.', 'danger')
                else:
                    try:
                        # Decrypt Private Key
                        priv_key_pem_enc = current_user.encrypted_private_key
                        priv_key_obj = decrypt_private_key(priv_key_pem_enc.encode('utf-8'), password)
                        
                        if not priv_key_obj:
                             flash('Błąd dekodowania klucza prywatnego.', 'danger')
                        else:
                            # Decrypt Session Key (Only Recipient)
                            enc_session_key = msg.enc_session_key_recipient
                                
                            session_key = decrypt_rsa(priv_key_obj, enc_session_key)
                            
                            # Decrypt Body
                            decrypted_body = decrypt_aes_gcm(session_key, msg.encrypted_body, msg.body_nonce, msg.tag).decode('utf-8')
                            
                            # Attachments are accessed via msg.attachments in template

                            # Mark as read if receiver
                            if not msg.is_read:
                                msg.is_read = True
                                db.session.commit()
                                
                    except Exception as e:
                        app.logger.error(f"Błąd deszyfrowania: {e}")
                        flash('Błąd deszyfrowania!', 'danger')

    time.sleep(random.uniform(1.0, 2.0))

    return render_template('view_message.html', msg=msg, sender_name=sender_name, decrypted_body=decrypted_body)

@app.route('/verify_signature/<string:message_id>', methods=['POST'])
@login_required
def verify_signature(message_id):

    if not validate_uuid(message_id):
        abort(400)
    msg = Message.query.get_or_404(message_id)
    
    if msg.receiver_id != current_user.id and msg.sender_id != current_user.id:
         abort(403)

    sender = User.query.get(msg.sender_id)
    if not sender or not msg.signature:
        flash('Brak podpisu lub nadawcy.', 'warning')
        return redirect(url_for('view_message', message_id=message_id))

    try:
        # Reconstruct what was signed: nonce + ciphertext + tag
        signed_data = msg.body_nonce + msg.encrypted_body + msg.tag
        
        # Sort attachments by TAG to ensure same order as signed
        sorted_attachments = sorted(msg.attachments, key=lambda x: x.tag)
        
        for att in sorted_attachments:
            signed_data += att.nonce + att.encrypted_blob + att.tag
        
        is_valid = verify_signature_rsa(sender.public_key, signed_data, msg.signature)
        
        if is_valid:
            flash('Podpis cyfrowy jest POPRAWNY. Wiadomość jest autentyczna.', 'success')
        else:
            flash('Podpis cyfrowy jest NIEPOPRAWNY! Wiadomość mogła zostać zmodyfikowana.', 'danger')
            
    except Exception as e:
         app.logger.error(f"Błąd weryfikacji: {e}")
         flash('Błąd weryfikacji!', 'danger')

    time.sleep(random.uniform(1.0, 2.0))

    return redirect(url_for('view_message', message_id=message_id))

@app.route('/download_attachment/<string:attachment_id>', methods=['POST'])
@login_required
def download_attachment(attachment_id):

    if not validate_uuid(attachment_id):
        abort(400)

    attachment = Attachment.query.get_or_404(attachment_id)

    msg = attachment.message
    
    if msg.receiver_id != current_user.id:
        abort(403)

    password = request.form.get('password')
    if not password:
         flash('Podaj hasło aby pobrać plik.', 'danger')
         return redirect(url_for('view_message', message_id=msg.id))
         
    if not verify_password(current_user.password_hash, password):
        flash('Nieprawidłowe hasło.', 'danger')
        time.sleep(random.uniform(1.0, 2.0))
        return redirect(url_for('view_message', message_id=msg.id))
        
    try:
        priv_key_pem_enc = current_user.encrypted_private_key
        priv_key_obj = decrypt_private_key(priv_key_pem_enc.encode('utf-8'), password)
        
        enc_session_key = msg.enc_session_key_recipient
            
        session_key = decrypt_rsa(priv_key_obj, enc_session_key)
        
        file_bytes = decrypt_aes_gcm(session_key, attachment.encrypted_blob, attachment.nonce, attachment.tag)
        
        time.sleep(random.uniform(1.0, 2.0))
        return send_file(
            io.BytesIO(file_bytes),
            as_attachment=True,
            download_name=attachment.filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        app.logger.error(f"Błąd pobierania: {e}")
        flash('Błąd pobierania!', 'danger')
        return redirect(url_for('view_message', message_id=msg.id))

@app.route('/delete_message/<string:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):

    if not validate_uuid(message_id):
        abort(400)
    msg = Message.query.get_or_404(message_id)
    
    if msg.receiver_id != current_user.id:
        abort(403)
        
    try:
        db.session.delete(msg)
        db.session.commit()
        
        flash('Wiadomość została trwale usunięta.', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Błąd usuwania: {e}")
        flash('Błąd podczas usuwania wiadomości!', 'danger')
        return redirect(url_for('view_message', message_id=message_id))

if __name__ == '__main__':
    # Defaultowo na stdout, level oznacza ze wyswietlaja sie wszystkie powiadomienia o wyzszym priorytecie (aktualnie bez DEBUG)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    app.run(host='0.0.0.0', port=5000)