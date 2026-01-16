import io
import os
import base64
import pyotp
import qrcode

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, abort, make_response
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

from config import Config
from models import db, User, Message, Attachment
from forms import RegistrationForm, LoginForm, MessageForm
from utils import validate_file
from crypto_utils import hash_password, verify_password, generate_key_pair, encrypt_totp, decrypt_totp, decrypt_private_key, encrypt_aes_gcm, encrypt_rsa, sign_rsa, decrypt_aes_gcm, decrypt_rsa, verify_signature_rsa

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
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

# Do usuniecia!!!!!!!!!!!!!!
@app.route('/')
def hello():
    return "<h1>Hello World!!!</h1>"

@app.route('/register', methods=['GET', 'POST'])
#@limiter.limit("5 per day")
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
                enc_totp_secret = encrypt_totp(totp_secret, password)
                
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
                flash(f'Wystąpił błąd podczas rejestracji.', 'danger')
                print(f"Error during registration: {e}")
            
    # Jeśli walidacja nie przeszła, Flask sam wyświetli błędy w HTML
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        # 1. Weryfikacja czy user istnieje
        if user:
            # 2. Weryfikacja hasła (Argon2)
            if verify_password(user.password_hash, form.password.data):
                
                # 3. Odszyfrowanie sekretu 2FA hasłem użytkownika
                decrypted_totp_secret = decrypt_totp(bytes.fromhex(user.encrypted_totp_secret), form.password.data)
                
                if decrypted_totp_secret:
                    # 4. Weryfikacja kodu TOTP
                    totp = pyotp.TOTP(decrypted_totp_secret)
                    if totp.verify(form.totp_code.data):
                        # SUKCES - Logowanie
                        login_user(user)
                        #flash('Zalogowano pomyślnie!', 'success')
                        return redirect(url_for('dashboard'))
                    else:
                        flash('Nieprawidłowy kod 2FA.', 'danger')
                else:
                    flash('Błąd 2FA.', 'danger')
            else:
                 flash('Nieprawidłowy login lub hasło.', 'danger')
        else:
             flash('Nieprawidłowy login lub hasło.', 'danger')
        
    return render_template('login.html', form=form)

# ==============================================================================
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
# ==============================================================================

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Wylogowano.', 'info')
    return redirect(url_for('login'))

# ==============================================================================

@app.route('/send', methods=['GET', 'POST'])
@login_required
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
                         nonce=att_data['nonce'], # nonces are reused here which is fine as encryption is same.
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
            flash(f'Błąd wysyłania! {e}', 'danger')
            print(f"Error sending message: {e}")
            db.session.rollback()
            
    return render_template('create_message.html', form=form)

# ==============================================================================

@app.route('/view_message/<string:message_id>', methods=['GET', 'POST'])
@login_required
def view_message(message_id):
    msg = Message.query.get_or_404(message_id)
    
    if msg.receiver_id != current_user.id:
         # Sender can view the page but NOT decrypt the content
         abort(403)

    sender = User.query.get(msg.sender_id)
    sender_name = sender.username if sender else "Nieznany"
    
    verification_status = None
    # Auto-verification removed as per user request.
    # Verification is now manual via /verify_signature/...

    decrypted_body = None
    #decrypted_file_name = None
    
    if request.method == 'POST':
        # Only receiver can decrypt
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
                        flash(f'Błąd deszyfrowania: {e}', 'danger')

    return render_template('view_message.html', msg=msg, sender_name=sender_name, decrypted_body=decrypted_body, verification_status=verification_status)

@app.route('/verify_signature/<string:message_id>', methods=['POST'])
@login_required
def verify_signature(message_id):
    msg = Message.query.get_or_404(message_id)
    
    if msg.receiver_id != current_user.id and msg.sender_id != current_user.id:
         abort(403)

    sender = User.query.get(msg.sender_id)
    if not sender or not msg.signature:
        flash('Brak podpisu lub nadawcy.', 'warning')
        return redirect(url_for('view_message', message_id=message_id))

    try:
        # Reconstruct what was signed: nonce + ciphertext + tag
        sign_data = msg.body_nonce + msg.encrypted_body + msg.tag
        
        # Sort attachments by TAG to ensure same order as signed
        sorted_attachments = sorted(msg.attachments, key=lambda x: x.tag)
        
        for att in sorted_attachments:
            sign_data += att.nonce + att.encrypted_blob + att.tag
        
        is_valid = verify_signature_rsa(sender.public_key, sign_data, msg.signature)
        
        if is_valid:
            flash('Podpis cyfrowy jest POPRAWNY. Wiadomość jest autentyczna.', 'success')
        else:
            flash('Podpis cyfrowy jest NIEPOPRAWNY! Wiadomość mogła zostać zmodyfikowana.', 'danger')
            
    except Exception as e:
         print(f"Verification error: {e}")
         flash(f'Błąd weryfikacji: {e}', 'danger')

    return redirect(url_for('view_message', message_id=message_id))

@app.route('/download_attachment/<string:attachment_id>', methods=['POST'])
@login_required
def download_attachment(attachment_id):
    attachment = Attachment.query.get_or_404(attachment_id)
    msg = attachment.message # relation defined in models
    
    if msg.receiver_id != current_user.id:
        abort(403)

    password = request.form.get('password')
    if not password:
         flash('Podaj hasło aby pobrać plik.', 'danger')
         return redirect(url_for('view_message', message_id=msg.id))
         
    if not verify_password(current_user.password_hash, password):
        flash('Nieprawidłowe hasło.', 'danger')
        return redirect(url_for('view_message', message_id=msg.id))
        
    try:
        priv_key_pem_enc = current_user.encrypted_private_key
        priv_key_obj = decrypt_private_key(priv_key_pem_enc.encode('utf-8'), password)
        
        # Only receiver can download
        enc_session_key = msg.enc_session_key_recipient
            
        session_key = decrypt_rsa(priv_key_obj, enc_session_key)
        
        file_bytes = decrypt_aes_gcm(session_key, attachment.encrypted_blob, attachment.nonce, attachment.tag)
        
        return send_file(
            io.BytesIO(file_bytes),
            as_attachment=True,
            download_name=attachment.filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        flash(f'Błąd pobierania: {e}', 'danger')
        return redirect(url_for('view_message', message_id=msg.id))

@app.route('/delete_message/<string:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    msg = Message.query.get_or_404(message_id)
    
    # Security check: Only the receiver can delete (and read)
    if msg.receiver_id != current_user.id:
        abort(403)
        
    try:
        # Manually delete attachments first (safer if no cascade is set)
        for att in msg.attachments:
            db.session.delete(att)
            
        # Delete the message itself
        db.session.delete(msg)
        db.session.commit()
        
        flash('Wiadomość została trwale usunięta.', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        db.session.rollback()
        flash(f'Błąd podczas usuwania wiadomości: {e}', 'danger')
        return redirect(url_for('view_message', message_id=message_id))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)