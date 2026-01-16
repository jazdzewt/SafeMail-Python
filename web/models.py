import uuid  # <--- Dodaj ten import na samej górze
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from sqlalchemy.orm import deferred

db = SQLAlchemy()

# Dziedziczy po 2 klasach
class User(UserMixin, db.Model):
    # Zmieniamy Integer na String(36)
    # default=... generuje losowe UUID przy tworzeniu nowego usera
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    # ten uuid4 zapewnia w pełni losowy identyfikator nie tajk jak pozostale
    
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    encrypted_private_key = db.Column(db.Text, nullable=False)
    encrypted_totp_secret = db.Column(db.String(300), nullable=True) # Zwiększamy length dla encrypted data

class Message(db.Model):
    #id = db.Column(db.Integer, primary_key=True)
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    topic = db.Column(db.String(150), nullable=False)
    sender_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.String(36), db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    # --- WARSTWA 1: TREŚĆ (Szyfrowanie Symetryczne AES) ---
    # Treść wiadomości zaszyfrowana losowym kluczem AES
    encrypted_body = deferred(db.Column(db.LargeBinary, nullable=False))
    
    # Nonce (IV) potrzebny do AES-GCM (nie musi być tajny, ale musi być unikalny)
    body_nonce = deferred(db.Column(db.LargeBinary, nullable=False))
    
    # Tag autentyczności (GCM auth tag) - gwarantuje, że nikt nie zmienił bitów w encrypted_body
    tag = deferred(db.Column(db.LargeBinary, nullable=False))

    # --- WARSTWA 2: KLUCZE (Szyfrowanie Asymetryczne RSA) ---
    # Klucz AES zaszyfrowany Kluczem Publicznym ODBIORCY
    # (Dzięki temu tylko Odbiorca otworzy tę wiadomość)
    enc_session_key_recipient = deferred(db.Column(db.LargeBinary, nullable=False))

    # --- WARSTWA 3: AUTENTYCZNOŚĆ (Podpis Cyfrowy) ---
    # Hash wiadomości podpisany Kluczem Prywatnym NADAWCY
    # (Dowód, że to naprawdę on wysłał, a nie serwer sfałszował wiadomość)
    signature = deferred(db.Column(db.LargeBinary, nullable=False))

    # Relacja do wielu załączników
    attachments = db.relationship('Attachment', backref='message', lazy=True)

class Attachment(db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    message_id = db.Column(db.String(36), db.ForeignKey('message.id'), nullable=False)
    
    filename = db.Column(db.String(255), nullable=False)
    encrypted_blob = deferred(db.Column(db.LargeBinary, nullable=False))
    nonce = deferred(db.Column(db.LargeBinary, nullable=False))
    tag = deferred(db.Column(db.LargeBinary, nullable=False))