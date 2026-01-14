import uuid  # <--- Dodaj ten import na samej górze
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

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