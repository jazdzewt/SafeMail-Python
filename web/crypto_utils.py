import os
import argon2
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

# Konfiguracja Argon2 (twarde limity dla bezpieczeństwa)
ph = argon2.PasswordHasher(
    time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16
)

def hash_password(password: str) -> str:
    """Tworzy bezpieczny hash hasła."""
    return ph.hash(password)

def verify_password(hash: str, password: str) -> bool:
    """Sprawdza czy hasło pasuje do hasha."""
    try:
        ph.verify(hash, password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False

def generate_key_pair(password: str):
    """
    Generuje parę kluczy RSA 2048-bit.
    Klucz prywatny jest SZYFROWANY hasłem użytkownika (AES-256).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Szyfrowanie klucza prywatnego hasłem użytkownika
    encrypted_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return encrypted_private_pem, public_pem

def decrypt_private_key(encrypted_pem_data: bytes, password: str):
    """
    Ładuje (odszyfrowuje) klucz prywatny RSA z formatu PEM używając hasła.
    """
    try:
        private_key = serialization.load_pem_private_key(
            encrypted_pem_data,
            password=password.encode(),
        )
        return private_key
    except Exception as e:
        print(f"Private keys decryption failed: {e}")
        return None

def encrypt_data(data: str, password: str) -> bytes:
    """
    Szyfruje dowolny tekst (np. sekret TOTP) używając hasła użytkownika.
    Używa PBKDF2 do wyprowadzenia klucza dla AES (Fernet).
    """
    # 1. Generujemy sól (w produkcji powinna być losowa i zapisana obok danych,
    # ale dla uproszczenia tutaj użyjemy stałej soli lub deterministycznej,
    # UWAGA: W pełnej implementacji sól powinna być per-user, zapisana w bazie osobno.
    # Tutaj dla uproszczenia (demo) użyjemy stałej soli lub hashu loginu.
    # Zróbmy to bezpiecznie: generujemy losową sól i doklejamy do wyniku.
    salt = os.urandom(16)
    
    # 2. Derive key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    # 3. Encrypt
    f = Fernet(key)
    token = f.encrypt(data.encode())
    
    # 4. Return salt + token (aby móc odszyfrować potrzebujemy tej soli)
    # Format: salt(16b) + token
    return salt + token

def decrypt_data(encrypted_data: bytes, password: str) -> str:
    """
    Odszyfrowuje dane (np. sekret TOTP).
    Wyciąga sól z pierwszych 16 bajtów, generuje klucz i odszyfrowuje.
    """
    # 1. Extract salt
    salt = encrypted_data[:16]
    token = encrypted_data[16:]
    
    # 2. Derive key (musi być identycznie jak przy szyfrowaniu)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    # 3. Decrypt
    f = Fernet(key)
    try:
        decrypted_bytes = f.decrypt(token)
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None