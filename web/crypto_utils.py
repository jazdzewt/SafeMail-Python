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

def encrypt_totp(data: str, password: str) -> bytes:
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

def decrypt_totp(encrypted_data: bytes, password: str) -> str:
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


# ==============================================================================

def encrypt_aes_gcm(session_key: bytes,plaintext: bytes):
    """
    Szyfruje dane algorytmem AES-GCM.
    Zwraca: (ciphertext, nonce, tag, session_key)
    """
    #session_key = key #os.urandom(32) # 256-bit AES key
    nonce = os.urandom(12) # 96-bit nonce for GCM
    
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    cipher = Cipher( algorithms.AES(session_key), modes.GCM(nonce), backend=default_backend() )
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return ciphertext, nonce, encryptor.tag, session_key

def decrypt_aes_gcm(session_key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Odszyfrowuje dane algorytmem AES-GCM.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    cipher = Cipher(algorithms.AES(session_key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    return decryptor.update(ciphertext) + decryptor.finalize()

def encrypt_rsa(public_key_pem: str, data: bytes) -> bytes:
    """
    Szyfruje dane (np. klucz sesyjny 32B) kluczem PUBLICZNYM (PEM).
    Używa OAEP + MGF1 + SHA256 (standard).
    """
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    
    encrypted = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def sign_rsa(private_key, data: bytes) -> bytes:
    """
    Podpisuje dane (np. hash wiadomości) kluczem PRYWATNYM.
    Używa PSS + MGF1 + SHA256.
    """
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def decrypt_rsa(private_key, ciphertext: bytes) -> bytes:
    """
    Odszyfrowuje dane (np. klucz sesyjny) używając klucza PRYWATNEGO.
    Używa OAEP + MGF1 + SHA256.
    """
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

def verify_signature_rsa(public_key_pem: str, data: bytes, signature: bytes) -> bool:
    """
    Weryfikuje podpis danych kluczem PUBLICZNYM.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Signature verification failed!")
        return False