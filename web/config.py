import os
from utils import get_secret
from datetime import timedelta

# kontener na ustawienia, Flask odczytuje atrybuty tej klasy i stosuje je jako parametry działania serwera
class Config:
    SECRET_KEY = get_secret('flask_key_file')
    # Ścieżka do bazy danych
    SQLALCHEMY_DATABASE_URI = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///app.db')
    # Zabrania skryptom JavaScript dostępu do ciasteczka sesji.
    SESSION_COOKIE_HTTPONLY = True
    # Ciasteczko zostanie wysłane tylko przez szyfrowane połączenie HTTPS.
    SESSION_COOKIE_SECURE = True
    # Mówi przeglądarce, by nie wysyłała ciasteczka, 
    # gdy użytkownik trafi na Twoją stronę z zewnętrznego linku w sposób podejrzany.
    SESSION_COOKIE_SAMESITE = 'Lax'

    # Czas życia tokena CSRF
    WTF_CSRF_TIME_LIMIT = 900 # 15 minut
    # Wymusza, aby tokeny CSRF były przesyłane tylko przez HTTPS
    WTF_CSRF_SSL_STRICT = True
    # Informacja jak długo użytkownik pozostaje zalogowany bez aktywności.
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=60)
    # Limit rozmiaru pliku, który można przesłać.
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024 # 10MB bo 1KB to 1024 bajtów, a 1MB to 1024KB

