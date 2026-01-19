import os
import uuid 
from werkzeug.utils import secure_filename
from wtforms.validators import ValidationError

def get_secret(secret_name):
    # Najpierw sprawdzamy  Docker Secrets
    try:
        with open(f'/run/secrets/{secret_name}', 'r') as file:
            return file.read().strip()
    except IOError:
        # Szukamy w zmiennych środowiskowych
        key = os.environ.get(secret_name.upper())
        if key:
            return key
            
    # Brak klucza, nie uruchamiamy aplikacji
    raise ValueError(f"CRITICAL ERROR: No Secret '{secret_name}'!")


FORBIDDEN_EXTENSIONS = {
    'exe', 'bat', 'com', 'cmd', 'sh', 'vbs', 'ps1', 'jar', 'msi', 'php', 'py', 'pl'
}

def validate_file(file_storage):
    # secure_filename usuwa niebezpieczne znaki (np. spacje, nawiasy, ../) z nazwy pliku, aby zapobiec atakom Path Traversal i problemom z systemem plików
    filename = secure_filename(file_storage.filename)
    if not filename:
        return None
    
    # Szukamy kropki od konca i bierzemy rozszerzenie
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext in FORBIDDEN_EXTENSIONS:
        return False
    return filename

def validate_file_size(form, field):
    max_mb = 10
    for file in field.data:
        if not file or isinstance(file, str): continue
        # Sprawdzamy rozmiar pliku przez przesuniecie kursora na koniec pliku
        file.seek(0, 2)
        size = file.tell()
        # Wracamy na poczatek pliku
        file.seek(0)
        if size > max_mb * 1024 * 1024:
            raise ValidationError(f'Plik "{file.filename}" jest za duży (max {max_mb}MB).')

def validate_uuid(uuid_string):
    try:
        # Sprawdzamy czy podany ciag znakow jest poprawnym UUID
        uuid.UUID(uuid_string)
        return True
    # Zła wartość, zły obiekt lub zły typ
    except (ValueError, AttributeError, TypeError):
        return False