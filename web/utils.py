import os 
from werkzeug.utils import secure_filename
from wtforms.validators import ValidationError

def get_secret(secret_name):
    # 1. Najpierw próbujemy Docker Secrets (plik)
    try:
        with open(f'/run/secrets/{secret_name}', 'r') as file:
            return file.read().strip()
    except IOError:
        # 2. Jak nie ma pliku, szukamy w zmiennych (dla kompatybilności)
        key = os.environ.get(secret_name.upper())
        if key:
            return key
            
    # 3. Jeśli nigdzie nie ma klucza - STOP! Nie uruchamiaj aplikacji
    raise ValueError(f"CRITICAL ERROR: No Secret '{secret_name}'!")


FORBIDDEN_EXTENSIONS = {
    'exe', 'bat', 'com', 'cmd', 'sh', 'vbs', 'ps1', 'jar', 'msi', 'php', 'py', 'pl'
}

def validate_file(file_storage):
    filename = secure_filename(file_storage.filename)
    if not filename:
        return None
        
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext in FORBIDDEN_EXTENSIONS:
        return False
    return filename

def validate_file_size(form, field):
    max_mb = 10
    for file in field.data:
        if not file or isinstance(file, str): continue
        file.seek(0, 2)
        size = file.tell()
        file.seek(0)
        if size > max_mb * 1024 * 1024:
            raise ValidationError(f'Plik "{file.filename}" jest za duży (max {max_mb}MB).')