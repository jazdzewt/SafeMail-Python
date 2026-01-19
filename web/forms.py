from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectMultipleField, MultipleFileField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp

from utils import validate_file_size

class RegistrationForm(FlaskForm):
    username = StringField('Login', validators=[
        DataRequired(message="Login jest wymagany"),
        Length(min=3, max=20, message="Login musi mieć od 3 do 20 znaków"),
        # [\w] - dowolna litera, cyfra lub znak podkreślenia
        Regexp(r'^[\w]+$', message="Login może zawierać tylko litery, cyfry i podkreślniki")])
    password = PasswordField('Hasło', validators=[
        DataRequired(message="Hasło jest wymagane"),
        Length(min=8, max=50, message="Hasło musi mieć od 8 do 50 znaków"),
        Regexp(r'^.*[a-z].*$', message="Hasło musi zawierać co najmniej jedną małą literę"),
        Regexp(r'^.*[A-Z].*$', message="Hasło musi zawierać co najmniej jedną wielką literę"),
        Regexp(r'^.*[0-9].*$', message="Hasło musi zawierać co najmniej jedną cyfrę"),
        Regexp(r'^.*[\W_].*$', message="Hasło musi zawierać co najmniej jeden znak specjalny")])
    confirm_password = PasswordField('Powtórz hasło', validators=[
        DataRequired(),
        EqualTo('password', message="Hasła muszą być identyczne")])
    submit = SubmitField('Zarejestruj się')

class LoginForm(FlaskForm):
    username = StringField('Login', validators=[DataRequired(),
        Length(min=3, max=20, message="Login ma od 3 do 20 znaków!"),
        Regexp(r'^[\w]+$', message="Login zawiera tylko litery, cyfry i podkreślniki!")])
    password = PasswordField('Hasło', validators=[DataRequired(), Length(min=8, max=50)])
    totp_code = StringField('Kod 2FA (6 cyfr)', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Zaloguj się')

class MessageForm(FlaskForm):
    recipient = SelectMultipleField('Odbiorcy', coerce=str, validators=[DataRequired(),
        Length(max=5, message="Możesz wysłać wiadomość do maksymalnie 5 odbiorców.")])
    topic = StringField('Temat', validators=[DataRequired(), Length(min=10, max=150, message="Temat musi mieć od 10 do 150 znaków")])
    content = TextAreaField('Treść wiadomości', validators=[DataRequired(), Length(min=1, max=5000)])
    # render_kw={'multiple': True} pozwala na przesłanie wielu plików. Mówi Flaskowi, 
    # że ma to być <input type="file" multiple>
    files = MultipleFileField('Załączniki (opcjonalnie)', render_kw={'multiple': True}, validators=[
        validate_file_size,
        Length(max=5, message="Możesz wysłać maksymalnie 5 załączników.")])
    password_confirm = PasswordField('Potwierdź hasło (do podpisu)', validators=[DataRequired(), Length(min=8, max=50)])
    submit = SubmitField('Wyślij wiadomość')