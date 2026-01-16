from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField, FileField, SelectMultipleField, MultipleFileField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp, ValidationError

from utils import validate_file_size

class RegistrationForm(FlaskForm):
    username = StringField('Login', validators=[
        DataRequired(message="Login jest wymagany"),
        Length(min=3, max=20, message="Login musi mieć od 3 do 20 znaków"),
        Regexp(r'^[\w]+$', message="Login może zawierać tylko litery, cyfry i podkreślniki")])

    password = PasswordField('Hasło', validators=[
        DataRequired(message="Hasło jest wymagane"),
        Length(min=8, message="Hasło musi mieć minimum 8 znaków"),
        Regexp(r'^.*[a-z].*$', message="Hasło musi zawierać co najmniej jedną małą literę"),
        Regexp(r'^.*[A-Z].*$', message="Hasło musi zawierać co najmniej jedną wielką literę"),
        Regexp(r'^.*[0-9].*$', message="Hasło musi zawierać co najmniej jedną cyfrę"),
        Regexp(r'^.*[\W_].*$', message="Hasło musi zawierać co najmniej jeden znak specjalny")])

    confirm_password = PasswordField('Powtórz hasło', validators=[
        DataRequired(),
        EqualTo('password', message="Hasła muszą być identyczne")])

    submit = SubmitField('Zarejestruj się')

class LoginForm(FlaskForm):
    username = StringField('Login', validators=[DataRequired()])
    password = PasswordField('Hasło', validators=[DataRequired()])
    totp_code = StringField('Kod 2FA (6 cyfr)', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Zaloguj się')

# ==============================================================================

class MessageForm(FlaskForm):
    recipient = SelectMultipleField('Odbiorcy', coerce=str, validators=[DataRequired()])
    topic = StringField('Temat', validators=[DataRequired(), Length(min=10, max=150, message="Temat musi mieć od 10 do 150 znaków")])
    content = TextAreaField('Treść wiadomości', validators=[DataRequired(), Length(min=1, max=5000)])
    files = MultipleFileField('Załączniki (opcjonalnie)', render_kw={'multiple': True}, validators=[validate_file_size])
    password_confirm = PasswordField('Potwierdź hasło (do podpisu)', validators=[DataRequired()])
    submit = SubmitField('Wyślij wiadomość')