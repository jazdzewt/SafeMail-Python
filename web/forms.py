# web/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, Regexp

class RegistrationForm(FlaskForm):
    username = StringField('Login', validators=[
        DataRequired(message="Login jest wymagany"),
        Length(min=3, max=20, message="Login musi mieć od 3 do 20 znaków"),
        Regexp(r'^[\w]+$', message="Login może zawierać tylko litery, cyfry i podkreślniki")])

    password = PasswordField('Hasło', validators=[
        DataRequired(message="Hasło jest wymagane"),
        Length(min=8, message="Hasło musi mieć minimum 8 znaków")])

    confirm_password = PasswordField('Powtórz hasło', validators=[
        DataRequired(),
        EqualTo('password', message="Hasła muszą być identyczne")])

    submit = SubmitField('Zarejestruj się')

class LoginForm(FlaskForm):
    username = StringField('Login', validators=[DataRequired()])
    password = PasswordField('Hasło', validators=[DataRequired()])
    submit = SubmitField('Zaloguj się')