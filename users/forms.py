import re
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import Required, Email, ValidationError, Length, EqualTo


def character_check(form, field):
    excluded_chars = "*?!'^+%&/()=}][{$#@<>"
    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(
                f"Character {char} is not allowed.")


class LoginForm(FlaskForm):
    username = StringField(validators=[Required(), Email()])
    password = PasswordField(validators=[Required()])
    pin = StringField(validators=[Required(),Length(min=6, max=6, message="PIN key should be exactly 6 characters long")])
    submit = SubmitField()


class RegisterForm(FlaskForm):
    email = StringField(validators=[Required(), Email()])
    firstname = StringField(validators=[Required(), character_check])
    lastname = StringField(validators=[Required(), character_check])
    phone = StringField(validators=[Required()])
    password = PasswordField(validators=[Required(), Length(min=6, max=12, message='Passwood must be between 6 and 12 characters length.')])
    confirm_password = PasswordField(validators=[Required(), EqualTo('password', message = 'Passwords do not match')])
    pin_key = StringField(validators=[Required(), Length(min=32, max = 32, message='PIN key must be exactly 32 characters')])
    submit = SubmitField()

    def validate_password(self, password):
        p = re.compile(r"(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[*?!'^+%&/()=}{$#@<>])")
        if not p.match(self.password.data):
            raise ValidationError('Password must contain 1 number, 1 special character, 1 uppercase and 1 lowercase letter')

    def validate_phone(self, phone):
        t = re.compile(r"(\d{4})(-{1})(\d{3})(-{1})(\d{4})")
        if not t.match(self.phone.data):
            raise ValidationError('Invalid phone number. Phone number must be in the form XXXX-XXX-XXXX')