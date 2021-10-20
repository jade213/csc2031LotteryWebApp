import re
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import Required, Email, ValidationError, Length


def character_check(form, field):
    excluded_chars = "*?!'^+%&/()=}][{$#@<>"
    for char in field.data:
        if char in excluded_chars:
            raise ValidationError(
                f"Character {char} is not allowed.")


class RegisterForm(FlaskForm):
    email = StringField(validators=[Required(), Email()])
    firstname = StringField(validators=[Required(), character_check])
    lastname = StringField(validators=[Required(), character_check])
    phone = StringField(validators=[Required()])
    password = PasswordField(validators=[Required(), Length(min=6, max=12, message='Passwood must be between 6 and 12 characters length.')])
    confirm_password = PasswordField(validators=[Required()])
    pin_key = StringField(validators=[Required()])
    submit = SubmitField()

    def validate_password(self, password):
        p = re.compile(r"(?=.*\d)(?=.*[A-Z])(?=.*[a-z])(?=.*[*?!'^+%&/()=}{$#@<>])")
        if not p.match(self.password.data):
            raise ValidationError('Password must contain 1 number, 1 special character, 1 uppercase and 1 lowercase letter')