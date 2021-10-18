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
    password = PasswordField(validators=[Required(), Length(min=6, max=12, message='Passwood must be between 6 and 12 characters length')])
    confirm_password = PasswordField(validators=[Required()])
    pin_key = StringField(validators=[Required()])
    submit = SubmitField()
