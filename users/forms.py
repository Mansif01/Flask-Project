from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField, PasswordField, EmailField, BooleanField
from wtforms.validators import Email, ValidationError, Length, EqualTo, DataRequired
import re

# This function checks if the entered information has the excluded characters and if it does then it raises a Validation
# error and error message is shown.
def character_check(form, field):
    wrong_char = "* ? ! ' ^ + % & / ( ) = } ] [ { $ # @ < >"
    for char in field.data:
        if char in wrong_char:
            raise ValidationError(f"Character {char} is not allowed.")

# This function checks if the phone number provided is in the correct form i.e. XXXX-XXX-XXXX and if it does not match
# then validation error is raised and error message is shown.
def validate_data(self, phone):
    p = re.compile(r'^\d{4}-\d{3}-\d{4}$')
    if not p.match(phone.data):
        raise ValidationError("The phone number must be all digits and in the form XXXX-XXX-XXXX.")

# This function checks if the password contains one digit, one uppercase letter, one lowercase letter and at least one
# special character and if it doesn't satisfy then error message is shown.
def validate_password(self, password):
    p = re.compile(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*\W).+$')
    if not p.match(password.data):
        raise ValidationError("It must contain at least one digit, one Uppercase letter, one Lowercase letter and "
                              "at least one special character.")

# This function checks if the date of birth is in the form DD/MM/YYYY and if it does not satisfy then error message
# is shown.
def validate_dateOfBirth(self, dateOfBirth):
    p = re.compile(r'^(0[1-9]|[12][0-9]|3[01])/(0[1-9]|1[0-2])/(19|20)\d{2}$')
    if not p.match(dateOfBirth.data):
        raise ValidationError("It must be in the form DD/MM/YYYY")


def validate_postcode(self, postcode):
    p = re.compile(r'^([A-Z]{1,2}\d[A-Z\d] \d[A-Z]{2}|[A-Z]{2}\d \d[A-Z]{2}|[A-Z]\d[A-Z] \d[A-Z]{2})$')
    if not p.match(postcode.data):
        raise ValidationError("It must be in the form XY YXX, XYY YXX or XXY YXX")


class RegisterForm(FlaskForm):
    email = EmailField(validators=[Email()])
    firstname = StringField(validators=[character_check])
    lastname = StringField(validators=[character_check])
    phone = StringField(validators=[validate_data])
    password = PasswordField(validators=[Length(min=6, max=12), validate_password])
    confirm_password = PasswordField(validators=[EqualTo('password', message='Both passwords must be equal!')])
    dateOfBirth = StringField(validators=[validate_dateOfBirth])
    postcode = StringField(validators=[validate_postcode])
    submit = SubmitField()

# A login form which takes the user's username, password, pin and postcode and matches it with the stored ones in the
# database. If matched then certain parts of the lottery application is shown. There is a submit button to submit it
# after entering details.
# It also shows a recaptcha.
class LoginForm(FlaskForm):
    username = StringField(validators=[DataRequired(), Email()])
    password = PasswordField(validators=[DataRequired()])
    pin = StringField(validators=[DataRequired()])
    postcode = StringField(validators=[DataRequired()])
    submit = SubmitField()
    recaptcha = RecaptchaField()

# A form to change password
# The current password must be provided and error messages shown if not provided
# The show password provides toggling between hidden and plain text of password
# The new password must be provided and length should be between 6 and 12 and error messages shown if not provided
# The confirm new password matches the provided password with the new password and if the password does not match then
# error message is shown
class PasswordForm(FlaskForm):
    current_password = PasswordField(id='password', validators=[DataRequired()])
    show_password = BooleanField('Show password', id='check')
    new_password = PasswordField(validators=[DataRequired(), Length(min=6, max=12, message="Must be between 8 and 15 "
                                                                                           "characters in length"),
                                             validate_password])
    confirm_new_password = PasswordField(validators=[DataRequired(), EqualTo('new_password', message='Both new '
                                                                                                     'password fields'
                                                                                                     ' must be equal')])
    submit = SubmitField('Change Password')
