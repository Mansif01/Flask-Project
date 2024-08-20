from flask_wtf import FlaskForm
from wtforms import IntegerField, SubmitField
from wtforms.validators import DataRequired, NumberRange


# Change the form signature so that 6 values must be entered and the values must be in the range of 1 to 60 otherwise
# the form will not be submitted and appropriate error messages will be shown.
class DrawForm(FlaskForm):
    number1 = IntegerField(id='no1', validators=[DataRequired(), NumberRange(min=1, max=60,
                                                                             message="Length of draw must be between "
                                                                                     "1 and 60")])
    number2 = IntegerField(id='no2', validators=[DataRequired(), NumberRange(min=1, max=60,
                                                                             message="Length of draw must be between "
                                                                                     "1 and 60")])
    number3 = IntegerField(id='no3', validators=[DataRequired(), NumberRange(min=1, max=60,
                                                                             message="Length of draw must be between "
                                                                                     "1 and 60")])
    number4 = IntegerField(id='no4', validators=[DataRequired(), NumberRange(min=1, max=60,
                                                                             message="Length of draw must be between "
                                                                                     "1 and 60")])
    number5 = IntegerField(id='no5', validators=[DataRequired(), NumberRange(min=1, max=60,
                                                                             message="Length of draw must be between "
                                                                                     "1 and 60")])
    number6 = IntegerField(id='no6', validators=[DataRequired(), NumberRange(min=1, max=60,
                                                                             message="Length of draw must be between "
                                                                                     "1 and 60")])
    submit = SubmitField("Submit Draw")

    # A custom validator that can access all the form fields
    def validate(self, **kwargs):
        standard_validators = FlaskForm.validate(self)
        if standard_validators:
            # The numbers are stored in a list
            numbers = [self.number1.data, self.number2.data, self.number3.data, self.number4.data, self.number5.data,
                       self.number6.data]

            # It checks if the numbers are unique
            if len(set(numbers)) != len(numbers):
                self.number6.errors.append("The draw numbers should be unique.")
                return False
            # It checks if the numbers are sorted in ascending order
            if numbers != sorted(numbers):
                self.number6.errors.append("The draw numbers must be stored in ascending order.")
                return False

            return True

        return False
