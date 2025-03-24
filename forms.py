from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField
from wtforms.validators import DataRequired, Email, EqualTo

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    company_name = StringField('Company Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password')])
    confirm_password = PasswordField('Confirm Password')
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CarbonForm(FlaskForm):
    electricity_bill = FloatField('Electricity Bill (USD)', validators=[DataRequired()])
    natural_gas_bill = FloatField('Natural Gas Bill (USD)', validators=[DataRequired()])
    fuel_bill = FloatField('Fuel Bill (USD)', validators=[DataRequired()])
    waste_generated = FloatField('Waste Generated (kg)', validators=[DataRequired()])
    recycling_percentage = FloatField('Recycling Percentage (%)', validators=[DataRequired()])
    kilometers_traveled = FloatField('Kilometers Traveled', validators=[DataRequired()])
    fuel_efficiency = FloatField('Fuel Efficiency (km/l)', validators=[DataRequired()])
    submit = SubmitField('Submit Data')
