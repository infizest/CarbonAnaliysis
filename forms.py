from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    company_name = StringField('Company Name', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), EqualTo('confirm_password')])
    confirm_password = PasswordField('Confirm Password')
    submit = SubmitField('Register')

    # Validation for unique username
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('This username is already taken. Please choose a different one.')

    # Validation for unique email
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('This email is already registered. Please use a different email.')

    # Validation for unique company name
    def validate_company_name(self, company_name):
        user = User.query.filter_by(company_name=company_name.data).first()
        if user:
            raise ValidationError('This company name is already in use. Please choose a different company name.')

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
