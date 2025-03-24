from database import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(64), unique=True, nullable=False)
    company_name = db.Column(db.String(128), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    energy_usage = db.relationship('EnergyUsage', backref='user', uselist=False)
    waste = db.relationship('Waste', backref='user', uselist=False)
    business_travel = db.relationship('BusinessTravel', backref='user', uselist=False)

class EnergyUsage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    electricity_bill = db.Column(db.Float, nullable=False)
    natural_gas_bill = db.Column(db.Float, nullable=False)
    fuel_bill = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Waste(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    waste_generated = db.Column(db.Float, nullable=False)
    recycling_percentage = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class BusinessTravel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kilometers_traveled = db.Column(db.Float, nullable=False)
    fuel_efficiency = db.Column(db.Float, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
