import os

class Config:
    SECRET_KEY = '697f85e04cd1048b4a257d68df1904a51684bbf2414ad560'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///carbon_footprint.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
