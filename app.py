from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from database import db
import pandas as pd;
import plotly.express as px
import pdfkit

from models import User, EnergyUsage, Waste, BusinessTravel
from forms import RegistrationForm, LoginForm, CarbonForm

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data,
                    company_name=form.company_name.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful!", "success")
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash("Invalid credentials", "danger")
    return render_template('login.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = CarbonForm()

    # Data submission
    if form.validate_on_submit():
        energy_usage = EnergyUsage(electricity_bill=form.electricity_bill.data,
                                    natural_gas_bill=form.natural_gas_bill.data,
                                    fuel_bill=form.fuel_bill.data, user_id=current_user.id)
        waste = Waste(waste_generated=form.waste_generated.data,
                       recycling_percentage=form.recycling_percentage.data, user_id=current_user.id)
        business_travel = BusinessTravel(kilometers_traveled=form.kilometers_traveled.data,
                                         fuel_efficiency=form.fuel_efficiency.data, user_id=current_user.id)
        db.session.add_all([energy_usage, waste, business_travel])
        db.session.commit()
        flash("Data submitted successfully!", "success")
        return redirect(url_for('dashboard'))

    # Error handling
    elif request.method == 'POST':
        flash("Form submission failed. Please check your inputs.", "danger")

    return render_template('dashboard.html', form=form)

@app.route('/graphs')
@login_required
def view_graphs():
    # Fetch data for graphs
    energy_data = EnergyUsage.query.filter_by(user_id=current_user.id).all()
    waste_data = Waste.query.filter_by(user_id=current_user.id).all()
    travel_data = BusinessTravel.query.filter_by(user_id=current_user.id).all()

    # Convert to DataFrame
    energy_df = pd.DataFrame([(e.electricity_bill, e.natural_gas_bill, e.fuel_bill) for e in energy_data],
                               columns=["Electricity Bill", "Natural Gas Bill", "Fuel Bill"])
    waste_df = pd.DataFrame([(w.waste_generated, w.recycling_percentage) for w in waste_data],
                              columns=["Waste Generated", "Recycling Percentage"])
    travel_df = pd.DataFrame([(t.kilometers_traveled, t.fuel_efficiency) for t in travel_data],
                               columns=["Kilometers Traveled", "Fuel Efficiency"])

    # Generate graphs
    energy_df_melted = energy_df.reset_index().melt(id_vars='index', var_name='Energy Source', value_name='Amount')
    energy_fig = px.bar(energy_df_melted, x='index', y='Amount', color='Energy Source', title="Energy Usage")
    waste_fig = px.pie(waste_df, values='Waste Generated', names='Waste Generated', title="Waste Management")
    travel_fig = px.line(travel_df, x=travel_df.index, y=["Kilometers Traveled", "Fuel Efficiency"], title="Business Travel Trends")

    # Convert to HTML
    energy_graph = energy_fig.to_html(full_html=False)
    waste_graph = waste_fig.to_html(full_html=False)
    travel_graph = travel_fig.to_html(full_html=False)

    return render_template('graphs.html', energy_graph=energy_graph, waste_graph=waste_graph, travel_graph=travel_graph)

@app.route('/download-pdf')
@login_required
def download_pdf():
    rendered_html = render_template('graphs.html')
    pdf = pdfkit.from_string(rendered_html, False)

    response = Response(pdf, content_type='application/pdf')
    response.headers['Content-Disposition'] = 'inline; filename=carbon_report.pdf'
    return responsev


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
