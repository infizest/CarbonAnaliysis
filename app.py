from flask import Flask, render_template, redirect, url_for, flash, request, Response
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from database import db
import pandas as pd
import base64
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO
import pdfkit
import io
from flask import Response, render_template
import tempfile

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

# Helper function to generate base64 encoded images
def plot_to_base64(fig):
    buffer = io.BytesIO()
    fig.savefig(buffer, format='png', bbox_inches='tight')
    buffer.seek(0)
    encoded_image = base64.b64encode(buffer.getvalue()).decode('utf-8')
    buffer.close()
    plt.close(fig)  # Close to prevent memory leaks
    return f"data:image/png;base64,{encoded_image}"
# Graph 1: Energy Usage
def generate_energy_graph(df):
    fig, ax = plt.subplots(figsize=(8, 5))
    df.plot(x='Month', y=['Electricity', 'Natural Gas', 'Fuel'], kind='bar', ax=ax)
    ax.set_title('Monthly Energy Usage')
    ax.set_ylabel('Energy (kWh)')
    ax.grid(True)
    return plot_to_base64(fig)

# Graph 2: Waste Management
def generate_waste_graph(df):
    fig, ax = plt.subplots(figsize=(8, 5))
    df.plot(x='Month', y=['Waste', 'Recycling'], kind='bar', ax=ax)
    ax.set_title('Waste Management Overview')
    ax.set_ylabel('Waste (kg)')
    ax.grid(True)
    return plot_to_base64(fig)

# Graph 3: Business Travel Trends
def generate_travel_graph(df):
    fig, ax = plt.subplots(figsize=(8, 5))
    sns.lineplot(x='Month', y='Travel', data=df, marker='o', ax=ax)
    ax.set_title('Business Travel Trends')
    ax.set_ylabel('Distance (km)')
    ax.grid(True)
    return plot_to_base64(fig)
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

    if form.validate_on_submit():
        energy_usage = EnergyUsage(
            electricity_bill=form.electricity_bill.data,
            natural_gas_bill=form.natural_gas_bill.data,
            fuel_bill=form.fuel_bill.data,
            user_id=current_user.id
        )
        waste = Waste(
            waste_generated=form.waste_generated.data,
            recycling_percentage=form.recycling_percentage.data,
            user_id=current_user.id
        )
        business_travel = BusinessTravel(
            kilometers_traveled=form.kilometers_traveled.data,
            fuel_efficiency=form.fuel_efficiency.data,
            user_id=current_user.id
        )
        db.session.add_all([energy_usage, waste, business_travel])
        db.session.commit()
        flash("Data submitted successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', form=form)

@app.route('/graphs')
@login_required
def view_graphs():
    # Fetch data
    energy_data = EnergyUsage.query.filter_by(user_id=current_user.id).all()
    waste_data = Waste.query.filter_by(user_id=current_user.id).all()
    travel_data = BusinessTravel.query.filter_by(user_id=current_user.id).all()

    # Convert to DataFrame
    months = range(1, len(energy_data) + 1)
    energy_df = pd.DataFrame([(e.electricity_bill, e.natural_gas_bill, e.fuel_bill) for e in energy_data],
                               columns=["Electricity", "Natural Gas", "Fuel"])
    energy_df['Month'] = months

    waste_df = pd.DataFrame([(w.waste_generated, w.recycling_percentage) for w in waste_data],
                              columns=["Waste", "Recycling"])
    waste_df['Month'] = months

    travel_df = pd.DataFrame([(t.kilometers_traveled,) for t in travel_data], columns=["Travel"])
    travel_df['Month'] = months

    # Generate graphs
    energy_graph = generate_energy_graph(energy_df)
    waste_graph = generate_waste_graph(waste_df)
    travel_graph = generate_travel_graph(travel_df)

    return render_template('graphs.html', energy_graph=energy_graph, waste_graph=waste_graph, travel_graph=travel_graph)


@app.route('/download-pdf')
@login_required
def download_pdf():
    path_to_wkhtmltopdf = '/usr/bin/wkhtmltopdf'
    config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)

    rendered_html = render_template('graphs.html')

    # Save to a temporary HTML file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as tmp_html:
        tmp_html.write(rendered_html.encode('utf-8'))
        tmp_html_path = tmp_html.name

    options = {
        "enable-local-file-access": ""
    }

    pdf = pdfkit.from_file(tmp_html_path, False, configuration=config, options=options)

    response = Response(pdf, content_type='application/pdf')
    response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'
    return response
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
      app.run(debug=True, host='0.0.0.0', port=8080)
