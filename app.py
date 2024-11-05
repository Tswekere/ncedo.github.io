from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, login_user, logout_user, UserMixin, login_required
import os
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from passlib.hash import scrypt

#Accessing MongoDB Atlas Cluster
load_dotenv()
connection : str = os.environ.get('Connection')
mongo_client : MongoClient = MongoClient(connection)

#importing the database and collections
database : Database = mongo_client.get_database("Ncedo")
users : Collection = database.get_collection("Users")
services : Collection = database.get_collection("Services")
secret_key = os.urandom(24)
#Root Route
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Flask-Login Configuration
login_manager = LoginManager()
login_manager.init_app(app)


class User(UserMixin):
    def __init__(self, id):
        self.id = id


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        address = request.form['address']
        phone = request.form['phone']
        name = request.form['name']

        existing_user = users.find_one({'username': username, 'email': email})
        if existing_user:
            flash('User already exists!')
            return redirect(url_for('home'))

        new_user = {
            'name' : name,
            'username' : username,
            'email' : email,
            'phone' : phone,
            'address': address,
            'password' : generate_password_hash(password)
        }

        users.insert_one(new_user)
        return redirect(url_for('home'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user_data = users.find_one({'email': email})  # Get user by email

        if user_data and check_password_hash(user_data['password'], password):
            login_user(User(user_data['_id']))  # Create User instance with the user's ID
            return redirect(url_for('dashboard'))

        flash('Invalid email or password')  # Flash message for invalid login
        return redirect(url_for('login'))  # Redirect to login page

    return render_template('login.html')  # Render the login template on GET request


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    search_results = []

    # Handle POST request for search
    if request.method == 'POST':
        service_type = request.form.get('service_type')

        # Search for companies by "Service Type" in the "Services" collection
        search_results = list(services.find({
            "Service Type": {"$regex": service_type, "$options": "i"}
        }))

    # Render dashboard with search results
    return render_template('dashboard.html', companies=search_results)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
