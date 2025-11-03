import os
from functools import wraps
from flask import Flask, request, redirect, url_for, session, flash, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from jinja2 import Environment, DictLoader

# --- App Configuration ---
app = Flask(__name__)
# It's crucial to set a strong, random secret key in a real application
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-very-secret-and-hard-to-guess-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Database Model ---
class User(db.Model):
    """User model for the database."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        """Hashes and sets the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

# --- Forms ---
class RegistrationForm(FlaskForm):
    """Form for user registration."""
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=25, message='Username must be between 4 and 25 characters.')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message='Password must be at least 8 characters long.')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match.')
    ])
    submit = SubmitField('Register')

    def validate_username(self, username):
        """Custom validator to check if the username is already taken."""
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

class LoginForm(FlaskForm):
    """Form for user login."""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# --- Decorators ---
def login_required(f):
    """Decorator to protect routes that require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to view this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- HTML Templates as Strings ---

# Base template with Tailwind CSS and Inter font
base_template_html = """
<!DOCTYPE html>
<html lang="en" class="h-full bg-gray-100">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }} - Secure Auth</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
    </style>
</head>
<body class="h-full">
    <div class="min-h-full flex flex-col justify-center items-center py-12 px-4 sm:px-6 lg:px-8">
        <div class="max-w-md w-full space-y-8">
            <div>
                <svg class="mx-auto h-12 w-auto text-indigo-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
                </svg>
                <h2 class="mt-6 text-center text-3xl font-bold tracking-tight text-gray-900">
                    {{ heading }}
                </h2>
            </div>
            
            <!-- Flash Messages -->
            {% with messages = get_flashed_messages(with_categories=true) %}
              {% if messages %}
                <div class="rounded-md bg-yellow-50 p-4">
                  <div class="flex">
                    <div class="flex-shrink-0">
                      <svg class="h-5 w-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path fill-rule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clip-rule="evenodd" />
                      </svg>
                    </div>
                    <div class="ml-3">
                      <h3 class="text-sm font-medium text-yellow-800">Attention needed</h3>
                      <div class="mt-2 text-sm text-yellow-700">
                        <ul role="list" class="list-disc space-y-1 pl-5">
                          {% for category, message in messages %}
                            <li>{{ message }}</li>
                          {% endfor %}
                        </ul>
                      </div>
                    </div>
                  </div>
                </div>
              {% endif %}
            {% endwith %}

            {% block content %}{% endblock %}
        </div>
    </div>
</body>
</html>
"""

# Login Page Template
login_template_html = """
{% extends 'base.html' %}
{% block content %}
<form class="mt-8 space-y-6" action="{{ url_for('login') }}" method="POST" novalidate>
    {{ form.hidden_tag() }}
    <div class="rounded-md shadow-sm -space-y-px">
        <div>
            {{ form.username.label(class="sr-only") }}
            {{ form.username(class="relative block w-full appearance-none rounded-none rounded-t-md border border-gray-300 px-3 py-2 text-gray-900 placeholder-gray-500 focus:z-10 focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm", placeholder="Username") }}
            {% if form.username.errors %}
                {% for error in form.username.errors %}
                    <p class="text-red-500 text-xs italic mt-1">{{ error }}</p>
                {% endfor %}
            {% endif %}
        </div>
        <div>
            {{ form.password.label(class="sr-only") }}
            {{ form.password(class="relative block w-full appearance-none rounded-none rounded-b-md border border-gray-300 px-3 py-2 text-gray-900 placeholder-gray-500 focus:z-10 focus:border-indigo-500 focus:outline-none focus:ring-indigo-500 sm:text-sm", placeholder="Password", type="password") }}
             {% if form.password.errors %}
                {% for error in form.password.errors %}
                    <p class="text-red-500 text-xs italic mt-1">{{ error }}</p>
                {% endfor %}
            {% endif %}
        </div>
    </div>
    
    <div>
        {{ form.submit(class="group relative flex w-full justify-center rounded-md border border-transparent bg-indigo-600 py-2 px-4 text-sm font-medium text-white hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2") }}
    </div>
</form>
<p class="mt-2 text-center text-sm text-gray-600">
    Or
    <a href="{{ url_for('register') }}" class="font-medium text-indigo-600 hover:text-indigo-500">register for a new account</a>
</p>
{% endblock %}
"""

# Registration Page Template
register_template_html = """
{% extends 'base.html' %}
{% block content %}
<form class="mt-8 space-y-6" action="{{ url_for('register') }}" method="POST" novalidate>
    {{ form.hidden_tag() }}
    <div class="rounded-md shadow-sm space-y-2">
        <div>
            {{ form.username.label(class="block text-sm font-medium text-gray-700") }}
            {{ form.username(class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm px-3 py-2 border") }}
            {% for error in form.username.errors %}<span class="text-red-500 text-xs">{{ error }}</span>{% endfor %}
        </div>
        <div>
            {{ form.password.label(class="block text-sm font-medium text-gray-700") }}
            {{ form.password(class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm px-3 py-2 border", type="password") }}
            {% for error in form.password.errors %}<span class="text-red-500 text-xs">{{ error }}</span>{% endfor %}
        </div>
        <div>
            {{ form.confirm_password.label(class="block text-sm font-medium text-gray-700") }}
            {{ form.confirm_password(class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500 sm:text-sm px-3 py-2 border", type="password") }}
            {% for error in form.confirm_password.errors %}<span class="text-red-500 text-xs">{{ error }}</span>{% endfor %}
        </div>
    </div>
    <div>
        {{ form.submit(class="group relative flex w-full justify-center rounded-md border border-transparent bg-indigo-600 py-2 px-4 text-sm font-medium text-white hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2") }}
    </div>
</form>
<p class="mt-2 text-center text-sm text-gray-600">
    Or
    <a href="{{ url_for('login') }}" class="font-medium text-indigo-600 hover:text-indigo-500">sign in to your existing account</a>
</p>
{% endblock %}
"""

# Dashboard Page Template
dashboard_template_html = """
{% extends 'base.html' %}
{% block content %}
<div class="text-center">
    <p class="text-lg text-gray-700">
        You are now logged in, <span class="font-semibold">{{ username }}</span>!
    </p>
    <p class="mt-4">
        This is a protected page. Only authenticated users can see this.
    </p>
    <a href="{{ url_for('logout') }}" class="mt-6 inline-block rounded-md border border-transparent bg-red-600 py-2 px-4 text-sm font-medium text-white hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2">Logout</a>
</div>
{% endblock %}
"""

# --- Jinja2 Environment Setup ---
# This loader tells Jinja to find templates in our Python dictionary
jinja_env = Environment(loader=DictLoader({
    'base.html': base_template_html,
    'login.html': login_template_html,
    'register.html': register_template_html,
    'dashboard.html': dashboard_template_html
}))
# This makes Flask's functions available in our custom environment
jinja_env.globals.update(
    get_flashed_messages=get_flashed_messages,
    url_for=url_for
)


# --- Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # Sanitize and hash password
        new_user = User(username=form.username.data)
        new_user.set_password(form.password.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{getattr(form, field).label.text}: {error}", 'warning')

    template = jinja_env.get_template('register.html')
    return template.render(
        title="Register",
        heading="Create your account",
        form=form
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            session['user_id'] = user.id
            session['username'] = user.username
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password.', 'warning')

    template = jinja_env.get_template('login.html')
    return template.render(
        title="Login",
        heading="Sign in to your account",
        form=form
    )

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    username = session.get('username', 'Guest')
    template = jinja_env.get_template('dashboard.html')
    return template.render(
        title="Dashboard",
        heading=f"Welcome to the Dashboard",
        username=username
    )

# --- Main Execution ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

