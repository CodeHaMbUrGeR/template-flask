from flask import Flask, render_template, url_for, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
import os

# --------------------------------------------------------------------------------------------------
# --- Flask App ------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db').replace('postgres://', 'postgresql://')  # dynamic
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev')  # dynamic

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --------------------------------------------------------------------------------------------------
# --- Database -------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)


# --------------------------------------------------------------------------------------------------
# --- Forms ----------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------
class LoginForm(FlaskForm):
    username = StringField(label="Benutzername", validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username", 'autocomplete': 'off'})
    password = PasswordField(label="Passwort", validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


# --------------------------------------------------------------------------------------------------
# --- Register, Login & Logout ---------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------
@app.route("/user", methods=["GET", "POST"])
def user():
    if current_user.is_authenticated:
        return redirect(url_for('logout'))
    else:
        return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password.decode("utf-8", "ignore"))
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


# --------------------------------------------------------------------------------------------------
# --- Routing --------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    return redirect(url_for('home'))


@app.route('/home', methods=['GET', 'POST'])
def home():
    return render_template('home.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    app.run(port=5000, debug=True)
