from flask import Flask, render_template, redirect, url_for, flash, request
from pytube import YouTube
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError




app = Flask(__name__)


app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///site.bd"
app.config['SECRET_KEY'] = "thisisasecretkey"
db = SQLAlchemy(app)
login_manager = LoginManager(app)
bcrypt = Bcrypt(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(90), nullable=False, unique=True)
    password = db.Column(db.String(110), nullable=False)


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=80)])
    submit = SubmitField('Register')


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegistrationForm()

    if request.method == "POST":
        username = form.username.data
        password = form.password.data

        # Hash the password before storing it
        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password=hashed_password)

        try:
            print("Register function called")  # Add this line
            db.session.add(new_user)
            db.session.commit()
            print(username)
            print(password)
            flash('Account created successfully', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Username already exists. Please choose another.', 'danger')
        except Exception:
            db.session.rollback()
            flash(f'Error creating account. Please try again.', 'danger')

    return render_template("register.html")





@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("download"))
        else:
            flash("Invalid username or password. Please try again.", "danger")

    return render_template("do_login.html")




@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("home.html")


@app.route("/download", methods=["GET", "POST"])
@login_required
def download():
    link_value = None
    image = None

    if request.method == "POST":
        yt_link = request.form.get('link_input')
        if yt_link:
            try:
                yt_object = YouTube(yt_link)
                video = yt_object.streams.get_highest_resolution()

                video.download()
                link_value = f"'{yt_object.title}' downloaded successfully!"
                image = yt_object.thumbnail_url
            except Exception:
                link_value = "Download Error: Unable to download the video."

    return render_template("download.html", link_value=link_value, image=image)



with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)