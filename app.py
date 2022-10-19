import os

from flask import Flask, render_template, redirect, request, flash, session, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///passmane.db"
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

# models
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    hash = db.Column(db.Text, nullable=False)
    passlists = db.relationship("Passlist", back_populates="user")


class Passlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(30))
    account = db.Column(db.String(30))
    password = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    user = db.relationship("User", back_populates="passlists")


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route("/")
def index():
    return render_template("index.html")


