import os
import secrets
import string

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
    return User.query.get(int(user_id))

# passwordを作成する
def get_random_password_string(length, flag):
    # 半角英数字のみ(大文字を含む)
    if flag:
        pass_chars = string.ascii_letters + string.digits + string.punctuation
    else:
        pass_chars = string.ascii_letters + string.digits
    # 半角英数字＋記号
    password = ''.join(secrets.choice(pass_chars) for x in range(length))
    return password

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        # userからemailとpasswordを受け取る
        email = request.form.get("email")
        main_password = request.form.get("mainpassword")
        sub_password = request.form.get("subpassword")

        # emailやpasswordの入力がない場合などのエラー処理
        if not email:
            flash("emailを入力してください")
            return render_template("register.html")
        if not main_password:
            flash("パスワードを入力してください")
            return render_template("register.html")
        if not sub_password:
            flash("パスワードを入力してください")
            return render_template("register.html")
        if main_password != sub_password:
            flash("同じパスワードを入力してください")
            return render_template("register.html")
        # hashの作成
        hash = generate_password_hash(main_password, method="sha512", salt_length=1000)
        new_user = User(email=email, hash=hash)
        
        # usersテーブルに登録
        try:
            db.session.add(new_user)
            db.session.commit()
        # 登録できなかった場合
        except:
            flash("既にuserが存在します")
            return render_template("register.html")

        return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")
    else:
        # userからemailとpasswordを受け取る
        email = request.form.get("email")
        password = request.form.get("password")
        # エラー処理
        if not email:
            flash("メールアドレスを入力してください。")
            return render_template("login.html")        
        if not password:
            flash("パスワードを入力してください。")
            return render_template("login.html")

        # データベースからuserのデータを取得
        user = User.query.filter_by(email=email).first()

        # user が存在しないまたは保存されたhashとpasswordのhashが違う場合
        if not user or not check_password_hash(user.hash, password):
            flash("メールアドレスもしくはパスワードが間違っています。")
            return render_template("login.html")

        login_user(user)
        # sessionにuser_idを保持
        session["user_id"] = user.id
        return redirect(url_for("index"))

# ログアウト機能
@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("index"))

# パスワードの生成
@app.route("/generate")
@login_required
def generate():
    return render_template("generate.html")

# パスワード一覧
@app.route("/passlist", methods=["GET", "POST"])
@login_required
def passlist():
    if request.method == "GET":
        user_id = session["user_id"]
        passlists = Passlist.query.filter_by(user_id=user_id)
        return render_template("passlist.html", passlists=passlists)
    else:
        title = request.form.get("title")
        account = request.form.get("account")
        flag = request.form.get("flag")
        length = request.form.get("length")
        user_id = session["user_id"]
        length = int(length)
        if not length:
            return render_template("generate.html", message="文字数を選択してください")

        if length < 0 or length > 30 or type(length) != int:
            return render_template("generate.html", message="1以上30以下の整数を入力してください")

        if type(title) == int:
            return render_template("generate.html", message="数字以外の文字も含めてください")

        with open('receiver.pem', 'rb') as f:
            public_pem = f.read()
            public_key = RSA.import_key(public_pem)

        generate_pass = get_random_password_string(int(length), flag)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        token = cipher_rsa.encrypt(generate_pass.encode())
        new_pass = Passlist(title=title, account=account, password=token, user_id=user_id)
        db.session.add(new_pass)
        db.commit()
        return redirect(url_for("passlist"))