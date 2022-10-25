from flask import Flask, render_template, redirect, url_for, flash, request, abort, session
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from urllib.parse import urlparse, urljoin
from datetime import timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app, session_options={"autoflush": False})

login_manager = LoginManager()
login_manager.init_app(app)

Base = declarative_base()

##CONFIGURE TABLES
# with app.app_context():

class User(UserMixin, db.Model, Base):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")

class BlogPost(db.Model, Base):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="post")

class Comment(db.Model, Base):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    post = relationship("BlogPost", back_populates="comments")

    # db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=int(user_id)).first()

def logged_check():
    if current_user.is_authenticated:
        return True
    else:
        return False

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and \
           ref_url.netloc == test_url.netloc


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=logged_check())


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_2_login = User.query.filter_by(email=form.email.data).first()
        if not user_2_login:
            flash("User Email does not exist. Please try again.")
            return render_template("login.html", form=form, logged_in=logged_check())
        if check_password_hash(pwhash=user_2_login.password, password=form.password.data):
            login_user(user_2_login)
            flash("logged in successfuly.")
        else:
            flash("Wrong Password. Please try again.")
            return render_template("login.html", form=form, logged_in=logged_check())

        next = request.args.get('next')
        if not is_safe_url(next):
            return abort(400)

        posts = BlogPost.query.all()
        return render_template("index.html", all_posts=posts, logged_in=logged_check())
    return render_template("login.html", form=form, logged_in=logged_check())


@app.route('/logout')
def logout():
    logout_user()
    flash("logged out successfuly.")
    return redirect((url_for('get_all_posts')))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        new_comment = Comment(
            body=form.body.data,
            author_id=current_user.id,
            post_id=requested_post.id
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, logged_in=logged_check(), form=form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=logged_check())


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=logged_check())


@app.route("/new-post", methods=["POST", "GET"])
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=logged_check())


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user.name
        post.body = edit_form.body.data
        db.session.commit()
        return render_template("post.html", post=post, logged_in=logged_check())

    return render_template("make-post.html", form=edit_form, logged_in=logged_check())


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/register", methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            name=form.name.data,
            email=form.email.data,
            password=hashed_password
        )
        if bool(User.query.filter_by(email=new_user.email).first()):
            flash("This Email is already registered.")
            return render_template("register.html", form=form, logged_in=logged_check())
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        posts = BlogPost.query.all()
        return render_template("index.html", all_posts=posts, logged_in=logged_check())
    return render_template("register.html", form=form, logged_in=logged_check())

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001)
