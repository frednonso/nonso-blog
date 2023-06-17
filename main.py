from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
#from datetime import date
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps



app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
#Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

#gravatar
gravatar = Gravatar(app, size=100, rating='g', default='retro',
                    force_default=False, force_lower=False, use_ssl=False, base_url=None)

login_manager = LoginManager()

login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

#db.create_all()

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # ***************Parent Relationship*************#
    blog_comments = relationship("Comment", back_populates="parent_post")


#db.create_all()

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    parent_post = relationship("BlogPost", back_populates="blog_comments")
    comment_author = relationship("User", back_populates="comments")

    # ***************Child Relationship*************#
    #post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    #parent_post = relationship("BlogPost", back_populates="blog_comments")
    text = db.Column(db.Text, nullable=False)


#db.create_all()


#create admin decorator
def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.id == 1:
            return function(*args, **kwargs)
        else:
            return abort(403)

    return wrapper_function




@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, user=current_user)




@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if user is None:
            hashed_and_salted_password = generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)
            new_user = User(email=form.email.data,
                            password=hashed_and_salted_password,
                            name=form.name.data)

            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for("get_all_posts"))

        elif user is not None:
            flash("You've already signed up with that email,log in instead.")
            return redirect(url_for("login"))




    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        un_hashed_password = form.password.data

        #find user from database
        user = User.query.filter_by(email=email).first()

        if user is None:
            flash("That email does not exist,please try again.")
            return redirect(url_for("login"))
        #log in user if password correct
        elif check_password_hash(pwhash=user.password, password=un_hashed_password) is True:
            login_user(user)

            return redirect(url_for("get_all_posts"))
        #flash message if password incorrect
        elif check_password_hash(pwhash=user.password, password=un_hashed_password) is False:
            flash("Password incorrect,please try again.")
            return redirect(url_for("login"))


    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)



@app.route('/logout')
def logout():
    logout_user()

    return redirect(url_for('get_all_posts'))


@app.route("/post", methods=["GET", "POST"])
def show_post():
    form = CommentForm()
    post_id = request.args.get("post_id")
    requested_post = BlogPost.query.get(post_id)



    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(text=form.comment.data,
                                  comment_author=current_user,
                                  parent_post=requested_post,
                                  )
            db.session.add(new_comment)
            db.session.commit()

            the_id = request.form["id"]
            comments = Comment.query.all()
            number_of_comments = len(comments)

            comment = Comment.query.get(number_of_comments)
            comment.post_id = the_id
            db.session.commit()
            return redirect(url_for("get_all_posts"))

        elif current_user.is_authenticated is False:
            flash("You need to login or register to comment")
            return redirect(url_for("login"))

    return render_template("post.html", post=requested_post, user=current_user, form=form)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        today_date = datetime.datetime.now()
        month = today_date.strftime("%B")
        day = today_date.day
        year = today_date.strftime("%Y")

        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=f"{month} {day}, {year}"
        )
        db.session.add(new_post)
        db.session.commit()

        return redirect(url_for("get_all_posts"))

    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
