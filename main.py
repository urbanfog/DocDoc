from flask import Flask, render_template, redirect, url_for, flash, abort, request, send_from_directory, send_file, Response, g
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date, datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import and_, or_, not_
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from werkzeug.utils import secure_filename
from forms import LoginForm, RegisterForm, CreateDocumentForm, SearchForm
import os
import boto3


ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

# AWS setup
AWS_BUCKET_NAME = 'docdoczilla'
UPLOAD_FOLDER = 'uploads'
# AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
# AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024

is_prod = os.environ.get('IS_HEROKU', None)
if is_prod:
    APP_SECRET_KEY = os.getenv('APP_SECRET_KEY')
else:
    from dotenv import load_dotenv, find_dotenv
    load_dotenv(find_dotenv(), override=True)
    APP_SECRET_KEY = os.getenv('APP_SECRET_KEY')

app.config['SECRET_KEY'] = APP_SECRET_KEY
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', "sqlite:///document.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


s3 = boto3.client(
    "s3",
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    documents = db.relationship("Document", backref="created_by")

    def __repr__(self):
        return '<User {}>'.format(self.name)


class Document(db.Model):
    __tablename__ = "documents"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    title = db.Column(db.String(250), unique=True, nullable=False)
    description = db.Column(db.String(250), nullable=False)
    upload_date = db.Column(db.String(250), nullable=False)
    file_url = db.Column(db.String(250), nullable=False)
    tags = db.Column(db.String(250), unique=False, nullable=True)

    def __repr__(self):
        return '<Document {}>'.format(self.title)


# DB seed stuff
db.drop_all()
db.create_all()


# new_user = User(
#     id=1,
#     email='james@james.com',
#     name='james',
#     password='james',
# )

# new_doc = Document(
#     user_id=1,
#     title='Test',
#     description='Test',
#     upload_date=datetime.today(),
#     file_url='coffee.jpg',
#     tags='new'
# )
# db.session.add(new_user)
# db.session.add(new_doc)
# db.session.commit()


@app.before_request
def before_request():
    g.search_form = SearchForm()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


@app.route('/elements')
def elements():
    return render_template("elements.html")

# TODO get search working


@app.route('/', methods=["GET"])
def landing():
    return render_template("landing.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            print(User.query.filter_by(email=form.email.data).first())
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("get_all_documents"))

    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_documents'))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_documents'))


@app.route("/user/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    user = User.query.get(user_id)
    edit_form = RegisterForm(
        name=user.name,
        email=user.email,
        password=user.password,
    )
    if edit_form.validate_on_submit():
        user.name = edit_form.name.data
        user.email = edit_form.email.data
        user.password = edit_form.password.data
        db.session.commit()
        return redirect(url_for("show_user", document_id=user.id))

    return render_template("register.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route('/documents', methods=["GET"])
def get_all_documents():
    documents = Document.query.all()
    print(documents)
    return render_template("index.html", form=g.search_form, documents=documents, current_user=current_user)


@app.route('/search', methods=["GET", "POST"])
def search():
    if g.search_form.validate():
        search_string = g.search_form.query.data
        print(search_string)
        results = Document.query.filter(
            Document.tags.like('%' + search_string + '%'))
        return render_template("index.html", form=g.search_form, documents=results, current_user=current_user)
    print(g.search_form.errors)
    return redirect(url_for("get_all_documents"))


@ app.route("/document/<int:document_id>", methods=["GET", "POST"])
def show_document(document_id):
    requested_document = Document.query.get(document_id)
    return render_template("document.html", document=requested_document, current_user=current_user)


def validate_and_upload(file):
    file.filename = secure_filename(file.filename)
    output = upload_file_to_s3(file, AWS_BUCKET_NAME)
    return str(output)


def upload_file_to_s3(file, bucket_name):
    """
    Docs: http://boto3.readthedocs.io/en/latest/guide/s3.html
    """
    try:
        s3.upload_fileobj(
            file,
            bucket_name,
            file.filename,
            ExtraArgs={
                "ContentType": file.content_type
            }
        )
    except Exception as e:
        print("Something Happened: ", e)
        return e
    return str(file.filename)
    # return f"https://{AWS_BUCKET_NAME}.s3-us-west-2.amazonaws.com/{file.filename}"


@ app.route("/download", methods=['POST'])
def download():
    id = request.form['id']
    document = Document.query.get(id)
    key = document.file_url
    s3_resource = boto3.resource('s3')
    my_bucket = s3_resource.Bucket(AWS_BUCKET_NAME)
    file_obj = my_bucket.Object(key).get()

    return Response(
        file_obj['Body'].read(),
        mimetype='text/plain',
        headers={"Content-Disposition": "attachment;filename={}".format(key)}
    )


@ app.route("/new-document", methods=["GET", "POST"])
@login_required
def add_document():
    form = CreateDocumentForm()
    if request.method == 'POST':
        # check if the post request has the file part
        new_document = Document(
            title=form.title.data,
            description=form.description.data,
            user_id=current_user.id,
            upload_date=date.today().strftime("%B %d, %Y"),
            file_url=validate_and_upload(form.file_url.data),
        )
        db.session.add(new_document)
        db.session.commit()
        return render_template("index.html")

    return render_template("make-document.html", form=form, current_user=current_user)


@ app.route("/edit-document/<int:document_id>", methods=["GET", "POST"])
def edit_document(document_id):
    document = Document.query.get(document_id)
    edit_form = CreateDocumentForm(
        title=document.title,
        description=document.description,
        file_url=document.file_url,
    )
    if edit_form.validate_on_submit():
        document.title = edit_form.title.data
        document.description = edit_form.description.data
        document.file_url = edit_form.file_url.data
        db.session.commit()
        return redirect(url_for("show_document", document_id=document.id))

    return render_template("make-document.html", form=edit_form, is_edit=True, current_user=current_user)


@ app.route("/delete", methods=["POST"])
def delete_document():
    id = request.form['id']
    doc = Document.query.get(id)
    s3_key = doc.file_url
    s3_resource = boto3.resource('s3')
    my_bucket = s3_resource.Bucket(AWS_BUCKET_NAME)
    my_bucket.Object(s3_key).delete()
    db.session.delete(doc)
    db.session.commit()
    flash('File deleted successfully')
    return redirect(url_for('get_all_documents'))


@ app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@ app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
