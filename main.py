from flask import Flask, render_template, redirect, url_for, flash, abort, request, send_from_directory
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
from forms import FileUploadForm, LoginForm, RegisterForm, CreateDocumentForm, SearchForm
import os

# TODO
# Search doc attributes

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 4 * 1024 * 1024

is_prod = os.environ.get('IS_HEROKU', None)
if is_prod:
    API_SECRET_KEY = os.getenv('API_SECRET_KEY')
else:
    from dotenv import load_dotenv, find_dotenv
    load_dotenv(find_dotenv(), override=True)
    API_SECRET_KEY = os.getenv('APP_SECRET_KEY')

app.config['SECRET_KEY'] = API_SECRET_KEY
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


# CONFIGURE TABLE
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    documents = relationship("Document", back_populates="created_by")


class Document(db.Model):
    __tablename__ = "documents"
    id = db.Column(db.Integer, primary_key=True)
    create_user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    created_by = relationship("User", back_populates="documents")
    title = db.Column(db.String(250), unique=True, nullable=False)
    description = db.Column(db.String(250), nullable=False)
    upload_date = db.Column(db.String(250), nullable=False)
    file_url = db.Column(db.String(250), nullable=False)


# DB seed stuff
# db.drop_all()
# db.create_all()

# new_user = User(
#     id=1,
#     email='Test',
#     name='Admin',
#     password='Test',
# )

# new_doc = Document(
#     create_user_id=1,
#     title='Test',
#     description='Test',
#     upload_date=datetime.today(),
#     file_url='wwww.google.com',
# )
# db.session.add(new_user)
# db.session.add(new_doc)
# db.session.commit()


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
    form = SearchForm()
    if form.validate():
        search_string = form.search_query.data
        results = Document.query.filter(
            # or_(
            # Document.title.like(f"%search_string%"),
            Document.description.like('%' + search_string + '%'),
            # )
        )
        print(search_string)
        print(results)
        return redirect(url_for("get_all_documents", results=results))
    print(form.errors)
    return render_template("landing.html", form=form)


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


@app.route('/documents')
def get_all_documents():
    documents = Document.query.all()
    return render_template("index.html", all_documents=documents, current_user=current_user)


@app.route("/document/<int:document_id>", methods=["GET", "POST"])
def show_document(document_id):
    requested_document = Document.query.get(document_id)
    return render_template("document.html", document=requested_document, current_user=current_user)


@app.route("/new-document", methods=["GET", "POST"])
def add_document():
    form = CreateDocumentForm()
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(MYDIR + "/" +
                      app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('uploaded_file',
                                    filename=filename))
    return

    if form.validate_on_submit():
        new_document = Document(
            title=form.title.data,
            description=form.description.data,
            file_url=form.file_url.data,
            create_user_id=current_user,
            upload_date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_document)
        db.session.commit()
        return redirect(url_for("get_all_documents"))

    return render_template("make-document.html", form=form, current_user=current_user)


@app.route("/edit-document/<int:document_id>", methods=["GET", "POST"])
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


@app.route("/delete/<int:document_id>")
@admin_only
def delete_document(document_id):
    document_to_delete = Document.query.get(document_id)
    db.session.delete(document_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_documents'))


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)


@app.route("/contact")
def contact():
    return render_template("contact.html", current_user=current_user)


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/', methods=['GET', 'POST'])
def upload_file():


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(os.path.join(MYDIR + "/" + app.config['UPLOAD_FOLDER'],
                               filename)


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
