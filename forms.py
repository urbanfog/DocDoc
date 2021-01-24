from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL


# WTForm
class CreateDocumentForm(FlaskForm):
    title = StringField("Document Title", validators=[DataRequired()])
    description = StringField("Description", validators=[DataRequired()])
    file_url = FileField("Document", validators=[FileRequired()])
    submit = SubmitField("Add Document")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")


class SearchForm(FlaskForm):
    search_query = StringField("Search", validators=[DataRequired()])
