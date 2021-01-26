from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired


# WTForm
class CreateDocumentForm(FlaskForm):
    title = StringField("Document Title", validators=[DataRequired()])
    description = StringField("Description", validators=[DataRequired()])
    file_url = FileField("Document", validators=[FileRequired()])
    tags = StringField("Tags", validators=[DataRequired()])
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
    query = StringField("Search", validators=[DataRequired()], render_kw={
        "placeholder": "Search", "id": "query", "type": "text"})
    submit = SubmitField("Search")
