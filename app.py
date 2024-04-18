import os
from flask import Flask, request, render_template, redirect, url_for, flash, session
from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import desc
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from flask_wtf import CSRFProtect, FlaskForm
from flask_wtf.csrf import generate_csrf
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo, Length
from datetime import datetime
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth

load_dotenv('.env')

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)
auth = LoginManager()
auth.init_app(app)
oauth = OAuth(app)
google = oauth.register(name='google',
                        client_id=os.environ.get('GOOGLE_CLIENT_ID', None),
                        client_secret=os.environ.get('GOOGLE_CLIENT_SECRET', None),
                        access_token_url='https://accounts.google.com/o/oauth2/token',
                        acces_token_params=None,
                        userinfo={
                                    'url': 'https://www.googleapis.com/oauth2/v3/userinfo',
                                    'email': lambda json: json['email'],
                                },
                        scopes=['https://www.googleapis.com/auth/userinfo.email',
                                'https://www.googleapis.com/auth/userinfo.profile'],
                        authorize_url='https://accounts.google.com/o/oauth2/auth',
                        authorize_params=None,
                        api_base_url='https://www.googleapis.com/oauth2/v1/',
                        client_kwargs={'scope': 'profile email'})


from models.Todo import Todo
from models.User import User


with app.app_context():
    db.create_all()


@auth.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def email_exists(email):
    user = User.query.filter_by(email=email).first()
    return user is not None


@auth.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for('login'))


class AddEditTodoForm(FlaskForm):
    content = StringField('content', validators=[DataRequired(), Length(min=1, max=1000,
                                                                        message='Todo too short/long')])


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    form = AddEditTodoForm()
    if form.validate_on_submit():
        new_todo = Todo(content=request.form.get('content'), user_id=current_user.id)
        db.session.add(new_todo)
        db.session.commit()
        return redirect(url_for('index'))

    todos = Todo.query.filter_by(user_id=current_user.id).order_by(desc('created_at')).all()
    return render_template('index.html', todos=todos)


@app.route('/edit/<int:todo_id>', methods=['GET', 'POST'])
@login_required
def edit_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)

    if todo.user_id != current_user.id and not current_user.is_admin:
        return 'Access Denied, Invalid user', 403

    form = AddEditTodoForm()
    if form.validate_on_submit():
        try:
            todo.content = request.form.get('content')
            todo.updated_at = datetime.now()
            db.session.commit()
            flash('Todo item successfully updated.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            return e

    return render_template('edit.html', todo=todo)


@app.route('/toggle_completed/<int:todo_id>', methods=['GET'])
@login_required
def toggle_completed(todo_id):
    todo = Todo.query.get_or_404(todo_id)

    if todo.user_id != current_user.id and not current_user.is_admin:
        return 'Access Denied, Invalid user', 403

    todo.completed = not todo.completed
    todo.updated_at = datetime.now()
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/delete_todo/<int:todo_id>', methods=['GET'])
@login_required
def delete_todo(todo_id):
    todo = Todo.query.get_or_404(todo_id)

    if todo.user_id != current_user.id and not current_user.is_admin:
        return 'Access Denied, Invalid user', 403

    db.session.delete(todo)
    db.session.commit()

    flash('Todo item successfully deleted', 'success')
    return redirect(url_for('index'))


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    flash('User logged out', 'success')
    return redirect(url_for('index'))


class RegisterForm(FlaskForm):
    first_name = StringField('first_name')
    last_name = StringField('last_name')
    email = StringField('email', validators=[DataRequired(), Email(), Length(8, 50,
                                                        message='Invalid email')])
    password = PasswordField('password', validators=[DataRequired(), Length(8, 50,
                                                        message='Password must be at least 8 characters long')])
    confirm_password = PasswordField('confirm_password', validators=[EqualTo('password',
                                                                             message='Passwords must match')])


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if email_exists(form.email.data):
            # save form values to repopulate form after redirection
            for field in ['first_name', 'last_name', 'email']:
                session[field] = request.form.get(field, '')

            flash('User already registered with that email', 'error')
            return redirect(url_for('register'))

        user = User()
        user.email = form.email.data
        user.first_name = form.first_name.data,
        user.last_name = form.last_name.data,
        user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')

        db.session.add(user)
        db.session.commit()

        flash('User registered!', 'success')

        for field in ['first_name', 'last_name', 'email']:
            session.pop(field, None)

        return redirect(url_for('index'))

    return render_template('register.html', form=form)


class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired(),])


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        session['email'] = form.email.data

        if not user:
            flash('User not found', 'error')
            return redirect(request.referrer)

        if not bcrypt.check_password_hash(user.password, form.password.data):
            flash('Incorrect password', 'error')
            return redirect(request.referrer)

        session.pop('email', None)

        login_user(user)

        return redirect(url_for('index'))

    return render_template('login.html', form=form)


@app.route('/login/google', methods=['GET'])
def google_login():
    if not current_user.is_anonymous:
        return redirect(url_for('index'))

    redirect_uri = url_for('callback_google', _external=True)
    session['state'] = generate_csrf(token_key=app.secret_key)
    app.logger.info(redirect_uri)
    app.logger.info(session['state'])
    return google.authorize_redirect(redirect_uri=redirect_uri, state=session['state'])  # client_id=google.client_id


@app.route('/callback/google', methods=['GET', 'POST'])
def callback_google():
    if not current_user.is_anonymous:
        return redirect(url_for('index'))

    if 'error' in request.args:
        return request.args['error'], 502

    if 'state' not in request.args:
        return 'Missing OAuth2 state', 502

    if request.args['state'] != session.get('state', None):
        return 'Invalid OAuth2 state token returned', 502

    # clear the state token session
    session.pop('state', None)

    token_json = google.authorize_access_token()
    if not token_json:
        return 'OAuth2 token missing', 502

    user_info = google.get('userinfo').json()  # https://www.googleapis.com/auth/userinfo.profile
    # app.logger.info(user_info)
    # {
    #     "email": "some.body@gmail.com",
    #     "family_name": "Body",
    #     "given_name": "Some",
    #     "id": "114337532535424235046",
    #     "locale": "en",
    #     "name": "Some Body",
    #     "picture": "https://lh3.googleusercontent.com/a/ACf8ocJ3h45Vj-k2h8tsAd66F6A3iZoeIO31dV4ce_RKVzRcqQ3QrA=s96-c",
    #     "verified_email": true
    # }

    # find the user in the database
    user = User.query.filter_by(email=user_info['email']).first()

    # if the user is already registered through the normal path prevent them registering again
    if user and user.password is not None:
        flash('You are already registered using this email', 'error')
        return redirect(url_for('login'))

    # create a new user, password=null
    if not user:
        user = User()
        user.email = user_info.get('email')
        user.first_name = user_info.get('given_name')
        user.last_name = user_info.get('family_name')
        db.session.add(user)
        db.session.commit()

    login_user(user, remember=True)

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
