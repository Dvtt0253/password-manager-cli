from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import dotenv
import os
import click
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from sqlalchemy.exc import IntegrityError
from argon2.exceptions import VerifyMismatchError


cipher_key = Fernet.generate_key()
cipher = Fernet(cipher_key)




dotenv.load_dotenv()


app = Flask(__name__)

session_file = os.path.expanduser("~/.cli_sessions")
os.makedirs(os.path.dirname(session_file), exist_ok=True)

ph = PasswordHasher()

database_uri = os.getenv('DATABASE_URI')

app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(db.Model):
   id = db.Column(db.Integer, primary_key=True)
   username = db.Column(db.Text, nullable=False, unique=True)
   hashed_password = db.Column(db.String(300), nullable=False)
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.Text, nullable=False)
    encrypted_password = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)


with app.app_context():
    db.create_all()
current_userid = None
@app.cli.command('init-acc')
def set_password():
    username = click.prompt("Create a Username")
    password  = click.prompt("Create a Master Password", hide_input=True)
    confirm_password = click.prompt("Confirm password", hide_input=True)
   
    if password:
        if password == confirm_password:
            password = ph.hash(password)
            try:
        
        
                new_user = User(username=username,hashed_password = password)
                db.session.add(new_user)
                db.session.commit()
                global current_userid
                current_userid = new_user.id
                
                click.echo("Master password has been initialized")
        
            except IntegrityError:
                click.echo("Username already exists")
        else:
            click.echo("Passwords do not match")
    else:
        click.echo("Please enter a password")
    

        


@app.cli.command('login')
def login():

    username = click.prompt("Username:")
    password = click.prompt("Password", hide_input=True)
    if username and password:
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            try:
                ph.verify(existing_user.hashed_password, password)
            except VerifyMismatchError:
                click.echo("Credentials Incorrect")
            global current_userid
            current_userid = existing_user.id
            click.echo(f"You are logged in {existing_user.username}")
        else:
            click.echo("User Not Found")
    else:
        click.echo("Please enter a valid username and password")






@app.cli.command('add-password')
def add_password():
    global current_userid
    app_name = click.prompt('Application Name: ')
    password = click.prompt("Application Password: ", hide_input=True)
    user_id = current_userid
    encrypted_password = cipher.encrypt(password.encode('utf-8'))

    new_password = Password(app_name=app_name, encrypted_password=encrypted_password, user_id=user_id)
    db.session.add(new_password)
    db.session.commit()

    click.echo("Password has been saved.")



@app.cli.command('request-password')
def request_password():
    global current_userid
    requested_app = click.prompt("Requested Application: ")
    master_password = click.prompt("Master Password:", hide_input=True)
    existing_user = User.query.filter_by(id=current_userid).first()
    if existing_user:
        try:
            ph.verify(existing_user.hashed_password, master_password)
        except VerifyMismatchError:
            click.echo("Password is Incorrect.")
        user_passwords = Password.query.filter_by(user_id=existing_user.id, app_name=requested_app).all()
        if user_passwords:
            for password in user_passwords:
                decrypted_password = cipher.decrypt(password.encrypted_password.decode('utf-8'))
                cipher.echo(f"{password.app_name}: {decrypted_password}")
        











