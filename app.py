from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import dotenv
import os
import click
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from sqlalchemy.exc import IntegrityError
from argon2.exceptions import VerifyMismatchError
import base64
from flask.cli import FlaskGroup


dotenv.load_dotenv()
cipher_key = Fernet.generate_key()

key = os.getenv('CIPHER_KEY')
cipher = Fernet(key)







app = Flask(__name__)
cli = FlaskGroup(app)

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
   is_deleted = db.Column(db.Boolean, nullable=False, default=False)
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.Text, nullable=False)
    encrypted_password = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)


with app.app_context():
    db.create_all()

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
                with open(session_file, "w") as file:
                    file.write(str(new_user.id))
               
                
                click.echo("Account has been initialized")
        
            except IntegrityError:
                click.echo("Username already exists")
                return
        else:
            click.echo("Passwords do not match")
            return
    else:
        click.echo("Please enter a password")
        return
    

        


@app.cli.command('login')
def login():

    username = click.prompt("Username")
    password = click.prompt("Password", hide_input=True)
    if username and password:
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            if existing_user.is_deleted == False:
                try:
                    ph.verify(existing_user.hashed_password, password)
                except VerifyMismatchError:
                    click.echo("Credentials are Incorrect")
                    return
                with open(session_file, "w") as file:
                    file.write(str(existing_user.id))
                click.echo(f"You are logged in {existing_user.username}")
            else:
                click.echo("User Not Found.")
                return
                return
        else:
            click.echo("User Not Found")
            return
    else:
        click.echo("Please enter a valid username and password")
        return






@app.cli.command('add-password')
def add_password():
    
    app_name = click.prompt('Application Name ').lower()
    password = click.prompt("Application Password ", hide_input=True)
    with open(session_file, "r") as file:
        user_id_str = file.read().strip()
    if user_id_str != "":
        user_id = int(user_id_str)
    
    
        encrypted_password = cipher.encrypt(password.encode('utf-8'))
        encrypted_b64 = base64.b64encode(encrypted_password).decode('utf-8')


        new_password = Password(app_name=app_name, encrypted_password=encrypted_b64, user_id=user_id)
        db.session.add(new_password)
        db.session.commit()

        click.echo("Password has been saved.")
    else:
        click.echo("Please Log In.")
        return
   



@app.cli.command('request-password')
def request_password():
    
    requested_app = click.prompt("Requested Application ").lower()
    master_password = click.prompt("Master Password", hide_input=True)
    with open(session_file, "r") as file:
        user_id_str = file.read().strip()
        


    if user_id_str != "":        
        user_id = int(user_id_str)
    
        
    
        existing_user = User.query.filter_by(id=user_id).first()
        if existing_user:
            try:
                ph.verify(existing_user.hashed_password, master_password)
            except VerifyMismatchError:
                click.echo("Password is Incorrect.")
            user_passwords = Password.query.filter_by(user_id=existing_user.id, app_name=requested_app).all()
            if user_passwords:
                for password in user_passwords:
                    encrypted_password = password.encrypted_password
                    decrypted_b64 = base64.b64decode(encrypted_password)
                    decrypted_bytes = cipher.decrypt(decrypted_b64)

                    decrypted_password = decrypted_bytes.decode('utf-8')
                    click.echo(f"{password.app_name}: {decrypted_password}")
        else:
            click.echo("User not found.")
    else:
        click.echo("Please Log In.")

        

@app.cli.command('show-passwords-list')
def show_passwords_list():

    with open(session_file, "r") as file:
        user_id_str = file.read().strip()
        
    if user_id_str != "":
        user_id = int(user_id_str)
       
        existing_user = User.query.filter_by(id=user_id).first()
        if existing_user:
            verify_username = click.prompt("Username")
            verify_password = click.prompt("Password", hide_input=True)
            if existing_user.username == verify_username:
                try:
                    ph.verify(existing_user.hashed_password, verify_password)
                except VerifyMismatchError:
                    click.echo("Incorrect Credentials")
                    return
                user_passwords = Password.query.filter_by(user_id=user_id).all()
                for password in user_passwords:
                    encrypted_password = password.encrypted_password
                        
                    decrypted_b64 = base64.b64decode(encrypted_password)
                    decrypted_bytes = cipher.decrypt(decrypted_b64)

                    decrypted_password = decrypted_bytes.decode('utf-8')
                    click.echo(f"{password.app_name}: {decrypted_password}")
            


                
            else:
             
                click.echo("Incorrect Credentials")
                return
        else:
            click.echo("User not found.")
            return
    else:
        click.echo("Please Log In.")
        

@app.cli.command('logout')
def logout():

    with open(session_file, "w") as file:
        file.write("")

    click.echo("You have successfully logged out!")

@app.cli.command('delete-password')
def delete_password():

    with open(session_file, "r") as file:
       user_id_str = file.read().strip()
    if user_id_str != "":
        user_id = int(user_id_str)
        existing_user = User.query.filter_by(id=user_id).first()
        deleted_app = click.prompt("Application Password to Delete").lower()
        master_password = click.prompt("Master Password")
        if existing_user:
            try: 
                ph.verify(existing_user.hashed_password, master_password)
            except VerifyMismatchError:
                click.echo("Incorrect Password")
                return
            deleted_password = Password.query.filter_by(app_name=deleted_app).all()
            for password in deleted_password:
                
                db.session.delete(password)
                db.session.commit()
                click.echo(f"The password for {deleted_app} has been deleted.")
        else:
            click.echo("User not found.")
            return
    else:
        click.echo("Please Log In.")
     
@app.cli.command("delete-account")
def delete_account():

    with open(session_file, "r") as file:
        user_id_str = file.read().strip()
    if user_id_str != "":

        user_id = int(user_id_str)
        deleted_user = User.query.filter_by(id=user_id).first()
        click.echo(" Please enter your login credentials to confirm account deletion. Please note, this action is final and cannot be undone.")
        username = click.prompt("Username")
        password = click.prompt("Password ", hide_input=True)
        if deleted_user:
            if deleted_user.username == username:
                try:
                    ph.verify(deleted_user.hashed_password, password)
                except VerifyMismatchError:
                    click.echo("Incorrect Credentials")
                    return
                deleted_passwords = Password.query.filter_by(user_id=deleted_user.id).all()
                if deleted_passwords:
                    for password in deleted_passwords:
                        db.session.delete(password)
                        db.session.commit()
                deleted_user.is_deleted = True
                db.session.commit()
                click.echo("Your accoount has been deleted.")
            else:
                click.echo("Incorrect Credentials.")
        else:
            click.echo("Incorrect Credentials")
            return
    else: 
        click.echo("Please Log In.")


if __name__ == '__main__':
    cli()
    
    

        











