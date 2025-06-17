# Password Manager CLI Tool

## Description
A local command line password manager that securely stores passwords for applications.


## Features
- User account creation and secure data storage and management using PostgreSQL and SQLAlchemy
- Password hashing using argon2 for user authentication
- Secure password encryption and decryption of stored passwords using Fernet




## Installation and Usage Instructions



### Installation and Setup:
- Download the Zip File from the Password CLI Repository
- Once installed on local machine, run `pip install .` to install the tool's dependencies from the setup.py file.
- Start up your postgreSQL server in order to create the demo database
- Connect to the default postgres database using `psql -d postgres`
- Create a user in PostgreSQL using the credentials provided in the .env file's database URI with the following command `CREATE USER demo_user WITH PASSWORD 'demo_password';`
- Create the database and declare the demo user owner privileges:
 `CREATE DATABASE passwordclidb OWNER demo_user;`
- Use the tool with `password-cli <command>` 


### Commands:
- `password-cli init-acc ` - Creates a new user account and master password for viewing passwords securely
- `password-cli login` - Logs in to an existing account
- `password-cli add-password` - Requests to add a new password to store
- `password-cli request-password` - Request to view a stored password
- `password-cli show-passwords-list` - Request to show the full list of stored passwords 
- `password-cli logout` - Logout and session clearing
- `password-cli delete-password` - Delete a stored password from the passwords list
- `password-cli delete-account` - Request to delete personal user account and clear account data


## Technologies Used:
- Python
- Flask
- PostgreSQL
- SQLAlchemy
- Cryptography(Fernet for encryption and decryption)
- Argon2(Password hashing)
- Click




