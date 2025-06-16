# Password Manager CLI Tool

## Description
A local command line password manager that securely stores passwords for entered applications.


## Features
- User account creation and secure data storage and management using PostgreSQL and SQLAlchemy
- Password hashing for user authentication
- Secure password encryption and decryption of stored passwords using Fernet




## Installation and Usage Instructions



### Installation:
- Download the Zip File from the Password CLI Repository
- Once installed on local machine, run `pip install .` to install the tool's dependencies from the setup.py file.
- Use the tool using `password-cli <command>` 


### Commands:
- `password-cli init-acc ` - Creates a new user account and master password for viewing passwords securely
- `password-cli login` - Logs in to an existing account
- `password-cli add-password` - Add a new password to store
- `password-cli request-password` - Request to view a stored password
- `password-cli show-passwords-list` - Request to show full list of stored passwords 
- `password-cli logout` - Logout and session clearing
- `password-cli delete-password` - Delete a stored password from the passwords list
- `password-cli delete-account` - Request to delete account and clear account data


## Technologies Used:
- Python
- Flask
- PostgreSQL
- SQLAlchemy
- Cryptography(Fernet for encryption and decryption)
- Argon2(Password hashing)
- Click




