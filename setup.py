from setuptools import setup

setup(
    name='password-cli',
    version='0.1',
    py_modules=['app'], 
    install_requires=[
        'Flask',
        'click',
        'cryptography',
        'python-dotenv',
        'SQLAlchemy',
        'argon2-cffi',
    ],
    entry_points={
        'console_scripts': [
            'password-cli=app:cli',
        ],
    },
)