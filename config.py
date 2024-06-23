import os
from dotenv import load_dotenv
from pydantic import EmailStr
from pathlib import Path
from typing import Optional

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:kseni4ka78@localhost/rest_app")
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))
CLOUDINARY_URL = os.getenv("CLOUDINARY_URL", "")

# Ваші дані для електронної пошти із .env
MAIL_USERNAME = os.getenv("MAIL_USERNAME", "your-email@example.com")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "your-email-password")
MAIL_FROM = os.getenv("MAIL_FROM", "your-email@example.com")
MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
MAIL_SERVER = os.getenv("MAIL_SERVER", "smtp.example.com")
MAIL_TLS = os.getenv("MAIL_TLS", 'True').lower() == 'true'
MAIL_SSL = os.getenv("MAIL_SSL", 'False').lower() == 'true'

MAIL_CONFIG = {
    "MAIL_USERNAME": MAIL_USERNAME,
    "MAIL_PASSWORD": MAIL_PASSWORD,
    "MAIL_FROM": MAIL_FROM,
    "MAIL_PORT": MAIL_PORT,
    "MAIL_SERVER": MAIL_SERVER,
    "MAIL_TLS": MAIL_TLS,
    "MAIL_SSL": MAIL_SSL,
    "USE_CREDENTIALS": True
}

TEMPLATE_FOLDER = Path(__file__).parent / 'templates'


class Settings:
    def __init__(self):
        self.DATABASE_URL = DATABASE_URL
        self.SECRET_KEY = SECRET_KEY
        self.ALGORITHM = ALGORITHM
        self.ACCESS_TOKEN_EXPIRE_MINUTES = ACCESS_TOKEN_EXPIRE_MINUTES
        self.REFRESH_TOKEN_EXPIRE_DAYS = REFRESH_TOKEN_EXPIRE_DAYS
        self.MAIL_USERNAME = MAIL_USERNAME
        self.MAIL_PASSWORD = MAIL_PASSWORD
        self.MAIL_FROM = MAIL_FROM
        self.MAIL_PORT = MAIL_PORT
        self.MAIL_SERVER = MAIL_SERVER
        self.MAIL_TLS = MAIL_TLS
        self.MAIL_SSL = MAIL_SSL
        self.CLOUDINARY_URL = CLOUDINARY_URL

settings = Settings()