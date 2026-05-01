import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # JWT secret — keep this in .env, never hardcode!
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "change-this-in-production")
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour

    # AES encryption key (32 bytes = AES-256)
    AES_KEY = b"thisis32byteslongaeskeymustbe32!"

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///secure_files.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # File storage
    UPLOAD_FOLDER = r"C:\Secure File Transfer System (Encryption + Authentication)\server\uploads"
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB limit