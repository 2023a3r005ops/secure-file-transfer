import bcrypt
from flask_jwt_extended import create_access_token
from models import User, db

def hash_password(plain_password: str) -> str:
    """Hash password using bcrypt with automatic salt."""
    salt = bcrypt.gensalt(rounds=12)  # Higher rounds = slower brute force
    return bcrypt.hashpw(plain_password.encode(), salt).decode()

def verify_password(plain_password: str, hashed: str) -> bool:
    """Verify a password against its bcrypt hash."""
    return bcrypt.checkpw(plain_password.encode(), hashed.encode())

def register_user(username: str, password: str):
    """Create a new user. Returns (user, error)."""
    if User.query.filter_by(username=username).first():
        return None, "Username already exists"

    if len(password) < 8:
        return None, "Password must be at least 8 characters"

    user = User(
        username=username,
        password_hash=hash_password(password)
    )
    db.session.add(user)
    db.session.commit()
    return user, None

def login_user(username: str, password: str):
    """Authenticate user. Returns (jwt_token, error)."""
    user = User.query.filter_by(username=username).first()

    if not user or not verify_password(password, user.password_hash):
        return None, "Invalid username or password"

    # Generate JWT token — expires in 1 hour
    token = create_access_token(identity=str(user.id))
    return token, None