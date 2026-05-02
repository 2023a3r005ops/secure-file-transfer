from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    storage_used = db.Column(db.Integer, default=0)       # bytes used
    storage_limit = db.Column(db.Integer, default=100*1024*1024)  # 100MB limit
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    files = db.relationship("File", backref="owner", lazy=True, foreign_keys="File.user_id")

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    stored_name = db.Column(db.String(200), nullable=False)
    file_size = db.Column(db.Integer)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)     # auto delete date
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    is_deleted = db.Column(db.Boolean, default=False)

class SharedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("file.id"), nullable=False)
    shared_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    shared_with = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    shared_at = db.Column(db.DateTime, default=datetime.utcnow)
    can_download = db.Column(db.Boolean, default=True)
    file = db.relationship("File", foreign_keys=[file_id])
    sharer = db.relationship("User", foreign_keys=[shared_by])
    receiver = db.relationship("User", foreign_keys=[shared_with])

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    action = db.Column(db.String(100))
    filename = db.Column(db.String(200))
    ip_address = db.Column(db.String(50))
    device_info = db.Column(db.String(300))    # browser/device
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)
    extra = db.Column(db.String(500))          # extra info e.g. shared_with

class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    ip_address = db.Column(db.String(50))
    device_info = db.Column(db.String(300))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)
    location = db.Column(db.String(200))
