from flask import Flask, request, jsonify, send_file
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from flask_cors import CORS
from config import Config
from models import db, User, File, SharedFile, AuditLog, LoginHistory
from auth import register_user, login_user
from encryption import encrypt_file, decrypt_file
import os, uuid, io
from functools import wraps
from collections import defaultdict
import time
from datetime import datetime, timedelta

app = Flask(__name__)
app.config.from_object(Config)
CORS(app, resources={r"/*": {"origins": "*"}})

db.init_app(app)
jwt = JWTManager(app)

os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

# ── Rate limiter ──
request_counts = defaultdict(list)

def rate_limit(max_requests=10, window=60):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            request_counts[ip] = [t for t in request_counts[ip] if now - t < window]
            if len(request_counts[ip]) >= max_requests:
                return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
            request_counts[ip].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def get_device_info():
    return request.headers.get('User-Agent', 'Unknown')[:300]

def log_action(user_id, action, filename=None, success=True, extra=None):
    entry = AuditLog(
        user_id=user_id,
        action=action,
        filename=filename,
        ip_address=request.remote_addr,
        device_info=get_device_info(),
        success=success,
        extra=extra
    )
    db.session.add(entry)
    db.session.commit()

def delete_expired_files():
    now = datetime.utcnow()
    expired = File.query.filter(
        File.expires_at != None,
        File.expires_at <= now,
        File.is_deleted == False
    ).all()
    for f in expired:
        path = os.path.join(Config.UPLOAD_FOLDER, f.stored_name)
        if os.path.exists(path):
            os.remove(path)
        user = User.query.get(f.user_id)
        if user:
            user.storage_used = max(0, user.storage_used - (f.file_size or 0))
        f.is_deleted = True
    if expired:
        db.session.commit()

# ── REGISTER ──
@app.route("/register", methods=["POST"])
@rate_limit(max_requests=5, window=300)
def register():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    user, error = register_user(username, password)
    if error:
        return jsonify({"error": error}), 400
    return jsonify({"message": f"User '{username}' registered successfully"}), 201

# ── LOGIN ──
@app.route("/login", methods=["POST"])
@rate_limit(max_requests=10, window=60)
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")
    user = User.query.filter_by(username=username).first()

    # Check if account is locked
    if user and user.locked_until and user.locked_until > datetime.utcnow():
        remaining = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
        return jsonify({"error": f"Account locked. Try again in {remaining} minutes."}), 403

    token, error = login_user(username, password)

    # Track login history
    history = LoginHistory(
        user_id=user.id if user else None,
        ip_address=request.remote_addr,
        device_info=get_device_info(),
        success=token is not None
    )
    db.session.add(history)

    if error:
        if user:
            user.failed_attempts += 1
            # Lock after 5 failed attempts for 30 minutes
            if user.failed_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=30)
                db.session.commit()
                return jsonify({"error": "Too many failed attempts. Account locked for 30 minutes."}), 403
        db.session.commit()
        log_action(user.id if user else None, "login_failed", success=False)
        return jsonify({"error": error}), 401

    # Reset failed attempts on success
    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()
    log_action(user.id, "login")
    return jsonify({"token": token, "message": "Login successful"}), 200

# ── UPLOAD ──
@app.route("/upload", methods=["POST"])
@jwt_required()
@rate_limit(max_requests=20, window=60)
def upload_file():
    delete_expired_files()
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # Get expiry days from request (optional)
    expiry_days = request.form.get("expiry_days", type=int)

    file_data = file.read()
    file_size = len(file_data)

    # Check storage limit
    if user.storage_used + file_size > user.storage_limit:
        used_mb = user.storage_used / (1024*1024)
        limit_mb = user.storage_limit / (1024*1024)
        return jsonify({"error": f"Storage limit exceeded. Used: {used_mb:.1f}MB / {limit_mb:.0f}MB"}), 400

    original_name = file.filename
    encrypted_data = encrypt_file(file_data, Config.AES_KEY)
    stored_name = str(uuid.uuid4()) + ".enc"
    file_path = os.path.join(Config.UPLOAD_FOLDER, stored_name)

    with open(file_path, "wb") as f:
        f.write(encrypted_data)

    # Set expiry if provided
    expires_at = None
    if expiry_days and expiry_days > 0:
        expires_at = datetime.utcnow() + timedelta(days=expiry_days)

    file_record = File(
        filename=original_name,
        stored_name=stored_name,
        file_size=file_size,
        user_id=user_id,
        expires_at=expires_at
    )
    db.session.add(file_record)

    # Update storage used
    user.storage_used += file_size
    db.session.commit()

    log_action(user_id, "upload", original_name)
    return jsonify({
        "message": "File uploaded and encrypted successfully",
        "file_id": file_record.id,
        "filename": original_name,
        "expires_at": expires_at.isoformat() if expires_at else None
    }), 201

# ── LIST FILES ──
@app.route("/files", methods=["GET"])
@jwt_required()
def list_files():
    delete_expired_files()
    user_id = int(get_jwt_identity())
    files = File.query.filter_by(user_id=user_id, is_deleted=False).all()
    return jsonify([{
        "id": f.id,
        "filename": f.filename,
        "size": f.file_size,
        "uploaded_at": f.uploaded_at.isoformat(),
        "expires_at": f.expires_at.isoformat() if f.expires_at else None,
        "owned": True
    } for f in files])

# ── SHARED FILES ──
@app.route("/shared-with-me", methods=["GET"])
@jwt_required()
def shared_with_me():
    user_id = int(get_jwt_identity())
    shares = SharedFile.query.filter_by(shared_with=user_id).all()
    result = []
    for s in shares:
        f = s.file
        if not f.is_deleted:
            result.append({
                "id": f.id,
                "filename": f.filename,
                "size": f.file_size,
                "uploaded_at": f.uploaded_at.isoformat(),
                "shared_by": s.sharer.username,
                "share_id": s.id,
                "owned": False
            })
    return jsonify(result)

# ── SHARE FILE ──
@app.route("/share", methods=["POST"])
@jwt_required()
def share_file():
    user_id = int(get_jwt_identity())
    data = request.get_json()
    file_id = data.get("file_id")
    target_username = data.get("username", "").strip()

    file_record = File.query.filter_by(id=file_id, user_id=user_id, is_deleted=False).first()
    if not file_record:
        return jsonify({"error": "File not found or access denied"}), 404

    target_user = User.query.filter_by(username=target_username).first()
    if not target_user:
        return jsonify({"error": f"User '{target_username}' not found"}), 404

    if target_user.id == user_id:
        return jsonify({"error": "Cannot share with yourself"}), 400

    # Check already shared
    existing = SharedFile.query.filter_by(
        file_id=file_id,
        shared_with=target_user.id
    ).first()
    if existing:
        return jsonify({"error": "File already shared with this user"}), 400

    share = SharedFile(
        file_id=file_id,
        shared_by=user_id,
        shared_with=target_user.id
    )
    db.session.add(share)
    db.session.commit()

    log_action(user_id, "share", file_record.filename, extra=f"shared_with:{target_username}")
    return jsonify({"message": f"File shared with '{target_username}' successfully"}), 200

# ── DOWNLOAD ──
@app.route("/download/<int:file_id>", methods=["GET"])
@jwt_required()
@rate_limit(max_requests=30, window=60)
def download_file(file_id):
    user_id = int(get_jwt_identity())

    # Check own file or shared file
    file_record = File.query.filter_by(id=file_id, is_deleted=False).first()
    if not file_record:
        return jsonify({"error": "File not found"}), 404

    is_owner = file_record.user_id == user_id
    is_shared = SharedFile.query.filter_by(file_id=file_id, shared_with=user_id).first()

    if not is_owner and not is_shared:
        return jsonify({"error": "Access denied"}), 403

    file_path = os.path.join(Config.UPLOAD_FOLDER, file_record.stored_name)
    if not os.path.exists(file_path):
        return jsonify({"error": "File missing from storage"}), 500

    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_file(encrypted_data, Config.AES_KEY)
    log_action(user_id, "download", file_record.filename)

    return send_file(
        io.BytesIO(decrypted_data),
        download_name=file_record.filename,
        as_attachment=True
    )

# ── DELETE FILE ──
@app.route("/delete/<int:file_id>", methods=["DELETE"])
@jwt_required()
def delete_file(file_id):
    user_id = int(get_jwt_identity())
    file_record = File.query.filter_by(id=file_id, user_id=user_id, is_deleted=False).first()
    if not file_record:
        return jsonify({"error": "File not found or access denied"}), 404

    # Delete from disk
    file_path = os.path.join(Config.UPLOAD_FOLDER, file_record.stored_name)
    if os.path.exists(file_path):
        os.remove(file_path)

    # Update storage
    user = User.query.get(user_id)
    user.storage_used = max(0, user.storage_used - (file_record.file_size or 0))

    file_record.is_deleted = True
    db.session.commit()

    log_action(user_id, "delete", file_record.filename)
    return jsonify({"message": "File deleted successfully"}), 200

# ── CHANGE PASSWORD ──
@app.route("/change-password", methods=["POST"])
@jwt_required()
def change_password():
    from auth import verify_password, hash_password
    user_id = int(get_jwt_identity())
    data = request.get_json()
    current_pw = data.get("current_password", "")
    new_pw = data.get("new_password", "")

    if len(new_pw) < 8:
        return jsonify({"error": "New password must be at least 8 characters"}), 400

    user = User.query.get(user_id)
    if not verify_password(current_pw, user.password_hash):
        return jsonify({"error": "Current password is incorrect"}), 401

    user.password_hash = hash_password(new_pw)
    db.session.commit()

    log_action(user_id, "password_change")
    return jsonify({"message": "Password changed successfully"}), 200

# ── STORAGE INFO ──
@app.route("/storage", methods=["GET"])
@jwt_required()
def storage_info():
    user_id = int(get_jwt_identity())
    user = User.query.get(user_id)
    return jsonify({
        "used": user.storage_used,
        "limit": user.storage_limit,
        "used_mb": round(user.storage_used / (1024*1024), 2),
        "limit_mb": round(user.storage_limit / (1024*1024), 2),
        "percent": round((user.storage_used / user.storage_limit) * 100, 1)
    })

# ── LOGIN HISTORY ──
@app.route("/login-history", methods=["GET"])
@jwt_required()
def login_history():
    user_id = int(get_jwt_identity())
    logs = LoginHistory.query.filter_by(user_id=user_id).order_by(LoginHistory.timestamp.desc()).limit(20).all()
    return jsonify([{
        "timestamp": l.timestamp.isoformat(),
        "ip": l.ip_address,
        "device": l.device_info,
        "success": l.success
    } for l in logs])

# ── AUDIT LOG ──
@app.route("/audit-log", methods=["GET"])
@jwt_required()
def audit_log():
    user_id = int(get_jwt_identity())
    logs = AuditLog.query.filter_by(user_id=user_id).order_by(AuditLog.timestamp.desc()).limit(50).all()
    return jsonify([{
        "action": l.action,
        "filename": l.filename,
        "timestamp": l.timestamp.isoformat(),
        "success": l.success,
        "ip": l.ip_address,
        "device": l.device_info,
        "extra": l.extra
    } for l in logs])

# ── FILE ACCESS LOGS ──
@app.route("/file-logs/<int:file_id>", methods=["GET"])
@jwt_required()
def file_logs(file_id):
    user_id = int(get_jwt_identity())
    file_record = File.query.filter_by(id=file_id, user_id=user_id).first()
    if not file_record:
        return jsonify({"error": "File not found"}), 404
    logs = AuditLog.query.filter_by(filename=file_record.filename, action="download").order_by(AuditLog.timestamp.desc()).all()
    return jsonify([{
        "user_id": l.user_id,
        "timestamp": l.timestamp.isoformat(),
        "ip": l.ip_address,
        "device": l.device_info
    } for l in logs])

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, ssl_context="adhoc")
