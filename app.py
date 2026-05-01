from flask import Flask, request, jsonify, send_file
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from flask_cors import CORS
from config import Config
from models import db, User, File, AuditLog
from auth import register_user, login_user
from encryption import encrypt_file, decrypt_file
import os, uuid, io
from functools import wraps
from collections import defaultdict
import time

app = Flask(__name__)
app.config.from_object(Config)
CORS(app, resources={r"/*": {"origins": "*"}})

db.init_app(app)
jwt = JWTManager(app)

os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)

# ─── Simple in-memory rate limiter ───────────────────────────────────────────
request_counts = defaultdict(list)

def rate_limit(max_requests=10, window=60):
    """Decorator: max_requests per window seconds per IP."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()
            # Remove old timestamps outside the window
            request_counts[ip] = [t for t in request_counts[ip] if now - t < window]
            if len(request_counts[ip]) >= max_requests:
                return jsonify({"error": "Rate limit exceeded. Try again later."}), 429
            request_counts[ip].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator

def log_action(user_id, action, filename=None, success=True):
    entry = AuditLog(
        user_id=user_id,
        action=action,
        filename=filename,
        ip_address=request.remote_addr,
        success=success
    )
    db.session.add(entry)
    db.session.commit()

# ─── Routes ──────────────────────────────────────────────────────────────────

@app.route("/register", methods=["POST"])
@rate_limit(max_requests=5, window=300)  # 5 registrations per 5 minutes
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


@app.route("/login", methods=["POST"])
@rate_limit(max_requests=10, window=60)  # 10 login attempts per minute
def login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    token, error = login_user(username, password)
    if error:
        # Log failed login attempt
        user = User.query.filter_by(username=username).first()
        if user:
            log_action(user.id, "login_failed", success=False)
        return jsonify({"error": error}), 401

    user = User.query.filter_by(username=username).first()
    log_action(user.id, "login")
    return jsonify({"token": token, "message": "Login successful"}), 200


@app.route("/upload", methods=["POST"])
@jwt_required()
@rate_limit(max_requests=20, window=60)
def upload_file():
    user_id = int(get_jwt_identity())

    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # Read file content
    file_data = file.read()
    original_name = file.filename

    # Encrypt using AES-256
    encrypted_data = encrypt_file(file_data, Config.AES_KEY)

    # Save with a UUID name (hides original filename on disk)
    stored_name = str(uuid.uuid4()) + ".enc"
    file_path = os.path.join(Config.UPLOAD_FOLDER, stored_name)

    with open(file_path, "wb") as f:
        f.write(encrypted_data)

    # Record in database
    file_record = File(
        filename=original_name,
        stored_name=stored_name,
        file_size=len(file_data),
        user_id=user_id
    )
    db.session.add(file_record)
    db.session.commit()

    log_action(user_id, "upload", original_name)
    return jsonify({
        "message": "File uploaded and encrypted successfully",
        "file_id": file_record.id,
        "filename": original_name
    }), 201


@app.route("/files", methods=["GET"])
@jwt_required()
def list_files():
    user_id = int(get_jwt_identity())
    files = File.query.filter_by(user_id=user_id).all()
    return jsonify([{
        "id": f.id,
        "filename": f.filename,
        "size": f.file_size,
        "uploaded_at": f.uploaded_at.isoformat()
    } for f in files])


@app.route("/download/<int:file_id>", methods=["GET"])
@jwt_required()
@rate_limit(max_requests=30, window=60)
def download_file(file_id):
    user_id = int(get_jwt_identity())

    # Only allow access to the owner's files
    file_record = File.query.filter_by(id=file_id, user_id=user_id).first()
    if not file_record:
        return jsonify({"error": "File not found or access denied"}), 404

    file_path = os.path.join(Config.UPLOAD_FOLDER, file_record.stored_name)
    if not os.path.exists(file_path):
        return jsonify({"error": "File missing from storage"}), 500

    # Read and decrypt
    with open(file_path, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_file(encrypted_data, Config.AES_KEY)

    log_action(user_id, "download", file_record.filename)

    return send_file(
        io.BytesIO(decrypted_data),
        download_name=file_record.filename,
        as_attachment=True
    )


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
        "ip": l.ip_address
    } for l in logs])


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, ssl_context="adhoc")  # TLS enabled