import os
import io
import base64
import time
import random
import socket
import qrcode
from datetime import datetime, timedelta

from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_apscheduler import APScheduler

# Make sure you have this file in your folder
from crypto_utils import (
    pqc_generate_keys, pqc_encrypt, pqc_decrypt, 
    generate_rsa_keys, sign_data, verify_signature
)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-key-change-me")

# Database Config
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL", "sqlite:///site.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SCHEDULER_API_ENABLED'] = True

db = SQLAlchemy(app)
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# --- SIMULATION LOGIC (BACKEND) ---
def simulate_bb84_protocol():
    """
    Simulates the BB84 Quantum Key Distribution protocol.
    Returns the step-by-step process and the final Sifted Key.
    """
    length = 12  # Number of Q-bits to simulate
    alice_bits = [random.randint(0, 1) for _ in range(length)]
    alice_bases = [random.choice(['+', 'X']) for _ in range(length)]
    bob_bases = [random.choice(['+', 'X']) for _ in range(length)]
    
    simulation_log = []
    sifted_key = []

    for i in range(length):
        # Alice's Polarization Logic
        if alice_bases[i] == '+':
            photon = '↑' if alice_bits[i] == 1 else '→'
        else: # Basis X
            photon = '↗' if alice_bits[i] == 1 else '↘'
            
        # Bob's Measurement
        match = (alice_bases[i] == bob_bases[i])
        
        if match:
            status = "MATCH"
            key_bit = str(alice_bits[i])
            sifted_key.append(key_bit)
            final_visual = "✅ Key Generated"
        else:
            status = "DISCARD"
            key_bit = "-"
            final_visual = "❌ Noise"

        simulation_log.append({
            "step": i + 1,
            "bit": alice_bits[i],
            "alice_basis": alice_bases[i],
            "photon": photon,
            "bob_basis": bob_bases[i],
            "status": status,
            "result": key_bit
        })

    return {
        "log": simulation_log,
        "final_key": "".join(sifted_key),
        "success_rate": f"{len(sifted_key)/length * 100:.1f}%"
    }

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    pqc_public_key = db.Column(db.LargeBinary, nullable=False)
    pqc_private_key = db.Column(db.LargeBinary, nullable=False)
    rsa_public_key = db.Column(db.LargeBinary, nullable=False)
    rsa_private_key = db.Column(db.LargeBinary, nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content_type = db.Column(db.String(50), nullable=False)
    file_name = db.Column(db.String(255))
    encrypted_data = db.Column(db.LargeBinary, nullable=False)
    signature = db.Column(db.LargeBinary, nullable=True)
    encryption_time_ms = db.Column(db.Float, default=0.0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    auto_delete = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime, nullable=True)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_activity(user_id, action):
    log = ActivityLog(user_id=user_id, action=action)
    db.session.add(log)
    db.session.commit()

# --- Helper: Get Real Local IP ---
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

# --- Filters ---
@app.template_filter('b64encode')
def b64encode_filter(data):
    if data is None: return ""
    return base64.b64encode(data).decode("utf-8")

@app.template_filter('hex_preview')
def hex_preview(data):
    if not data: return ""
    return data[:32].hex().upper() + "..."

# --- Routes ---
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]
        confirm = request.form["confirm_password"]
        
        if password != confirm:
            flash("Passwords do not match")
            return redirect(url_for("register"))
        
        if User.query.filter((User.username == username)).first():
            flash("User exists")
            return redirect(url_for("register"))

        pqc_pub, pqc_priv = pqc_generate_keys()
        rsa_pub, rsa_priv = generate_rsa_keys()
        hashed = generate_password_hash(password)

        new_user = User(
            name=name, email=email, username=username, password_hash=hashed,
            pqc_public_key=pqc_pub, pqc_private_key=pqc_priv,
            rsa_public_key=rsa_pub, rsa_private_key=rsa_priv
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            log_activity(user.id, "Logged in")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    log_activity(current_user.id, "Logged out")
    logout_user()
    return redirect(url_for("index"))

# --- SIMULATION ROUTES ---
@app.route('/simulation')
def simulation_page():
    return render_template('simulation.html')

@app.route('/api/run_bb84', methods=['POST'])
def api_run_bb84():
    data = simulate_bb84_protocol()
    return jsonify(data)

@app.route('/api/run_attack', methods=['POST'])
def api_run_attack():
    # This dummy endpoint is not strictly needed for the JS simulation 
    # but good to keep for future expansion
    return jsonify({"status": "ready"})

# --- MAIN ROUTES ---

@app.route("/dashboard")
@login_required
def dashboard():
    users = User.query.filter(User.id != current_user.id).all()
    msg_count = Message.query.filter_by(receiver_id=current_user.id).count()
    file_count = Message.query.filter(Message.receiver_id==current_user.id, Message.content_type!='text').count()
    return render_template("dashboard.html", users=users, msg_count=msg_count, file_count=file_count)

@app.route("/chats")
@login_required
def chats():
    msgs = Message.query.filter_by(receiver_id=current_user.id, content_type='text').order_by(Message.timestamp.desc()).all()
    processed = process_messages(msgs)
    return render_template("chats.html", inbox=processed)

@app.route("/files")
@login_required
def files():
    msgs = Message.query.filter(
        Message.receiver_id == current_user.id, 
        Message.content_type.in_(['file', 'image'])
    ).order_by(Message.timestamp.desc()).all()
    processed = process_messages(msgs)
    return render_template("files.html", inbox=processed)

@app.route("/activity")
@login_required
def activity():
    logs = ActivityLog.query.filter_by(user_id=current_user.id).order_by(ActivityLog.timestamp.desc()).all()
    return render_template("activity.html", logs=logs)

def process_messages(msg_list):
    results = []
    for msg in msg_list:
        sender = User.query.get(msg.sender_id)
        decrypted = pqc_decrypt(current_user.pqc_private_key, msg.encrypted_data)
        verified = False
        if msg.signature:
            verified = verify_signature(sender.rsa_public_key, msg.signature, decrypted)
        
        results.append({
            "msg": msg,
            "sender": sender.username,
            "decrypted": decrypted,
            "verified": verified
        })
    return results

@app.route("/send", methods=["POST"])
@login_required
def send():
    try:
        receiver_id = int(request.form["receiver"])
        content_type = request.form["type"]
        auto_del = 'auto_delete' in request.form
        
        file_name = None
        content = b""

        if content_type == "text":
            content = request.form["content"].encode()
        else:
            uploaded = request.files["file"]
            file_name = uploaded.filename
            content = uploaded.read()

        receiver = User.query.get(receiver_id)
        
        start_time = time.perf_counter()
        signature = sign_data(current_user.rsa_private_key, content)
        encrypted = pqc_encrypt(receiver.pqc_public_key, content)
        enc_time = (time.perf_counter() - start_time) * 1000 

        expires = datetime.utcnow() + timedelta(days=2) if auto_del else None

        msg = Message(
            sender_id=current_user.id, receiver_id=receiver_id,
            content_type=content_type, file_name=file_name,
            encrypted_data=encrypted, signature=signature,
            encryption_time_ms=enc_time, auto_delete=auto_del, expires_at=expires
        )
        db.session.add(msg)
        log_activity(current_user.id, f"Sent {content_type} to {receiver.username}")
        db.session.commit()
        flash(f"Transmission Secure. Time: {enc_time:.2f}ms")
    except Exception as e:
        flash(f"Error: {str(e)}")
        
    return redirect(url_for("dashboard"))

@app.route("/download/<int:msg_id>")
@login_required
def download(msg_id):
    msg = Message.query.get(msg_id)
    if msg.receiver_id != current_user.id: return "Unauthorized", 403
    decrypted = pqc_decrypt(current_user.pqc_private_key, msg.encrypted_data)
    log_activity(current_user.id, f"Downloaded {msg.file_name}")
    return send_file(io.BytesIO(decrypted), as_attachment=True, download_name=msg.file_name or "file")

@app.route("/generate_qr")
# @login_required
def generate_qr():
    # Use real local IP for mobile testing
    local_ip = get_local_ip()
    # Change this URL to your Ngrok link if using Ngrok
    url = f"http://{local_ip}:5000"
    
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    # 0.0.0.0 is needed to access from mobile
    app.run(debug=True, host="0.0.0.0", port=5000)