import sqlite3
from flask import Flask, request, jsonify, g
from werkzeug.security import generate_password_hash
from datetime import datetime
import os

DATABASE = "users.db"
app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

def init_db():
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

@app.route("/register", methods=["POST"])
def register():
    # Accept JSON with name, email, password
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Send JSON with name, email, password"}), 400

    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    # Basic validation 
    if not name or not email or not password:
        return jsonify({"error": "name, email and password are required"}), 400
    if len(password) < 6:
        return jsonify({"error": "password must be at least 6 characters"}), 400

    password_hash = generate_password_hash(password)  # secure hash

    now = datetime.utcnow().isoformat()
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (name, email, password_hash, now)
        )
        conn.commit()
        user_id = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify({"error": "email already registered"}), 409

    return jsonify({
        "message": "registered successfully",
        "user": {"id": user_id, "name": name, "email": email, "created_at": now}
    }), 201

@app.route("/users", methods=["GET"])
def list_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, name, email, created_at FROM users ORDER BY id DESC")
    rows = cur.fetchall()
    users = [dict(row) for row in rows]
    return jsonify({"users": users})

if __name__ == "__main__":
    init_db()
    # show file path and start server
    print(f"Using database file: {os.path.abspath(DATABASE)}")
    app.run(host="0.0.0.0", port=5000)
