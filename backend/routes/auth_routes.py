import re
import secrets
import sqlite3
from datetime import datetime

from flask import Blueprint, request, session
from werkzeug.security import check_password_hash, generate_password_hash
from backend.database import get_db
from backend.utils import success_response, error_response

auth_bp = Blueprint('auth', __name__)

USERNAME_PATTERN = re.compile(r'^[A-Za-z][A-Za-z0-9_]{2,31}$')
EMAIL_PATTERN = re.compile(r'^[^\s@]+@[^\s@]+\.[^\s@]+$')
MIN_PASSWORD_LENGTH = 8


def _generate_account_number(db):
    """Generate a unique 12-digit account number matching the seed-data convention."""
    while True:
        account_number = str(secrets.randbelow(900_000_000_000) + 100_000_000_000)
        exists = db.execute(
            "SELECT 1 FROM ACCOUNTS WHERE account_number = ?",
            (account_number,),
        ).fetchone()
        if not exists:
            return account_number


def _public_customer(customer):
    return {
        "id": customer["customer_id"],
        "username": customer["username"],
        "full_name": f"{customer['first_name']} {customer['last_name']}".strip(),
        "email": customer["email"],
    }


@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error_response("Registration details are required", 400)

    full_name = str(data.get('full_name', '')).strip()
    username = str(data.get('username', '')).strip()
    email = str(data.get('email', '')).strip().lower()
    password = data.get('password')

    if not full_name or not username or not email or not isinstance(password, str) or not password:
        return error_response("Full name, username, email, and password are required", 400)
    if len(full_name) > 120:
        return error_response("Full name must be 120 characters or fewer", 400)
    if not USERNAME_PATTERN.fullmatch(username):
        return error_response("Username must start with a letter and contain 3-32 letters, numbers, or underscores", 400)
    if not EMAIL_PATTERN.fullmatch(email) or len(email) > 254:
        return error_response("Enter a valid email address", 400)
    if len(password) < MIN_PASSWORD_LENGTH:
        return error_response(f"Password must be at least {MIN_PASSWORD_LENGTH} characters", 400)

    name_parts = full_name.split()
    first_name = name_parts[0]
    last_name = " ".join(name_parts[1:])
    db = get_db()
    duplicate = db.execute(
        "SELECT username, email FROM CUSTOMERS WHERE username = ? OR lower(email) = lower(?)",
        (username, email),
    ).fetchone()
    if duplicate:
        if duplicate["username"] == username:
            return error_response("That username is already in use", 409)
        return error_response("That email is already registered", 409)

    timestamp = datetime.now().strftime('%Y-%m-%d')
    try:
        db.execute('BEGIN')
        cursor = db.execute(
            """
            INSERT INTO CUSTOMERS
                (first_name, last_name, username, email, phone, date_of_birth, address,
                 city, state, postal_code, registration_date, status, password_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
            """,
            (
                first_name,
                last_name,
                username,
                email,
                '',
                '',
                '',
                '',
                '',
                '',
                timestamp,
                generate_password_hash(password, method='pbkdf2:sha256:1000'),
            ),
        )
        db.execute(
            """
            INSERT INTO ACCOUNTS
                (customer_id, account_number, account_type, balance, currency, account_status, created_date)
            VALUES (?, ?, 'SAVINGS', 0.0, 'INR', 'ACTIVE', ?)
            """,
            (cursor.lastrowid, _generate_account_number(db), timestamp),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return error_response("That username or email is already registered", 409)

    customer = db.execute(
        "SELECT customer_id, first_name, last_name, username, email FROM CUSTOMERS WHERE customer_id = ?",
        (cursor.lastrowid,),
    ).fetchone()
    session.clear()
    session['customer_id'] = customer['customer_id']
    return success_response({"user": _public_customer(customer)}, "Account created successfully", 201)

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return error_response("Missing credentials", 400)
    
    username = data['username']
    password = data['password']
    
    db = get_db()
    customer = db.execute('SELECT * FROM CUSTOMERS WHERE username = ?', (username,)).fetchone()
    
    ip_address = request.remote_addr or '127.0.0.1'
    browser = request.headers.get('User-Agent', '')[:255]
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if customer and check_password_hash(customer['password_hash'], password):
        if customer['status'] != 'ACTIVE':
            db.execute('INSERT INTO LOGIN_ACTIVITY (customer_id, login_timestamp, ip_address, device_type, browser, login_status, failure_reason) VALUES (?, ?, ?, ?, ?, ?, ?)',
                       (customer['customer_id'], timestamp, ip_address, 'Desktop', browser, 'FAILED', 'Account inactive'))
            db.commit()
            return error_response("Account is not active", 403)
            
        session.clear()
        session['customer_id'] = customer['customer_id']
        
        db.execute('INSERT INTO LOGIN_ACTIVITY (customer_id, login_timestamp, ip_address, device_type, browser, login_status, failure_reason) VALUES (?, ?, ?, ?, ?, ?, ?)',
                   (customer['customer_id'], timestamp, ip_address, 'Desktop', browser, 'SUCCESS', ''))
        db.commit()
        
        return success_response({
            "customer": {
                "customer_id": customer['customer_id'],
                "username": customer['username'],
                "name": f"{customer['first_name']} {customer['last_name']}"
            }
        }, "Login successful")
        
    else:
        customer_id = customer['customer_id'] if customer else None
        db.execute('INSERT INTO LOGIN_ACTIVITY (customer_id, login_timestamp, ip_address, device_type, browser, login_status, failure_reason) VALUES (?, ?, ?, ?, ?, ?, ?)',
                   (customer_id, timestamp, ip_address, 'Desktop', browser, 'FAILED', 'Invalid credentials'))
        db.commit()
        return error_response("Invalid username or password", 401)

@auth_bp.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return success_response(message="Logged out successfully")

@auth_bp.route('/me', methods=['GET'])
def me():
    customer_id = session.get('customer_id')
    if not customer_id:
        return success_response({"authenticated": False})
        
    db = get_db()
    customer = db.execute('SELECT customer_id, first_name, last_name, username, email FROM CUSTOMERS WHERE customer_id = ?', (customer_id,)).fetchone()
    if customer:
        return success_response({
            "authenticated": True,
            "customer": {
                "customer_id": customer['customer_id'],
                "username": customer['username'],
                "name": f"{customer['first_name']} {customer['last_name']}".strip(),
                "email": customer['email'],
            }
        })
    return success_response({"authenticated": False})
