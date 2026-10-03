from flask import Blueprint, session
from backend.database import get_db
from backend.utils import success_response, error_response

account_bp = Blueprint('accounts', __name__)

@account_bp.route('/dashboard', methods=['GET'])
def dashboard():
    customer_id = session.get('customer_id')
    if not customer_id:
        return error_response("Unauthorized", 401)
        
    db = get_db()
    customer = db.execute('SELECT first_name, last_name, username FROM CUSTOMERS WHERE customer_id = ?', (customer_id,)).fetchone()
    accounts = db.execute('SELECT * FROM ACCOUNTS WHERE customer_id = ?', (customer_id,)).fetchall()
    
    account_count = len(accounts)
    total_balance = sum(acc['balance'] for acc in accounts)
    account_ids = [acc['account_id'] for acc in accounts]
    
    recent_transactions = []
    if account_ids:
        placeholders = ','.join('?' * len(account_ids))
        recent_transactions = db.execute(f'''
            SELECT t.*, a.account_number 
            FROM TRANSACTIONS t
            JOIN ACCOUNTS a ON t.account_id = a.account_id
            WHERE t.account_id IN ({placeholders})
            ORDER BY transaction_date DESC LIMIT 5
        ''', account_ids).fetchall()

    return success_response({
        "customer": {
            "name": f"{customer['first_name']} {customer['last_name']}",
            "username": customer['username']
        },
        "account_count": account_count,
        "total_balance": total_balance,
        "recent_transactions": [dict(t) for t in recent_transactions]
    })

@account_bp.route('/accounts', methods=['GET'])
def get_accounts():
    customer_id = session.get('customer_id')
    if not customer_id:
        return error_response("Unauthorized", 401)
        
    db = get_db()
    accounts = db.execute('SELECT account_id, account_number, account_type, balance, currency, account_status as status FROM ACCOUNTS WHERE customer_id = ?', (customer_id,)).fetchall()
    return success_response({"accounts": [dict(a) for a in accounts]})

@account_bp.route('/accounts/<int:account_id>', methods=['GET'])
def get_account_details(account_id):
    customer_id = session.get('customer_id')
    if not customer_id:
        return error_response("Unauthorized", 401)
        
    db = get_db()
    account = db.execute('SELECT * FROM ACCOUNTS WHERE account_id = ?', (account_id,)).fetchone()
    
    if not account:
        return error_response("Account not found", 404)
        
    if account['customer_id'] != customer_id:
        return error_response("Access denied", 403)
        
    return success_response({"account": dict(account)})
