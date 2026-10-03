from flask import Blueprint, request, session
from backend.database import get_db
from backend.utils import success_response, error_response
from datetime import datetime
import uuid

transaction_bp = Blueprint('transactions', __name__)

@transaction_bp.route('/transactions', methods=['GET'])
def get_transactions():
    customer_id = session.get('customer_id')
    if not customer_id:
        return error_response("Unauthorized", 401)
        
    db = get_db()
    
    accounts = db.execute('SELECT account_id FROM ACCOUNTS WHERE customer_id = ?', (customer_id,)).fetchall()
    account_ids = [acc['account_id'] for acc in accounts]
    
    if not account_ids:
        return success_response({"transactions": []})
        
    transaction_type = request.args.get('transaction_type')
    placeholders = ','.join('?' * len(account_ids))
    
    query = f'''
        SELECT t.*, a.account_number 
        FROM TRANSACTIONS t
        JOIN ACCOUNTS a ON t.account_id = a.account_id
        WHERE t.account_id IN ({placeholders})
    '''
    params = account_ids
    
    if transaction_type:
        query += ' AND t.transaction_type = ?'
        params.append(transaction_type)
        
    query += ' ORDER BY transaction_date DESC'
    
    transactions = db.execute(query, params).fetchall()
    return success_response({"transactions": [dict(t) for t in transactions]})

@transaction_bp.route('/transfer', methods=['POST'])
def transfer():
    customer_id = session.get('customer_id')
    if not customer_id:
        return error_response("Unauthorized", 401)
        
    data = request.get_json()
    from_account_id = data.get('from_account_id')
    beneficiary_id = data.get('beneficiary_id')
    amount = data.get('amount')
    description = data.get('description', 'Transfer')
    
    if not all([from_account_id, beneficiary_id, amount]):
        return error_response("Missing required fields", 400)
        
    try:
        amount = float(amount)
        if amount <= 0:
            return error_response("Amount must be greater than zero", 400)
    except ValueError:
        return error_response("Invalid amount", 400)
        
    db = get_db()
    
    # Validate source account
    source_acc = db.execute('SELECT * FROM ACCOUNTS WHERE account_id = ?', (from_account_id,)).fetchone()
    if not source_acc or source_acc['customer_id'] != customer_id:
        return error_response("Invalid source account", 403)
    if source_acc['account_status'] != 'ACTIVE':
        return error_response("Source account is not active", 400)
    if source_acc['balance'] < amount:
        return error_response("Insufficient balance", 400)
        
    # Validate beneficiary
    beneficiary = db.execute('SELECT * FROM BENEFICIARIES WHERE beneficiary_id = ?', (beneficiary_id,)).fetchone()
    if not beneficiary or beneficiary['customer_id'] != customer_id:
        return error_response("Invalid beneficiary", 403)
    if beneficiary['status'] != 'ACTIVE':
        return error_response("Beneficiary is not active", 400)
        
    try:
        new_balance = source_acc['balance'] - amount
        ref_num = f"TXN{uuid.uuid4().hex[:12].upper()}"
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Perform transfer in transaction
        db.execute('BEGIN TRANSACTION')
        db.execute('UPDATE ACCOUNTS SET balance = ? WHERE account_id = ?', (new_balance, from_account_id))
        db.execute('''
            INSERT INTO TRANSACTIONS 
            (account_id, transaction_type, amount, transaction_date, description, reference_number, balance_after_transaction, transaction_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (from_account_id, 'TRANSFER_OUT', amount, timestamp, description, ref_num, new_balance, 'SUCCESS'))
        db.commit()
        
        return success_response({"reference_number": ref_num}, "Transfer successful")
        
    except Exception as e:
        db.execute('ROLLBACK')
        return error_response(f"Transfer failed: {str(e)}", 500)
