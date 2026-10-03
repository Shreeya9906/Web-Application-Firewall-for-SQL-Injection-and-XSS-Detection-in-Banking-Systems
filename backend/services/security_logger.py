from backend.database import get_db
from datetime import datetime

def log_security_event(customer_id, source_ip, endpoint, http_method, parameter_name, request_value, attack_type, confidence, action, reason):
    db = get_db()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    db.execute('''
        INSERT INTO SECURITY_EVENTS 
        (timestamp, customer_id, source_ip, endpoint, http_method, parameter_name, request_value, attack_type, confidence, action, reason)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (timestamp, customer_id, source_ip, endpoint, http_method, parameter_name, request_value, attack_type, confidence, action, reason))
    db.commit()
    return db.execute('SELECT last_insert_rowid()').fetchone()[0]
