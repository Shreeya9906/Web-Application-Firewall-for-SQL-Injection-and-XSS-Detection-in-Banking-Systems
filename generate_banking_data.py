import os
import random
import sqlite3
import pandas as pd
from faker import Faker
from werkzeug.security import generate_password_hash
from datetime import datetime, timedelta

# Configuration
NUM_CUSTOMERS = 1000
NUM_ACCOUNTS = 1500
NUM_BENEFICIARIES = 2500
NUM_TRANSACTIONS = 10000
NUM_LOGINS = 5000
NUM_SECURITY_EVENTS = 100

# Set fixed seeds for reproducibility
SEED = 42
Faker.seed(SEED)
random.seed(SEED)
import numpy as np
np.random.seed(SEED)

fake = Faker('en_IN')

# Project structure setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, 'datasets')
BANKING_DIR = os.path.join(DATASETS_DIR, 'banking')
SECURITY_DIR = os.path.join(DATASETS_DIR, 'security')

os.makedirs(BANKING_DIR, exist_ok=True)
os.makedirs(SECURITY_DIR, exist_ok=True)

print("========================================")
print("SYNTHETIC BANKING DATA GENERATOR")
print("========================================\n")

# --- 1. CUSTOMERS ---
print("Generating Customers...")
customers = []
usernames = set()
emails = set()

for i in range(1, NUM_CUSTOMERS + 1):
    first_name = fake.first_name()
    last_name = fake.last_name()
    
    # Ensure unique username
    username = fake.user_name() + str(i)
    while username in usernames:
        username = fake.user_name() + str(random.randint(1000, 9999))
    usernames.add(username)
    
    # Ensure unique email
    email = f"{username}@{fake.free_email_domain()}"
    while email in emails:
        email = f"{username}_{random.randint(1000,9999)}@{fake.free_email_domain()}"
    emails.add(email)
    
    reg_date = fake.date_between(start_date='-5y', end_date='today')
    
    customers.append({
        'customer_id': i,
        'first_name': first_name,
        'last_name': last_name,
        'username': username,
        'email': email,
        'phone': fake.phone_number(),
        'date_of_birth': fake.date_of_birth(minimum_age=18, maximum_age=90).strftime('%Y-%m-%d'),
        'address': fake.street_address(),
        'city': fake.city(),
        'state': fake.state(),
        'postal_code': fake.postcode(),
        'registration_date': reg_date.strftime('%Y-%m-%d'),
        'status': random.choices(['ACTIVE', 'INACTIVE', 'BLOCKED'], weights=[0.85, 0.1, 0.05])[0],
        'password_hash': generate_password_hash('password123', method='pbkdf2:sha256:1000') # Default dummy password
    })
df_customers = pd.DataFrame(customers)

# --- 2. ACCOUNTS ---
print("Generating Accounts...")
accounts = []
account_numbers = set()
account_id = 1

# Ensure every customer gets at least one account, then randomly distribute the rest
customer_ids = list(df_customers['customer_id'])
assigned_customers = customer_ids + random.choices(customer_ids, k=NUM_ACCOUNTS - NUM_CUSTOMERS)

for cid in assigned_customers:
    # Ensure unique account number
    acc_num = str(fake.unique.random_number(digits=12, fix_len=True))
    
    created_date = fake.date_between(start_date='-5y', end_date='today')
    
    accounts.append({
        'account_id': account_id,
        'customer_id': cid,
        'account_number': acc_num,
        'account_type': random.choice(['SAVINGS', 'CURRENT']),
        'balance': round(random.uniform(1000.0, 500000.0), 2),
        'currency': 'INR',
        'account_status': random.choices(['ACTIVE', 'BLOCKED', 'CLOSED'], weights=[0.9, 0.05, 0.05])[0],
        'created_date': created_date.strftime('%Y-%m-%d')
    })
    account_id += 1
df_accounts = pd.DataFrame(accounts)

# --- 3. BENEFICIARIES ---
print("Generating Beneficiaries...")
beneficiaries = []
for i in range(1, NUM_BENEFICIARIES + 1):
    cid = random.choice(customer_ids)
    created_date = fake.date_between(start_date='-3y', end_date='today')
    
    beneficiaries.append({
        'beneficiary_id': i,
        'customer_id': cid,
        'beneficiary_name': fake.name(),
        'beneficiary_account_number': str(fake.random_number(digits=12, fix_len=True)),
        'bank_name': random.choice(['State Bank of India', 'HDFC Bank', 'ICICI Bank', 'Axis Bank', 'Kotak Mahindra Bank', 'Punjab National Bank']),
        'ifsc_code': fake.lexify(text='????0######').upper(),
        'nickname': fake.first_name(),
        'status': random.choices(['ACTIVE', 'BLOCKED'], weights=[0.95, 0.05])[0],
        'created_date': created_date.strftime('%Y-%m-%d')
    })
df_beneficiaries = pd.DataFrame(beneficiaries)

# --- 4. TRANSACTIONS ---
print("Generating Transactions...")
transactions = []
account_ids = list(df_accounts['account_id'])
ref_numbers = set()

for i in range(1, NUM_TRANSACTIONS + 1):
    acc_id = random.choice(account_ids)
    t_type = random.choice(['DEPOSIT', 'WITHDRAWAL', 'TRANSFER_IN', 'TRANSFER_OUT', 'PAYMENT'])
    amount = round(random.uniform(50.0, 50000.0), 2)
    t_date = fake.date_time_between(start_date='-1y', end_date='now')
    
    # Dummy logic for balance after tx - normally calculated, here we just synthesize something positive
    bal_after = round(random.uniform(amount, amount + 500000.0), 2)
    
    ref_num = "TXN" + str(fake.unique.random_number(digits=12, fix_len=True))
    
    transactions.append({
        'transaction_id': i,
        'account_id': acc_id,
        'transaction_type': t_type,
        'amount': amount,
        'transaction_date': t_date.strftime('%Y-%m-%d %H:%M:%S'),
        'description': f"Synthetic {t_type} transaction",
        'reference_number': ref_num,
        'balance_after_transaction': bal_after,
        'transaction_status': random.choices(['SUCCESS', 'FAILED', 'PENDING'], weights=[0.85, 0.1, 0.05])[0]
    })
df_transactions = pd.DataFrame(transactions)

# --- 5. LOGIN_ACTIVITY ---
print("Generating Login Activity...")
logins = []
for i in range(1, NUM_LOGINS + 1):
    cid = random.choice(customer_ids)
    l_time = fake.date_time_between(start_date='-6m', end_date='now')
    status = random.choices(['SUCCESS', 'FAILED', 'LOCKED'], weights=[0.8, 0.15, 0.05])[0]
    reason = "Invalid credentials" if status == 'FAILED' else ("Too many attempts" if status == 'LOCKED' else "")
    
    logins.append({
        'login_id': i,
        'customer_id': cid,
        'login_timestamp': l_time.strftime('%Y-%m-%d %H:%M:%S'),
        'ip_address': fake.ipv4_public(),
        'device_type': random.choice(['Mobile', 'Desktop', 'Tablet']),
        'browser': random.choice(['Chrome', 'Firefox', 'Safari', 'Edge']),
        'login_status': status,
        'failure_reason': reason
    })
df_logins = pd.DataFrame(logins)

# --- 6. SECURITY_EVENTS (WAF simulation) ---
print("Generating Security Events...")
security_events = []
for i in range(1, NUM_SECURITY_EVENTS + 1):
    cid = random.choice(customer_ids)
    s_time = fake.date_time_between(start_date='-1m', end_date='now')
    
    attack = random.choices(['NORMAL', 'SQL_INJECTION', 'XSS'], weights=[0.7, 0.2, 0.1])[0]
    if attack == 'NORMAL':
        action = 'ALLOWED'
        confidence = round(random.uniform(0.01, 0.2), 2)
        req_val = fake.user_name()
    elif attack == 'SQL_INJECTION':
        action = 'BLOCKED'
        confidence = round(random.uniform(0.85, 0.99), 2)
        req_val = "' OR 1=1 --"
    else:
        action = 'BLOCKED'
        confidence = round(random.uniform(0.85, 0.99), 2)
        req_val = "<script>alert(1)</script>"

    security_events.append({
        'event_id': i,
        'timestamp': s_time.strftime('%Y-%m-%d %H:%M:%S'),
        'customer_id': cid,
        'source_ip': fake.ipv4_public(),
        'endpoint': random.choice(['/login', '/dashboard', '/transfer', '/beneficiary']),
        'http_method': random.choice(['GET', 'POST']),
        'parameter_name': random.choice(['username', 'account_id', 'amount']),
        'request_value': req_val,
        'attack_type': attack,
        'confidence': confidence,
        'action': action,
        'reason': f"Detected {attack} signature" if attack != 'NORMAL' else "Normal traffic"
    })
df_security = pd.DataFrame(security_events)

# --- SAVE TO CSV ---
print("Saving to CSV files...")
df_customers.to_csv(os.path.join(BANKING_DIR, 'customers.csv'), index=False)
df_accounts.to_csv(os.path.join(BANKING_DIR, 'accounts.csv'), index=False)
df_beneficiaries.to_csv(os.path.join(BANKING_DIR, 'beneficiaries.csv'), index=False)
df_transactions.to_csv(os.path.join(BANKING_DIR, 'transactions.csv'), index=False)
df_logins.to_csv(os.path.join(BANKING_DIR, 'login_activity.csv'), index=False)
df_security.to_csv(os.path.join(BANKING_DIR, 'security_events.csv'), index=False)

# --- CREATE SQLITE DATABASE ---
print("Creating SQLite database...")
db_path = os.path.join(BANKING_DIR, 'banking.db')
if os.path.exists(db_path):
    os.remove(db_path)

conn = sqlite3.connect(db_path)
df_customers.to_sql('CUSTOMERS', conn, if_exists='replace', index=False)
df_accounts.to_sql('ACCOUNTS', conn, if_exists='replace', index=False)
df_beneficiaries.to_sql('BENEFICIARIES', conn, if_exists='replace', index=False)
df_transactions.to_sql('TRANSACTIONS', conn, if_exists='replace', index=False)
df_logins.to_sql('LOGIN_ACTIVITY', conn, if_exists='replace', index=False)
df_security.to_sql('SECURITY_EVENTS', conn, if_exists='replace', index=False)

# Make proper Primary Keys and Foreign Keys in an explicit schema SQL file
schema_sql = """
CREATE TABLE CUSTOMERS_NEW (
    customer_id INTEGER PRIMARY KEY,
    first_name TEXT,
    last_name TEXT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    phone TEXT,
    date_of_birth TEXT,
    address TEXT,
    city TEXT,
    state TEXT,
    postal_code TEXT,
    registration_date TEXT,
    status TEXT,
    password_hash TEXT
);

CREATE TABLE ACCOUNTS_NEW (
    account_id INTEGER PRIMARY KEY,
    customer_id INTEGER,
    account_number TEXT UNIQUE,
    account_type TEXT,
    balance REAL,
    currency TEXT,
    account_status TEXT,
    created_date TEXT,
    FOREIGN KEY(customer_id) REFERENCES CUSTOMERS_NEW(customer_id)
);

CREATE TABLE BENEFICIARIES_NEW (
    beneficiary_id INTEGER PRIMARY KEY,
    customer_id INTEGER,
    beneficiary_name TEXT,
    beneficiary_account_number TEXT,
    bank_name TEXT,
    ifsc_code TEXT,
    nickname TEXT,
    status TEXT,
    created_date TEXT,
    FOREIGN KEY(customer_id) REFERENCES CUSTOMERS_NEW(customer_id)
);

CREATE TABLE TRANSACTIONS_NEW (
    transaction_id INTEGER PRIMARY KEY,
    account_id INTEGER,
    transaction_type TEXT,
    amount REAL,
    transaction_date TEXT,
    description TEXT,
    reference_number TEXT UNIQUE,
    balance_after_transaction REAL,
    transaction_status TEXT,
    FOREIGN KEY(account_id) REFERENCES ACCOUNTS_NEW(account_id)
);

CREATE TABLE LOGIN_ACTIVITY_NEW (
    login_id INTEGER PRIMARY KEY,
    customer_id INTEGER,
    login_timestamp TEXT,
    ip_address TEXT,
    device_type TEXT,
    browser TEXT,
    login_status TEXT,
    failure_reason TEXT,
    FOREIGN KEY(customer_id) REFERENCES CUSTOMERS_NEW(customer_id)
);

CREATE TABLE SECURITY_EVENTS_NEW (
    event_id INTEGER PRIMARY KEY,
    timestamp TEXT,
    customer_id INTEGER,
    source_ip TEXT,
    endpoint TEXT,
    http_method TEXT,
    parameter_name TEXT,
    request_value TEXT,
    attack_type TEXT,
    confidence REAL,
    action TEXT,
    reason TEXT,
    FOREIGN KEY(customer_id) REFERENCES CUSTOMERS_NEW(customer_id)
);

INSERT INTO CUSTOMERS_NEW SELECT * FROM CUSTOMERS;
INSERT INTO ACCOUNTS_NEW SELECT * FROM ACCOUNTS;
INSERT INTO BENEFICIARIES_NEW SELECT * FROM BENEFICIARIES;
INSERT INTO TRANSACTIONS_NEW SELECT * FROM TRANSACTIONS;
INSERT INTO LOGIN_ACTIVITY_NEW SELECT * FROM LOGIN_ACTIVITY;
INSERT INTO SECURITY_EVENTS_NEW SELECT * FROM SECURITY_EVENTS;

DROP TABLE CUSTOMERS;
DROP TABLE ACCOUNTS;
DROP TABLE BENEFICIARIES;
DROP TABLE TRANSACTIONS;
DROP TABLE LOGIN_ACTIVITY;
DROP TABLE SECURITY_EVENTS;

ALTER TABLE CUSTOMERS_NEW RENAME TO CUSTOMERS;
ALTER TABLE ACCOUNTS_NEW RENAME TO ACCOUNTS;
ALTER TABLE BENEFICIARIES_NEW RENAME TO BENEFICIARIES;
ALTER TABLE TRANSACTIONS_NEW RENAME TO TRANSACTIONS;
ALTER TABLE LOGIN_ACTIVITY_NEW RENAME TO LOGIN_ACTIVITY;
ALTER TABLE SECURITY_EVENTS_NEW RENAME TO SECURITY_EVENTS;
"""

print("Applying strict schema with constraints...")
conn.executescript(schema_sql)
conn.commit()

# --- CREATE SQL DUMP ---
print("Creating SQL dump file...")
with open(os.path.join(BANKING_DIR, 'banking_database.sql'), 'w') as f:
    for line in conn.iterdump():
        f.write('%s\n' % line)

conn.close()

# --- GENERATE SECURITY DATASETS ---
print("Generating Security Test Datasets...")
sqli_payloads = pd.DataFrame([
    {"request": "' OR 1=1 --", "label": 1, "attack_type": "SQL_INJECTION", "endpoint": "/login", "http_method": "POST"},
    {"request": "admin' --", "label": 1, "attack_type": "SQL_INJECTION", "endpoint": "/login", "http_method": "POST"},
    {"request": "1; DROP TABLE users", "label": 1, "attack_type": "SQL_INJECTION", "endpoint": "/account/1", "http_method": "GET"},
    {"request": "' UNION SELECT username, password FROM users--", "label": 1, "attack_type": "SQL_INJECTION", "endpoint": "/search", "http_method": "GET"},
    {"request": "1 AND SLEEP(5)", "label": 1, "attack_type": "SQL_INJECTION", "endpoint": "/account/1", "http_method": "GET"}
])
sqli_payloads.to_csv(os.path.join(SECURITY_DIR, 'sql_injection_test_payloads.csv'), index=False)

xss_payloads = pd.DataFrame([
    {"request": "<script>alert('XSS')</script>", "label": 1, "attack_type": "XSS", "endpoint": "/search", "http_method": "GET"},
    {"request": "<img src=x onerror=alert(1)>", "label": 1, "attack_type": "XSS", "endpoint": "/dashboard", "http_method": "GET"},
    {"request": "javascript:alert(1)", "label": 1, "attack_type": "XSS", "endpoint": "/beneficiary", "http_method": "POST"},
    {"request": "<svg/onload=alert('XSS')>", "label": 1, "attack_type": "XSS", "endpoint": "/search", "http_method": "GET"}
])
xss_payloads.to_csv(os.path.join(SECURITY_DIR, 'xss_test_payloads.csv'), index=False)

normal_requests = pd.DataFrame([
    {"request": "john_doe", "label": 0, "attack_type": "NORMAL", "endpoint": "/login", "http_method": "POST"},
    {"request": "10500", "label": 0, "attack_type": "NORMAL", "endpoint": "/transfer", "http_method": "POST"},
    {"request": "saving account", "label": 0, "attack_type": "NORMAL", "endpoint": "/search", "http_method": "GET"},
    {"request": "123", "label": 0, "attack_type": "NORMAL", "endpoint": "/account/123", "http_method": "GET"}
])
normal_requests.to_csv(os.path.join(SECURITY_DIR, 'normal_web_requests.csv'), index=False)


# --- VALIDATION ---
print("\nDATA VALIDATION")
print("-" * 29)

# Validate duplicates
dup_customers = df_customers['customer_id'].duplicated().sum()
dup_accounts = df_accounts['account_id'].duplicated().sum()
dup_usernames = df_customers['username'].duplicated().sum()
dup_emails = df_customers['email'].duplicated().sum()

# Validate orphans
orphan_accounts = (~df_accounts['customer_id'].isin(df_customers['customer_id'])).sum()
orphan_txns = (~df_transactions['account_id'].isin(df_accounts['account_id'])).sum()

# Validate amounts
invalid_amounts = (df_transactions['amount'] < 0).sum()

# Missing values check for required fields
missing_req = df_customers[['customer_id', 'username', 'email']].isnull().sum().sum() + \
              df_accounts[['account_id', 'customer_id', 'account_number']].isnull().sum().sum()

print(f"Duplicate customers: {dup_customers}")
print(f"Duplicate accounts: {dup_accounts}")
print(f"Duplicate usernames: {dup_usernames}")
print(f"Duplicate emails: {dup_emails}")
print(f"Orphan accounts: {orphan_accounts}")
print(f"Orphan transactions: {orphan_txns}")
print(f"Invalid amounts: {invalid_amounts}")
print(f"Missing required values: {missing_req}")

if all(v == 0 for v in [dup_customers, dup_accounts, dup_usernames, dup_emails, orphan_accounts, orphan_txns, invalid_amounts, missing_req]):
    print("\nVALIDATION PASSED")
else:
    print("\nVALIDATION FAILED")

print("\n========================================")
print(f"Customers       : {len(df_customers)}")
print(f"Accounts        : {len(df_accounts)}")
print(f"Beneficiaries   : {len(df_beneficiaries)}")
print(f"Transactions    : {len(df_transactions)}")
print(f"Login Activity  : {len(df_logins)}")
print(f"Security Events : {len(df_security)}")
print("Database created: banking.db")
print("Data generation completed successfully.")
print("========================================\n")
