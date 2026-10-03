# Web Application Firewall for SQL Injection and XSS Detection in Banking Systems

## Project Purpose
This project is an academic simulation of a banking web application that is designed to be protected by a Web Application Firewall (WAF) using Machine Learning. The current phase establishes the full application stack (React + Flask + SQLite) and incorporates the synthetic banking dataset. **All data is synthetic. No real banking information is used.** The ML WAF detection (SQL Injection and XSS) will be integrated in the next phase.

## Architecture
- **Frontend**: React (Vite)
- **Backend**: Python Flask REST API
- **Database**: SQLite (`dataset/banking/banking.db`)
- **Machine Learning (Future)**: Decision Tree classifier to detect SQLi and XSS before requests hit the Flask API.

## Folder Structure
```text
sqli_xss/
├── artifacts/             # Trained ML models
├── backend/               # Flask API (Routes, Services, DB connection)
├── dataset/               
│   ├── banking/           # SQLite DB and CSV tables
│   ├── security/          # Future web payloads for WAF testing
│   └── sql_injections/    # Original ML training data
├── frontend/              # React frontend application
├── generate_banking_data.py
├── predict_query.py
├── train_waf.py
├── requirements.txt
└── README.md
```

## Backend Setup
The Flask backend manages the secure connection to the database and serves the API endpoints.
1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the backend:
   ```bash
   $env:PYTHONPATH="."
   python backend/app.py
   ```
   *(On Mac/Linux: `PYTHONPATH=. python backend/app.py`)*

## Frontend Setup
The React frontend handles the user interface.
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install npm dependencies:
   ```bash
   npm install
   ```
3. Start the development server:
   ```bash
   npm run dev
   ```
   *The app will be available at http://localhost:5173*

## Available API Endpoints
- `POST /api/login`: Authenticate customer
- `POST /api/logout`: Terminate session
- `GET /api/me`: Get current authenticated user
- `GET /api/dashboard`: Fetch summary information (balance, accounts, recent txns)
- `GET /api/accounts`: Fetch all customer accounts
- `GET /api/accounts/<id>`: Fetch details for a specific account
- `GET /api/transactions`: Fetch transaction history (supports `?transaction_type=...`)
- `POST /api/transfer`: Perform a fund transfer between an account and a beneficiary
- `GET /api/beneficiaries`: List user's beneficiaries
- `POST /api/beneficiaries`: Add a new beneficiary

## Testing Procedure
1. Start the Backend API on port 5000.
2. Start the Frontend React App on port 5173.
3. Open `http://localhost:5173/login`.
4. Use a synthetic username and password (`password123`) from `dataset/banking/customers.csv`.
5. Verify access to Dashboard, Accounts, Transactions, Transfer, and Beneficiaries pages.
6. Test a transfer and confirm the balance updates.
7. Note that unauthorized access (e.g. going directly to `/dashboard`) will correctly bounce you to the login page.
