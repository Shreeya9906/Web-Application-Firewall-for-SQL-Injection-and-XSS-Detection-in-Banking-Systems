from flask import Blueprint, request, session

from backend.database import get_db
from backend.utils import success_response, error_response

from datetime import datetime

beneficiary_bp = Blueprint('beneficiaries', __name__)


@beneficiary_bp.route('/beneficiaries', methods=['GET'])
def get_beneficiaries():

    customer_id = session.get('customer_id')

    if not customer_id:
        return error_response("Unauthorized", 401)

    db = get_db()

    beneficiaries = db.execute(
        '''
        SELECT *
        FROM BENEFICIARIES
        WHERE customer_id = ?
        ''',
        (customer_id,)
    ).fetchall()

    return success_response({
        "beneficiaries": [dict(b) for b in beneficiaries]
    })


@beneficiary_bp.route('/beneficiaries', methods=['POST'])
def add_beneficiary():

    customer_id = session.get('customer_id')

    if not customer_id:
        return error_response("Unauthorized", 401)

    data = request.get_json() or {}

    name = (data.get('beneficiary_name') or '').strip()
    account_number = (data.get('beneficiary_account_number') or '').strip()
    nickname = (data.get('nickname') or '').strip()

    if not name or not account_number:
        return error_response(
            "Beneficiary name and account number are required",
            400
        )

    db = get_db()

    # ---------------------------------------------------------
    # Verify the destination account from the ACCOUNTS table.
    # The account database is the source of truth for:
    # - account owner
    # - bank name
    # - IFSC code
    # - account status
    # ---------------------------------------------------------
    account = db.execute(
        '''
        SELECT
            a.account_id,
            a.customer_id,
            a.account_number,
            a.account_type,
            a.currency,
            a.account_status,
            a.bank_name,
            a.ifsc_code,
            c.first_name,
            c.last_name
        FROM ACCOUNTS a
        JOIN CUSTOMERS c
            ON c.customer_id = a.customer_id
        WHERE a.account_number = ?
        ''',
        (account_number,)
    ).fetchone()

    if not account:
        return error_response(
            "No bank account found with this account number",
            404
        )

    # Only active accounts can be added as beneficiaries.
    if account["account_status"] != "ACTIVE":
        return error_response(
            "The destination account is not active",
            400
        )

    # ---------------------------------------------------------
    # Verify the supplied beneficiary name against the actual
    # account holder.
    # ---------------------------------------------------------
    actual_name = (
        f"{account['first_name']} {account['last_name']}"
    ).strip()

    if name.casefold() != actual_name.casefold():
        return error_response(
            "Beneficiary name does not match the account holder",
            400
        )

    # ---------------------------------------------------------
    # Bank and IFSC come ONLY from the verified account.
    # Do not trust values supplied by React.
    # ---------------------------------------------------------
    bank_name = account["bank_name"]
    ifsc_code = account["ifsc_code"]

    if not bank_name or not ifsc_code:
        return error_response(
            "Bank information is not configured for this account",
            400
        )

    # ---------------------------------------------------------
    # Check duplicate beneficiary.
    # ---------------------------------------------------------
    existing = db.execute(
        '''
        SELECT beneficiary_id
        FROM BENEFICIARIES
        WHERE customer_id = ?
          AND beneficiary_account_number = ?
        ''',
        (customer_id, account_number)
    ).fetchone()

    if existing:
        return error_response(
            "Beneficiary with this account number already exists",
            400
        )

    timestamp = datetime.now().strftime('%Y-%m-%d')

    db.execute(
        '''
        INSERT INTO BENEFICIARIES
        (
            customer_id,
            beneficiary_name,
            beneficiary_account_number,
            bank_name,
            ifsc_code,
            nickname,
            status,
            created_date
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            customer_id,
            actual_name,
            account_number,
            bank_name,
            ifsc_code,
            nickname,
            'ACTIVE',
            timestamp
        )
    )

    db.commit()

    return success_response(
        message="Beneficiary added successfully"
    )
