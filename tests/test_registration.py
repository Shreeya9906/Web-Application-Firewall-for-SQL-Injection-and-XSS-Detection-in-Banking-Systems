import json
import shutil
import tempfile
import unittest
import uuid
from pathlib import Path

from werkzeug.security import check_password_hash

from backend import database
from backend.app import create_app


ROOT = Path(__file__).resolve().parents[1]


class RegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original_db_path = database.DB_PATH
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / 'banking.db'
        shutil.copy(ROOT / 'dataset' / 'banking' / 'banking.db', cls.db_path)
        database.DB_PATH = str(cls.db_path)
        cls.app = create_app()
        cls.app.config.update(TESTING=True)

    @classmethod
    def tearDownClass(cls):
        database.DB_PATH = cls.original_db_path
        cls.temp_dir.cleanup()

    def setUp(self):
        self.client = self.app.test_client()
        suffix = uuid.uuid4().hex[:10]
        self.registration = {
            'full_name': 'New Banking Customer',
            'username': f'newuser_{suffix}',
            'email': f'newuser_{suffix}@example.com',
            'password': 'SecurePass123!',
        }

    def test_registration_creates_hashed_user_and_session(self):
        response = self.client.post('/api/register', json=self.registration)
        self.assertEqual(response.status_code, 201)
        body = response.get_json()
        self.assertEqual(body['user']['username'], self.registration['username'])
        self.assertEqual(body['user']['full_name'], self.registration['full_name'])
        self.assertNotIn('password', json.dumps(body))
        self.assertNotIn('password_hash', json.dumps(body))

        me = self.client.get('/api/me').get_json()
        self.assertTrue(me['authenticated'])
        self.assertEqual(me['customer']['username'], self.registration['username'])
        self.assertEqual(self.client.get('/api/dashboard').status_code, 200)
        dashboard = self.client.get('/api/dashboard').get_json()
        self.assertEqual(dashboard['account_count'], 1)
        self.assertEqual(dashboard['total_balance'], 0)
        self.assertEqual(dashboard['recent_transactions'], [])

        with self.app.app_context():
            row = database.get_db().execute(
                'SELECT customer_id, password_hash, status FROM CUSTOMERS WHERE username = ?',
                (self.registration['username'],),
            ).fetchone()
            accounts = database.get_db().execute(
                'SELECT customer_id, account_number, account_type, balance, currency, account_status FROM ACCOUNTS WHERE customer_id = ?',
                (row['customer_id'],),
            ).fetchall()
        self.assertEqual(row['status'], 'ACTIVE')
        self.assertNotEqual(row['password_hash'], self.registration['password'])
        self.assertTrue(check_password_hash(row['password_hash'], self.registration['password']))
        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0]['customer_id'], row['customer_id'])
        self.assertEqual(len(accounts[0]['account_number']), 12)
        self.assertTrue(accounts[0]['account_number'].isdigit())
        self.assertEqual(accounts[0]['account_type'], 'SAVINGS')
        self.assertEqual(accounts[0]['balance'], 0)
        self.assertEqual(accounts[0]['currency'], 'INR')
        self.assertEqual(accounts[0]['account_status'], 'ACTIVE')

    def test_logout_and_login_again_use_existing_session_flow(self):
        self.assertEqual(self.client.post('/api/register', json=self.registration).status_code, 201)
        self.assertEqual(self.client.post('/api/logout').status_code, 200)
        self.assertFalse(self.client.get('/api/me').get_json()['authenticated'])
        response = self.client.post('/api/login', json={
            'username': self.registration['username'],
            'password': self.registration['password'],
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.get('/api/me').get_json()['customer']['username'], self.registration['username'])
        accounts = self.client.get('/api/accounts').get_json()['accounts']
        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0]['account_type'], 'SAVINGS')
        self.assertEqual(accounts[0]['balance'], 0.0)
        self.assertEqual(accounts[0]['status'], 'ACTIVE')
        dashboard = self.client.get('/api/dashboard').get_json()
        self.assertEqual(dashboard['account_count'], 1)
        self.assertEqual(dashboard['total_balance'], 0.0)

    def test_duplicate_username_and_email_are_rejected(self):
        self.assertEqual(self.client.post('/api/register', json=self.registration).status_code, 201)
        duplicate_username = {**self.registration, 'email': 'different@example.com'}
        duplicate_email = {**self.registration, 'username': f'other_{uuid.uuid4().hex[:10]}'}
        self.assertEqual(self.client.post('/api/register', json=duplicate_username).status_code, 409)
        self.assertIn('username', self.client.post('/api/register', json=duplicate_username).get_json()['message'].lower())
        self.assertEqual(self.client.post('/api/register', json=duplicate_email).status_code, 409)
        self.assertIn('email', self.client.post('/api/register', json=duplicate_email).get_json()['message'].lower())
        with self.app.app_context():
            customer_count = database.get_db().execute(
                'SELECT COUNT(*) FROM CUSTOMERS WHERE username = ?', (self.registration['username'],)
            ).fetchone()[0]
            account_count = database.get_db().execute(
                'SELECT COUNT(*) FROM ACCOUNTS WHERE customer_id = (SELECT customer_id FROM CUSTOMERS WHERE username = ?)',
                (self.registration['username'],),
            ).fetchone()[0]
        self.assertEqual(customer_count, 1)
        self.assertEqual(account_count, 1)

    def test_invalid_registration_and_waf_payloads_are_rejected(self):
        invalid = {**self.registration, 'username': 'bad username', 'password': 'short'}
        self.assertEqual(self.client.post('/api/register', json=invalid).status_code, 400)
        sql_payload = {**self.registration, 'username': "admin' OR 1=1 --"}
        xss_payload = {**self.registration, 'full_name': '<script>alert(1)</script>'}
        self.assertEqual(self.client.post('/api/register', json=sql_payload).status_code, 403)
        self.assertEqual(self.client.post('/api/register', json=xss_payload).status_code, 403)


if __name__ == '__main__':
    unittest.main()
