import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { ArrowLeft, CreditCard } from 'lucide-react';
import { Link } from 'react-router-dom';
import { getAccountDetails } from '../services/api';
import Loading from '../components/Loading';
import ErrorMessage from '../components/ErrorMessage';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';

export default function AccountDetails() {
  const { accountId } = useParams();
  const [account, setAccount] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    getAccountDetails(accountId)
      .then(res => setAccount(res.data.account))
      .catch(err => setError(err.response?.data?.message || 'Failed to load account'));
  }, [accountId]);

  if (error) return <ErrorMessage message={error} />;
  if (!account) return <Loading />;

  return (
    <div className="page-container">
      <PageHeader eyebrow="Account details" title={`${account.account_type} account`} description="Review account information and current balance." actions={<Link className="button button-secondary" to="/accounts"><ArrowLeft size={15} /> Back to accounts</Link>} />
      <div className="card detail-card"><div className="account-card-top"><div><p className="eyebrow">Available balance</p><p className="balance">₹{Number(account.balance).toLocaleString('en-IN', { minimumFractionDigits: 2 })}</p></div><CreditCard size={30} className="account-icon" /></div><dl className="detail-grid"><div className="detail-item"><dt>Account number</dt><dd className="mono">•••• •••• {String(account.account_number).slice(-4)}</dd></div><div className="detail-item"><dt>Account type</dt><dd>{account.account_type}</dd></div><div className="detail-item"><dt>Currency</dt><dd>{account.currency}</dd></div><div className="detail-item"><dt>Status</dt><dd><StatusBadge value={account.account_status} /></dd></div><div className="detail-item"><dt>Opened</dt><dd>{account.created_date}</dd></div></dl></div>
    </div>
  );
}
