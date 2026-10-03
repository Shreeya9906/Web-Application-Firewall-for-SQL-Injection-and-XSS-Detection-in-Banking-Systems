import { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { ArrowUpRight, CreditCard } from 'lucide-react';
import { getAccounts } from '../services/api';
import Loading from '../components/Loading';
import ErrorMessage from '../components/ErrorMessage';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';

export default function Accounts() {
  const [accounts, setAccounts] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    getAccounts().then(res => setAccounts(res.data.accounts)).catch(() => setError('Unable to load your accounts.'));
  }, []);

  if (!accounts && !error) return <Loading />;

  return (
    <div className="page-container">
      <PageHeader eyebrow="Banking" title="Your accounts" description="A clear view of your balances and account health." />
      <ErrorMessage message={error} />
      {accounts && (accounts.length ? <div className="accounts-list">{accounts.map(acc => <Link to={`/accounts/${acc.account_id}`} key={acc.account_id} className="account-card card"><div className="account-card-top"><h3>{acc.account_type} account</h3><CreditCard className="account-icon" size={20} /></div><p className="account-number">•••• •••• {String(acc.account_number).slice(-4)}</p><p className="balance">₹{Number(acc.balance).toLocaleString('en-IN', { minimumFractionDigits: 2 })}</p><div className="account-card-bottom"><StatusBadge value={acc.status} /><small>View details <ArrowUpRight size={13} /></small></div></Link>)}</div> : <div className="card"><div className="empty-state"><strong>No accounts found</strong><span>Your connected accounts will appear here.</span></div></div>)}
    </div>
  );
}
