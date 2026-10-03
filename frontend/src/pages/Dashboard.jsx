import { useState, useEffect } from 'react';
import { Activity, ArrowUpRight, CreditCard, Send, ShieldCheck, Users } from 'lucide-react';
import { Link } from 'react-router-dom';
import { getDashboard, getSecuritySummary } from '../services/api';
import Loading from '../components/Loading';
import ErrorMessage from '../components/ErrorMessage';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [security, setSecurity] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    Promise.all([getDashboard(), getSecuritySummary()]).then(([dashboard, summary]) => {
      setData(dashboard.data);
      setSecurity(summary.data);
    }).catch(() => setError('Unable to load your banking overview.'));
  }, []);

  if (!data && !error) return <Loading />;

  return (
    <div className="page-container">
      <ErrorMessage message={error} />
      {data && <>
      <div className="dashboard-hero"><div><p className="eyebrow">Personal overview</p><h1>Good to see you, {data.customer.name.split(' ')[0]}.</h1><p>Your accounts at a glance, with protection working quietly in the background.</p></div><StatusBadge value="ACTIVE" /></div>
      {data.account_count === 0 ? <div className="onboarding-card card"><div className="onboarding-icon"><CreditCard size={24} /></div><div><p className="eyebrow">Welcome to SecureBank</p><h2>Your banking profile is ready.</h2><p>Add or activate an account to start using your banking services. Your balances and activity will appear here once an account is connected.</p><Link className="button button-primary" to="/accounts">View accounts <ArrowUpRight size={15} /></Link></div></div> : <>
      <div className="dashboard-grid">
        <div className="balance-card"><p className="eyebrow">Total available balance</p><h2>₹{Number(data.total_balance).toLocaleString('en-IN', { minimumFractionDigits: 2 })}</h2><p>Across {data.account_count} connected accounts</p><span className="balance-meta"><Activity size={14} /> Live account view</span></div>
        <div className="summary-card card"><h3>Protection at a glance</h3><div className="summary-line"><span>WAF status</span><strong className="text-success">Monitoring</strong></div><div className="summary-line"><span>Blocked requests</span><strong>{security?.blocked_events ?? 0}</strong></div><div className="summary-line"><span>Security events</span><strong>{security?.total_events ?? 0}</strong></div></div>
      </div>
      <div className="section-heading"><h2>Quick actions</h2><span>Common tasks</span></div><div className="quick-actions"><Link className="quick-action" to="/transfer"><span className="quick-action-icon"><Send size={16} /></span>Transfer money<ArrowUpRight size={15} /></Link><Link className="quick-action" to="/accounts"><span className="quick-action-icon"><CreditCard size={16} /></span>View accounts<ArrowUpRight size={15} /></Link><Link className="quick-action" to="/beneficiaries"><span className="quick-action-icon"><Users size={16} /></span>Manage beneficiaries<ArrowUpRight size={15} /></Link></div>
      <div className="section-heading"><h2>Recent transactions</h2><Link className="muted" to="/transactions">View all</Link></div>
      <div className="table-scroll"><table className="data-table"><thead><tr><th>Date</th><th>Type</th><th>Account</th><th>Amount</th><th>Status</th></tr></thead><tbody>{data.recent_transactions.length ? data.recent_transactions.map(txn => <tr key={txn.transaction_id}><td>{txn.transaction_date}</td><td>{txn.transaction_type}</td><td className="mono">•••• {String(txn.account_number).slice(-4)}</td><td>₹{Number(txn.amount).toLocaleString('en-IN', { minimumFractionDigits: 2 })}</td><td><StatusBadge value={txn.transaction_status} /></td></tr>) : <tr><td colSpan="5">No recent transactions.</td></tr>}</tbody></table></div>
      <div className="section-heading"><h2>Security activity</h2><Link className="muted" to="/security">Open Security Center</Link></div><div className="card" style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}><div className="quick-action-icon"><ShieldCheck size={19} /></div><div><strong>Protection is active</strong><p className="muted">SQL Injection, XSS, and behavioral monitoring are enabled for your session.</p></div></div>
      </>}
      </>}
    </div>
  );
}
