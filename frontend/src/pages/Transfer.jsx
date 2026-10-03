import { useState, useEffect } from 'react';
import { ArrowRight, CheckCircle2, Info, Send } from 'lucide-react';
import { getAccounts, getBeneficiaries, transfer } from '../services/api';
import Loading from '../components/Loading';
import ErrorMessage from '../components/ErrorMessage';
import PageHeader from '../components/PageHeader';

export default function Transfer() {
  const [accounts, setAccounts] = useState([]);
  const [beneficiaries, setBeneficiaries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [submitting, setSubmitting] = useState(false);
  
  const [formData, setFormData] = useState({
    from_account_id: '',
    beneficiary_id: '',
    amount: '',
    description: ''
  });

  useEffect(() => {
    Promise.all([getAccounts(), getBeneficiaries()])
      .then(([accRes, benRes]) => {
        setAccounts(accRes.data.accounts);
        setBeneficiaries(benRes.data.beneficiaries);
        setLoading(false);
      });
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setSubmitting(true);
    try {
      const res = await transfer(formData);
      setSuccess(`Transfer successful! Reference: ${res.data.reference_number}`);
      setFormData({ ...formData, amount: '', description: '' });
      // refresh balances implicitly
    } catch (err) {
      setError(err.response?.data?.message || 'Transfer failed');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading) return <Loading />;

  return (
    <div className="page-container">
      <PageHeader eyebrow="Payments" title="Transfer money" description="Send funds securely to one of your saved beneficiaries." />
      <ErrorMessage message={error} />
      {success && <div className="success-message"><CheckCircle2 size={17} />{success}</div>}
      <div className="transfer-layout"><form onSubmit={handleSubmit} className="form-card card">
        <h3>New transfer</h3>
        <div className="form-group">
          <label>From Account</label>
          <select value={formData.from_account_id} onChange={e => setFormData({...formData, from_account_id: e.target.value})} required>
            <option value="">Select Account</option>
            {accounts.map(acc => (
              <option key={acc.account_id} value={acc.account_id}>•••• {String(acc.account_number).slice(-4)} (₹{Number(acc.balance).toLocaleString('en-IN')})</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label>To Beneficiary</label>
          <select value={formData.beneficiary_id} onChange={e => setFormData({...formData, beneficiary_id: e.target.value})} required>
            <option value="">Select Beneficiary</option>
            {beneficiaries.map(ben => (
              <option key={ben.beneficiary_id} value={ben.beneficiary_id}>{ben.beneficiary_name} - {ben.bank_name}</option>
            ))}
          </select>
        </div>
        <div className="form-group">
          <label>Amount (₹)</label>
          <input type="number" step="0.01" min="1" value={formData.amount} onChange={e => setFormData({...formData, amount: e.target.value})} required />
        </div>
        <div className="form-group">
          <label>Description</label>
          <input type="text" value={formData.description} onChange={e => setFormData({...formData, description: e.target.value})} />
        </div>
        <button type="submit" className="button button-primary" disabled={submitting}><Send size={16} />{submitting ? 'Processing...' : 'Review transfer'}<ArrowRight size={15} /></button>
      </form><aside className="card"><h3>Before you send</h3><div className="transfer-note"><Info size={18} />Confirm the beneficiary and amount carefully. Transfers are submitted securely through your authenticated banking session.</div><div className="summary-line"><span>Accounts available</span><strong>{accounts.length}</strong></div><div className="summary-line"><span>Saved beneficiaries</span><strong>{beneficiaries.length}</strong></div></aside></div>
    </div>
  );
}
