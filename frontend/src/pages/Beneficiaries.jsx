import { useState, useEffect } from 'react';
import { Building2, CheckCircle2, UserPlus } from 'lucide-react';
import { getBeneficiaries, addBeneficiary } from '../services/api';
import Loading from '../components/Loading';
import ErrorMessage from '../components/ErrorMessage';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';

export default function Beneficiaries() {
  const [beneficiaries, setBeneficiaries] = useState(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [formData, setFormData] = useState({
    beneficiary_name: '',
    beneficiary_account_number: '',
    bank_name: '',
    ifsc_code: '',
    nickname: ''
  });

  const loadBen = () => {
    setLoading(true);
    getBeneficiaries().then(res => setBeneficiaries(res.data.beneficiaries)).catch(() => setError('Unable to load beneficiaries.')).finally(() => setLoading(false));
  };

  useEffect(() => { loadBen(); }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setSubmitting(true);
    try {
      await addBeneficiary(formData);
      setSuccess('Beneficiary added!');
      setFormData({ beneficiary_name: '', beneficiary_account_number: '', bank_name: '', ifsc_code: '', nickname: '' });
      loadBen();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to add beneficiary');
    } finally {
      setSubmitting(false);
    }
  };

  if (loading && !beneficiaries) return <Loading />;

  return (
    <div className="page-container">
      <PageHeader eyebrow="Payments" title="Beneficiaries" description="Keep trusted recipients ready for secure transfers." />
      <div className="beneficiaries-grid"><div className="card">
          <h3><UserPlus size={17} /> Add new beneficiary</h3>
          <ErrorMessage message={error} />
          {success && <div className="success-message"><CheckCircle2 size={17} />{success}</div>}
          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <label>Name</label>
              <input type="text" value={formData.beneficiary_name} onChange={e => setFormData({...formData, beneficiary_name: e.target.value})} required />
            </div>
            <div className="form-group">
              <label>Account Number</label>
              <input type="text" value={formData.beneficiary_account_number} onChange={e => setFormData({...formData, beneficiary_account_number: e.target.value})} required />
            </div>
            <div className="form-group">
              <label>Bank Name</label>
              <input type="text" value={formData.bank_name} onChange={e => setFormData({...formData, bank_name: e.target.value})} required />
            </div>
            <div className="form-group">
              <label>IFSC Code</label>
              <input type="text" value={formData.ifsc_code} onChange={e => setFormData({...formData, ifsc_code: e.target.value})} required />
            </div>
            <div className="form-group">
              <label>Nickname</label>
              <input type="text" value={formData.nickname} onChange={e => setFormData({...formData, nickname: e.target.value})} />
            </div>
            <button type="submit" className="button button-primary" disabled={submitting}><UserPlus size={16} />{submitting ? 'Saving...' : 'Save beneficiary'}</button>
          </form>
        </div>

        <div className="card">
          <h3><Building2 size={17} /> Saved beneficiaries</h3>
          {beneficiaries?.length ? <ul className="ben-list">{beneficiaries.map(ben => <li key={ben.beneficiary_id} className="ben-item"><div className="ben-avatar">{String(ben.beneficiary_name).slice(0, 1).toUpperCase()}</div><div className="ben-content"><strong>{ben.beneficiary_name}</strong><span>{ben.bank_name} · •••• {String(ben.beneficiary_account_number).slice(-4)}</span><span>IFSC {ben.ifsc_code}</span></div><div className="ben-meta"><StatusBadge value={ben.status} /><small>{ben.nickname || 'Recipient'}</small></div></li>)}</ul> : <div className="empty-state"><strong>No beneficiaries yet</strong><span>Add a trusted recipient to get started.</span></div>}
        </div>
      </div>
    </div>
  );
}
