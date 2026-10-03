import { useEffect, useState } from 'react';
import { Mail, ShieldCheck, User } from 'lucide-react';
import { getMe } from '../services/api';
import Loading from '../components/Loading';
import ErrorMessage from '../components/ErrorMessage';
import PageHeader from '../components/PageHeader';

export default function Profile() {
  const [customer, setCustomer] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    getMe().then(response => {
      if (response.data.authenticated) setCustomer(response.data.customer);
      else setError('Your session has expired. Please sign in again.');
    }).catch(() => setError('Unable to load your profile.'));
  }, []);

  if (!customer && !error) return <Loading />;

  return <div className="page-container profile-page">
    <PageHeader eyebrow="Personal banking" title="Your profile" description="Your authenticated SecureBank identity." />
    <ErrorMessage message={error} />
    {customer && <div className="profile-page-grid"><section className="card profile-identity-card"><div className="profile-large-avatar">{customer.name.split(' ').map(part => part[0]).join('').slice(0, 2).toUpperCase()}</div><p className="eyebrow">Authenticated customer</p><h2>{customer.name}</h2><p className="muted">@{customer.username}</p><div className="profile-protection"><ShieldCheck size={17} /><span>Protected by SecureBank session monitoring</span></div></section><section className="card profile-details-card"><h3>Account identity</h3><div className="profile-detail-row"><User size={17} /><div><span>Full name</span><strong>{customer.name}</strong></div></div><div className="profile-detail-row"><User size={17} /><div><span>Username</span><strong>{customer.username}</strong></div></div>{customer.email && <div className="profile-detail-row"><Mail size={17} /><div><span>Email address</span><strong>{customer.email}</strong></div></div>}</section></div>}
  </div>;
}
