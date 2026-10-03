import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Link } from 'react-router-dom';
import { Eye, EyeOff, Lock, ShieldCheck } from 'lucide-react';
import { login } from '../services/api';
import ErrorMessage from '../components/ErrorMessage';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await login(username, password);
      navigate('/dashboard');
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <section className="login-visual">
        <div className="brand-lockup"><div className="brand-mark"><ShieldCheck size={20} /></div><strong>SecureBank</strong></div>
        <div><p className="eyebrow">Private banking, protected</p><h1>Your money, in better hands.</h1><p>Move money, manage accounts, and stay ahead of security events from one calm, considered workspace.</p></div>
        <div className="login-visual-footer"><span>Encrypted sessions</span><span>24/7 monitoring</span><span>WAF protected</span></div>
      </section>
      <section className="login-form-panel">
        <form onSubmit={handleSubmit} className="login-form">
          <p className="eyebrow">Welcome back</p>
          <h2>Sign in to SecureBank</h2>
          <p>Use your banking credentials to continue securely.</p>
          <ErrorMessage message={error} />
          <div className="form-group"><label htmlFor="username">Username</label><input id="username" type="text" value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" required /></div>
          <div className="form-group login-field"><label htmlFor="password">Password</label><input id="password" type={showPassword ? 'text' : 'password'} value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" required /><button type="button" className="icon-button password-toggle" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button></div>
          <button type="submit" className="button button-primary" style={{ width: '100%' }} disabled={loading}><Lock size={16} />{loading ? 'Signing in...' : 'Sign in securely'}</button>
          <p className="auth-switch">New to SecureBank? <Link to="/register">Create an account</Link></p>
          <div className="protected-indicator"><ShieldCheck size={15} /> Protected by SecureBank WAF and session monitoring</div>
        </form>
      </section>
    </div>
  );
}
