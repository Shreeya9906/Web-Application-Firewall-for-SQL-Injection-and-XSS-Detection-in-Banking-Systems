import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ArrowRight, Check, Eye, EyeOff, ShieldCheck } from 'lucide-react';
import { register } from '../services/api';
import ErrorMessage from '../components/ErrorMessage';

const initialForm = { full_name: '', username: '', email: '', password: '', confirm_password: '' };

function validate(form) {
  const errors = {};
  if (!form.full_name.trim()) errors.full_name = 'Enter your full name.';
  if (!/^[A-Za-z][A-Za-z0-9_]{2,31}$/.test(form.username.trim())) errors.username = 'Use 3-32 letters, numbers, or underscores, starting with a letter.';
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email.trim())) errors.email = 'Enter a valid email address.';
  if (form.password.length < 8) errors.password = 'Use at least 8 characters.';
  if (form.password !== form.confirm_password) errors.confirm_password = 'Passwords do not match.';
  return errors;
}

export default function Register() {
  const [form, setForm] = useState(initialForm);
  const [errors, setErrors] = useState({});
  const [serverError, setServerError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmation, setShowConfirmation] = useState(false);
  const navigate = useNavigate();

  const updateField = (field, value) => {
    setForm(current => ({ ...current, [field]: value }));
    setErrors(current => ({ ...current, [field]: '' }));
    setServerError('');
  };

  const handleSubmit = async event => {
    event.preventDefault();
    const validationErrors = validate(form);
    setErrors(validationErrors);
    setServerError('');
    if (Object.keys(validationErrors).length) return;
    setLoading(true);
    try {
      await register({ full_name: form.full_name.trim(), username: form.username.trim(), email: form.email.trim(), password: form.password });
      navigate('/dashboard');
    } catch (error) {
      setServerError(error.response?.data?.message || 'We could not create your account.');
    } finally {
      setLoading(false);
    }
  };

  const requirement = form.password.length >= 8;
  return <div className="login-container">
    <section className="login-visual">
      <div className="brand-lockup"><div className="brand-mark"><ShieldCheck size={20} /></div><strong>SecureBank</strong></div>
      <div><p className="eyebrow">A safer start</p><h1>Make banking feel simple.</h1><p>Create your secure profile and step into a banking workspace designed around clarity, control, and protection.</p></div>
      <div className="login-visual-footer"><span>Encrypted sessions</span><span>Real-time WAF</span><span>Private by design</span></div>
    </section>
    <section className="login-form-panel">
      <form onSubmit={handleSubmit} className="login-form registration-form" noValidate>
        <p className="eyebrow">New to SecureBank</p><h2>Create your account</h2><p>Set up your profile in a few secure steps.</p>
        <ErrorMessage message={serverError} />
        <div className="form-group"><label htmlFor="full-name">Full name</label><input id="full-name" type="text" value={form.full_name} onChange={event => updateField('full_name', event.target.value)} autoComplete="name" aria-invalid={Boolean(errors.full_name)} required />{errors.full_name && <small className="field-error">{errors.full_name}</small>}</div>
        <div className="form-group"><label htmlFor="register-username">Username</label><input id="register-username" type="text" value={form.username} onChange={event => updateField('username', event.target.value)} autoComplete="username" aria-invalid={Boolean(errors.username)} required />{errors.username && <small className="field-error">{errors.username}</small>}</div>
        <div className="form-group"><label htmlFor="register-email">Email address</label><input id="register-email" type="email" value={form.email} onChange={event => updateField('email', event.target.value)} autoComplete="email" aria-invalid={Boolean(errors.email)} required />{errors.email && <small className="field-error">{errors.email}</small>}</div>
        <div className="form-group login-field"><label htmlFor="register-password">Password</label><input id="register-password" type={showPassword ? 'text' : 'password'} value={form.password} onChange={event => updateField('password', event.target.value)} autoComplete="new-password" aria-invalid={Boolean(errors.password)} required /><button type="button" className="icon-button password-toggle" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'}>{showPassword ? <EyeOff size={17} /> : <Eye size={17} />}</button>{errors.password && <small className="field-error">{errors.password}</small>}</div>
        <div className="password-requirements"><span className={requirement ? 'met' : ''}>{requirement ? <Check size={13} /> : <span className="requirement-dot" />} At least 8 characters</span></div>
        <div className="form-group login-field"><label htmlFor="confirm-password">Confirm password</label><input id="confirm-password" type={showConfirmation ? 'text' : 'password'} value={form.confirm_password} onChange={event => updateField('confirm_password', event.target.value)} autoComplete="new-password" aria-invalid={Boolean(errors.confirm_password)} required /><button type="button" className="icon-button password-toggle" onClick={() => setShowConfirmation(value => !value)} aria-label={showConfirmation ? 'Hide confirmation password' : 'Show confirmation password'}>{showConfirmation ? <EyeOff size={17} /> : <Eye size={17} />}</button>{errors.confirm_password && <small className="field-error">{errors.confirm_password}</small>}</div>
        <button type="submit" className="button button-primary" style={{ width: '100%' }} disabled={loading}>{loading ? 'Creating account...' : 'Create secure account'}<ArrowRight size={16} /></button>
        <p className="auth-switch">Already have an account? <Link to="/login">Sign in</Link></p>
      </form>
    </section>
  </div>;
}
