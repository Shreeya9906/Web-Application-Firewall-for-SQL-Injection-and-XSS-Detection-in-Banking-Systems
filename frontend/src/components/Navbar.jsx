import { Link, useNavigate } from 'react-router-dom';
import { logout } from '../services/api';

export default function Navbar() {
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <nav className="navbar">
      <div className="nav-brand">SecureBank</div>
      <div className="nav-links">
        <Link to="/dashboard">Dashboard</Link>
        <Link to="/accounts">Accounts</Link>
        <Link to="/transactions">Transactions</Link>
        <Link to="/transfer">Transfer</Link>
        <Link to="/beneficiaries">Beneficiaries</Link>
        <Link to="/security" className="security-link">Security</Link>
      </div>
      <button onClick={handleLogout} className="btn-logout">Logout</button>
    </nav>
  );
}
