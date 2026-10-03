import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  ArrowLeftRight,
  Bell,
  Building2,
  ChevronRight,
  CreditCard,
  LayoutDashboard,
  LogOut,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  Settings,
  ShieldCheck,
  Users,
  X
} from 'lucide-react';
import { getMe, getSecurityEvents, logout } from '../services/api';

const pageTitles = {
  '/dashboard': 'Overview',
  '/accounts': 'Accounts',
  '/transactions': 'Transactions',
  '/transfer': 'Transfer money',
  '/beneficiaries': 'Beneficiaries',
  '/security': 'Security Center'
  ,'/profile': 'Your profile'
};

const bankingLinks = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard, end: true },
  { to: '/accounts', label: 'Accounts', icon: CreditCard },
  { to: '/transactions', label: 'Transactions', icon: ArrowLeftRight },
  { to: '/transfer', label: 'Transfer', icon: Building2 },
  { to: '/beneficiaries', label: 'Beneficiaries', icon: Users }
];

export default function AppShell() {
  const location = useLocation();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [collapsed, setCollapsed] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const [identity, setIdentity] = useState(null);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [notificationsLoading, setNotificationsLoading] = useState(false);
  const title = pageTitles[location.pathname] || (location.pathname.startsWith('/accounts/') ? 'Account details' : 'SecureBank');

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const closeMobile = () => setMobileOpen(false);

  useEffect(() => {
    getMe().then(response => {
      if (response.data.authenticated) setIdentity(response.data.customer);
    }).catch(() => setIdentity(null));
  }, []);

  const displayName = identity?.name || identity?.username || 'SecureBank user';
  const initials = displayName.split(' ').map(part => part[0]).join('').slice(0, 2).toUpperCase();

  const toggleNotifications = async () => {
    setNotificationsOpen(value => !value);
    if (!notifications.length) {
      setNotificationsLoading(true);
      try {
        const response = await getSecurityEvents({ limit: 5 });
        setNotifications(response.data.events || []);
      } catch {
        setNotifications([]);
      } finally {
        setNotificationsLoading(false);
      }
    }
  };

  const viewAllNotifications = event => {
    event.preventDefault();
    setNotificationsOpen(false);
    if (location.pathname === '/security') {
      document.getElementById('security-events')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } else {
      navigate('/security');
    }
  };

  return (
    <div className={`app-shell ${collapsed ? 'sidebar-collapsed' : ''}`}>
      <div className={`sidebar-backdrop ${mobileOpen ? 'visible' : ''}`} onClick={closeMobile} />
      <aside className={`sidebar ${mobileOpen ? 'mobile-open' : ''}`}>
        <div className="sidebar-brand">
          <div className="brand-mark"><ShieldCheck size={20} strokeWidth={2.3} /></div>
          <div className="brand-copy"><strong>SecureBank</strong><span>Protected banking</span></div>
          <button className="icon-button mobile-close" onClick={closeMobile} aria-label="Close navigation"><X size={18} /></button>
        </div>

        <div className="sidebar-scroll">
          <div className="nav-group">
            <span className="nav-label">Overview</span>
            {bankingLinks.slice(0, 1).map(({ to, label, icon: Icon, end }) => <NavLink key={to} to={to} end={end} className="nav-item" onClick={closeMobile}><Icon size={18} /><span>{label}</span></NavLink>)}
          </div>
          <div className="nav-group">
            <span className="nav-label">Banking</span>
            {bankingLinks.slice(1).map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} className="nav-item" onClick={closeMobile}><Icon size={18} /><span>{label}</span></NavLink>)}
          </div>
          <div className="nav-group">
            <span className="nav-label">Security</span>
            <NavLink to="/security" className="nav-item security-nav-item" onClick={closeMobile}><ShieldCheck size={18} /><span>Security Center</span><span className="live-dot" /></NavLink>
          </div>
        </div>

        <div className="sidebar-footer">
          <div className="sidebar-secure"><span className="secure-dot" /> WAF protection active</div>
          <button className="nav-item settings-item" type="button" disabled title="Settings are not available in this banking workspace"><Settings size={18} /><span>Settings</span></button>
          <button className="nav-item signout-button" onClick={handleLogout}><LogOut size={18} /><span>Sign out</span></button>
        </div>
      </aside>

      <div className="shell-main">
        <header className="topbar">
          <div className="topbar-left">
            <button className="icon-button mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu size={21} /></button>
            <button className="icon-button collapse-button" onClick={() => setCollapsed(value => !value)} aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}>{collapsed ? <PanelLeftOpen size={19} /> : <PanelLeftClose size={19} />}</button>
            <div className="breadcrumb"><span>SecureBank</span><ChevronRight size={14} /><strong>{title}</strong></div>
          </div>
          <div className="topbar-actions">
            <div className="notification-wrap"><button className="icon-button notification-button" onClick={toggleNotifications} aria-label="Notifications" aria-expanded={notificationsOpen}><Bell size={18} /><span /></button>{notificationsOpen && <div className="notification-menu"><div className="notification-menu-heading"><strong>Security activity</strong><button type="button" onClick={viewAllNotifications}>View all</button></div>{notificationsLoading ? <div className="notification-empty">Loading alerts...</div> : notifications.length ? notifications.map(event => <NavLink className="notification-item" to="/security" key={event.event_id} onClick={() => setNotificationsOpen(false)}><span className={`notification-dot ${event.risk_level?.toLowerCase() || 'low'}`} /><span><strong>{event.attack_type?.replaceAll('_', ' ') || 'Security event'}</strong><small>{event.risk_level || 'LOW'} · {event.timestamp}</small></span></NavLink>) : <div className="notification-empty">No recent security events.</div>}</div>}</div>
            <div className="profile-wrap"><button className="profile-chip profile-button" onClick={() => setProfileOpen(value => !value)} aria-expanded={profileOpen}><div className="avatar">{initials}</div><div className="profile-copy"><strong>{displayName}</strong><span>Personal banking</span></div><ChevronRight size={14} className={profileOpen ? 'profile-chevron open' : 'profile-chevron'} /></button>{profileOpen && <div className="profile-menu"><div className="profile-menu-identity"><strong>{displayName}</strong><span>{identity?.username || 'Authenticated session'}</span></div><NavLink to="/profile" onClick={() => setProfileOpen(false)}>Profile</NavLink><NavLink to="/security" onClick={() => setProfileOpen(false)}>Security Center</NavLink><button type="button" onClick={handleLogout}>Sign out</button></div>}</div>
          </div>
        </header>
        <main className="content-area"><Outlet /></main>
      </div>
    </div>
  );
}
