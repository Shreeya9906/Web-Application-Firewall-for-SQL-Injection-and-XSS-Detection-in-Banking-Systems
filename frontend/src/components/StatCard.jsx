export default function StatCard({ label, value, detail, icon: Icon }) {
  return <div className="security-stat">{Icon && <Icon size={17} aria-hidden="true" className="stat-icon" />}<span className="stat-label">{label}</span><strong>{value}</strong>{detail && <span className="stat-detail">{detail}</span>}</div>;
}
