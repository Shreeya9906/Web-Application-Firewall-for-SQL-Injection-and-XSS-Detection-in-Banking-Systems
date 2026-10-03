export default function StatusBadge({ value, className = '' }) {
  const normalized = String(value || 'UNKNOWN').toLowerCase().replaceAll(' ', '-');
  return <span className={`status-badge ${normalized} ${className}`}>{value || 'UNKNOWN'}</span>;
}
