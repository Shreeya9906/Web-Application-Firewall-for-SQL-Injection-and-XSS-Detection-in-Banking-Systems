import { Inbox } from 'lucide-react';

export default function EmptyState({ title, message }) {
  return <div className="empty-state"><Inbox size={24} aria-hidden="true" /><strong>{title}</strong>{message && <span>{message}</span>}</div>;
}
