import { useState, useEffect } from 'react';
import { getTransactions } from '../services/api';
import Loading from '../components/Loading';
import ErrorMessage from '../components/ErrorMessage';
import PageHeader from '../components/PageHeader';
import StatusBadge from '../components/StatusBadge';

export default function Transactions() {
  const [transactions, setTransactions] = useState(null);
  const [filter, setFilter] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    setError('');
    getTransactions(filter).then(res => setTransactions(res.data.transactions)).catch(() => setError('Unable to load transactions.'));
  }, [filter]);

  if (!transactions && !error) return <Loading />;

  return (
    <div className="page-container">
      <PageHeader eyebrow="Activity" title="Transactions" description="Review recent account activity and movement of funds." />
      <ErrorMessage message={error} />
      <div className="filter-bar"><div className="filter-control"><label htmlFor="transaction-filter">Transaction type</label><select id="transaction-filter" value={filter} onChange={e => setFilter(e.target.value)}>
          <option value="">All</option>
          <option value="DEPOSIT">Deposit</option>
          <option value="WITHDRAWAL">Withdrawal</option>
          <option value="TRANSFER_IN">Transfer In</option>
          <option value="TRANSFER_OUT">Transfer Out</option>
        </select></div>{transactions && <span className="muted">{transactions.length} results</span>}</div>
      {transactions && <div className="table-scroll"><table className="data-table">
        <thead>
          <tr>
            <th>Date</th>
            <th>Ref</th>
            <th>Account</th>
            <th>Type</th>
            <th>Amount</th>
            <th>Balance After</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {transactions.map(txn => (
            <tr key={txn.transaction_id}>
              <td>{txn.transaction_date}</td>
              <td>{txn.reference_number}</td>
              <td className="mono">•••• {String(txn.account_number).slice(-4)}</td>
              <td>{txn.transaction_type}</td>
              <td>₹{Number(txn.amount).toLocaleString('en-IN', { minimumFractionDigits: 2 })}</td>
              <td>₹{Number(txn.balance_after_transaction).toLocaleString('en-IN', { minimumFractionDigits: 2 })}</td>
              <td><StatusBadge value={txn.transaction_status} /></td>
            </tr>
          ))}
        </tbody>
      </table></div>}
    </div>
  );
}
