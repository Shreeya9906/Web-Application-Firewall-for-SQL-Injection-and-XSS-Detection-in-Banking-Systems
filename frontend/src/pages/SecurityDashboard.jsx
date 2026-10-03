import { useEffect, useState } from 'react';
import { Activity, Check, Clock3, Eye, RefreshCw, ShieldAlert, ShieldCheck, X } from 'lucide-react';
import Loading from '../components/Loading';
import ErrorMessage from '../components/ErrorMessage';
import PageHeader from '../components/PageHeader';
import StatCard from '../components/StatCard';
import {
  getAttackDistribution,
  getDetectionSummary,
  getSecurityEvents,
  getSecuritySummary,
  getSecurityTrends,
  getAdaptiveRules,
  getBehaviorAlerts,
  reviewAdaptiveRule,
  reviewSecurityEvent
} from '../services/api';

const REFRESH_INTERVAL = 15000;

const statCards = [
  { key: 'total_events', label: 'Total Security Events', detail: 'Recorded by the WAF' },
  { key: 'blocked_events', label: 'Blocked Requests', detail: 'Requests stopped at the edge' },
  { key: 'sql_injection', label: 'SQL Injection', detail: 'TF-IDF + Decision Tree ML' },
  { key: 'xss', label: 'XSS Attacks', detail: 'Dedicated pattern detection' },
  { key: 'multiple_attacks', label: 'Multiple Attacks', detail: 'More than one signal detected' }
];

function formatAttackType(value) {
  return value.replaceAll('_', ' ');
}

function AttackBadge({ type }) {
  const className = type.toLowerCase().replaceAll('_', '-');
  return <span className={`attack-badge ${className}`}>{formatAttackType(type)}</span>;
}

function DistributionChart({ distribution }) {
  if (!distribution.length) return <p className="empty-state">No security events recorded.</p>;
  const largest = Math.max(...distribution.map(item => item.count), 1);

  return (
    <div className="distribution-chart" aria-label="Attack distribution">
      {distribution.map(item => (
        <div className="distribution-row" key={item.attack_type}>
          <div className="distribution-label">
            <AttackBadge type={item.attack_type} />
            <strong>{item.count}</strong>
          </div>
          <div className="distribution-track">
            <div
              className="distribution-fill"
              style={{ width: `${(item.count / largest) * 100}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

function TrendChart({ trends }) {
  if (!trends.length) return <p className="empty-state">No security events recorded.</p>;
  const largest = Math.max(...trends.map(item => item.count), 1);

  return (
    <div className="trend-chart" aria-label="Security events over time">
      {trends.map(item => (
        <div className="trend-column" key={item.date}>
          <span className="trend-count">{item.count}</span>
          <div className="trend-bar-track">
            <div className="trend-bar" style={{ height: `${(item.count / largest) * 100}%` }} />
          </div>
          <span className="trend-date">{item.date}</span>
        </div>
      ))}
    </div>
  );
}

export default function SecurityDashboard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [refreshing, setRefreshing] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [actionError, setActionError] = useState('');

  const loadSecurityData = async () => {
    setRefreshing(true);
    try {
      const [summary, events, distribution, trends, detectionSummary, adaptiveRules, behaviorAlerts] = await Promise.all([
        getSecuritySummary(),
        getSecurityEvents({ limit: 20 }),
        getAttackDistribution(),
        getSecurityTrends(),
        getDetectionSummary(),
        getAdaptiveRules(),
        getBehaviorAlerts()
      ]);
      setData({
        summary: summary.data,
        events: events.data.events || [],
        distribution: distribution.data.distribution || [],
        trends: trends.data.trends || [],
        detections: detectionSummary.data.detections || {},
        riskLevels: detectionSummary.data.risk_levels || {},
        suggestions: adaptiveRules.data.suggestions || [],
        behaviorAlerts: behaviorAlerts.data.alerts || []
      });
      setError('');
    } catch {
      setError('Unable to load security data.');
    } finally {
      setRefreshing(false);
    }
  };

  const reviewEvent = async (eventId, status) => {
    try { setActionError(''); await reviewSecurityEvent(eventId, status); await loadSecurityData(); } catch { setActionError('Unable to update this event review.'); }
  };

  const reviewRule = async (ruleId, status) => {
    try { setActionError(''); await reviewAdaptiveRule(ruleId, status); await loadSecurityData(); } catch { setActionError('Unable to update this rule suggestion.'); }
  };

  useEffect(() => {
    loadSecurityData();
    const timer = setInterval(loadSecurityData, REFRESH_INTERVAL);
    return () => clearInterval(timer);
  }, []);

  if (!data && !error) return <Loading />;

  return (
    <div className="page-container security-dashboard">
      <PageHeader eyebrow="Security operations" title="Security Center" description="Real-time protection and threat monitoring." actions={<button className="button button-secondary" onClick={loadSecurityData} disabled={refreshing}><RefreshCw size={15} className={refreshing ? 'spin' : ''} /> Refresh</button>} />
      <div className="security-header">
        <div>
          <p className="eyebrow">Web application firewall</p>
          <h2>Protection is active</h2>
          <p className="security-subtitle">SQL Injection, XSS, and behavioral monitoring are watching every API request.</p>
        </div>
        <div className="waf-status"><span className="secure-dot" /> Active / monitoring</div>
      </div>

      <ErrorMessage message={error} />
      <ErrorMessage message={actionError} />

      {data && (
        <>
          <section className="security-stats" aria-label="Security statistics">
            {statCards.map(card => <StatCard key={card.key} label={card.label} value={data.summary[card.key] ?? 0} detail={card.detail} />)}
          </section>

          <section className="security-panel protection-grid"><div className="panel-heading"><div><ShieldCheck size={18} /><h3>Protection layers</h3></div><span className="panel-kicker">Last updated just now</span></div><div className="detection-summary-grid"><div className="detection-summary-item"><span><ShieldCheck size={14} /> SQL Injection</span><strong>Protected</strong><small>ML detection active</small></div><div className="detection-summary-item"><span><ShieldCheck size={14} /> XSS</span><strong>Protected</strong><small>Rule detection active</small></div><div className="detection-summary-item"><span><ShieldCheck size={14} /> Behavioral</span><strong>Monitoring</strong><small>Repeated activity watch</small></div></div></section>

          <section className="security-visuals">
            <div className="security-panel">
              <div className="panel-heading">
                <div><Activity size={18} aria-hidden="true" /><h3>Attack Distribution</h3></div>
                <span className="panel-kicker">All recorded events</span>
              </div>
              <DistributionChart distribution={data.distribution} />
            </div>
            <div className="security-panel">
              <div className="panel-heading">
                <div><ShieldAlert size={18} aria-hidden="true" /><h3>Attack Trend</h3></div>
                <span className="panel-kicker">By date</span>
              </div>
              <TrendChart trends={data.trends} />
            </div>
          </section>

          <section className="security-panel detection-summary-panel">
            <div className="panel-heading">
              <div><Activity size={18} aria-hidden="true" /><h3>Detection Summary</h3></div>
              <span className="panel-kicker">Mechanism by attack type</span>
            </div>
            <div className="detection-summary-grid">
              {['sql_injection', 'xss', 'multiple_attacks'].map(type => {
                const detection = data.detections[type] || { count: 0, source: type === 'sql_injection' ? 'ML' : type === 'xss' ? 'RULE' : 'HYBRID' };
                return (
                  <div className="detection-summary-item" key={type}>
                    <span>{formatAttackType(type)}</span>
                    <strong>{detection.count}</strong>
                    <small>{detection.source} detection</small>
                  </div>
                );
              })}
            </div>
          </section>

          <section className="security-panel">
            <div className="panel-heading"><div><ShieldAlert size={18} aria-hidden="true" /><h3>Behavioral Alerts</h3></div><span className="panel-kicker">Recent repeated activity</span></div>
            {data.behaviorAlerts.length ? <div className="behavior-alert-list">{data.behaviorAlerts.map((alert, index) => <div className="behavior-alert" key={`${alert.attack_type}-${index}`}><strong>{alert.behavior_type.replaceAll('_', ' ')}</strong><span>Source: {alert.source}</span><span>Attack count: {alert.attack_count}</span><span>Window: {Math.round(alert.window_seconds / 60)} minutes</span><span className="risk-badge critical">{alert.risk_level}</span></div>)}</div> : <p className="empty-state">No repeated attack activity detected.</p>}
          </section>

          <section className="security-panel events-panel" id="security-events">
            <div className="panel-heading">
              <div><ShieldAlert size={18} aria-hidden="true" /><h3>Recent Security Events</h3></div>
              <span className="panel-kicker">Latest 20</span>
            </div>
            {data.events.length ? (
              <div className="table-scroll">
                <table className="data-table security-events-table">
                  <thead><tr><th>Timestamp</th><th>Attack Type</th><th>Source</th><th>Risk</th><th>Method</th><th>Endpoint</th><th>Explanation</th><th>Notification</th><th>Action</th></tr></thead>
                  <tbody>
                    {data.events.map(event => (
                      <tr key={event.event_id}>
                        <td>{event.timestamp}</td>
                        <td><AttackBadge type={event.attack_type || 'UNKNOWN'} /></td>
                        <td>{event.source || 'UNKNOWN'}</td>
                        <td><span className={`risk-badge ${event.risk_level?.toLowerCase() || 'low'}`}>{event.risk_level || 'LOW'}</span></td>
                        <td>{event.http_method}</td>
                        <td className="endpoint-cell">{event.endpoint}</td>
                        <td>{event.explanation || event.reason || 'WAF event'}</td>
                        <td><span className={`action-badge notification-${event.notification_status?.toLowerCase() || 'not_sent'}`}>{event.notification_status || 'NOT_SENT'}</span></td>
                        <td>
                          <button type="button" className="text-button" onClick={() => setSelectedEvent(event)}><Eye size={14} /> Details</button>
                          <span className="action-badge">{event.review_status || 'UNREVIEWED'}</span>
                          {event.review_status === 'UNREVIEWED' && <div className="review-actions">
                            <button type="button" title="Confirm attack" onClick={() => reviewEvent(event.event_id, 'CONFIRMED_ATTACK')}><Check size={14} aria-hidden="true" /></button>
                            <button type="button" title="Mark false positive" onClick={() => reviewEvent(event.event_id, 'FALSE_POSITIVE')}><X size={14} aria-hidden="true" /></button>
                          </div>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : <p className="empty-state">No security events recorded.</p>}
          </section>

          <section className="security-panel">
            <div className="panel-heading"><div><ShieldAlert size={18} aria-hidden="true" /><h3>Adaptive Rule Suggestions</h3></div><span className="panel-kicker">Human approval required</span></div>
            {data.suggestions.length ? <div className="table-scroll"><table className="data-table"><thead><tr><th>Attack Type</th><th>Pattern Summary</th><th>Occurrences</th><th>Reason</th><th>Status</th><th>Action</th></tr></thead><tbody>
              {data.suggestions.map(rule => <tr key={rule.id}><td><AttackBadge type={rule.attack_type} /></td><td>{rule.rule_pattern}</td><td>{rule.occurrence_count}</td><td>{rule.reason}</td><td>{rule.status}</td><td>{rule.status === 'SUGGESTED' && <div className="review-actions"><button type="button" title="Approve suggestion" onClick={() => reviewRule(rule.id, 'APPROVED')}><Check size={14} aria-hidden="true" /></button><button type="button" title="Reject suggestion" onClick={() => reviewRule(rule.id, 'REJECTED')}><X size={14} aria-hidden="true" /></button></div>}</td></tr>)}
            </tbody></table></div> : <p className="empty-state">No adaptive rule suggestions.</p>}
          </section>
          {selectedEvent && <div className="drawer-backdrop" onClick={() => setSelectedEvent(null)}><aside className="event-drawer" onClick={event => event.stopPropagation()}><div className="panel-heading"><div><ShieldAlert size={18} /><h3>Event details</h3></div><button className="icon-button" onClick={() => setSelectedEvent(null)} aria-label="Close event details"><X size={18} /></button></div><div className="drawer-event-type"><AttackBadge type={selectedEvent.attack_type} /><span className={`risk-badge ${selectedEvent.risk_level?.toLowerCase() || 'low'}`}>{selectedEvent.risk_level || 'LOW'}</span></div><dl className="detail-grid"><div className="detail-item"><dt>Timestamp</dt><dd>{selectedEvent.timestamp}</dd></div><div className="detail-item"><dt>Decision</dt><dd>{selectedEvent.action || 'BLOCK'}</dd></div><div className="detail-item"><dt>Detection source</dt><dd>{selectedEvent.source || 'UNKNOWN'}</dd></div><div className="detail-item"><dt>HTTP method</dt><dd>{selectedEvent.http_method}</dd></div><div className="detail-item"><dt>Endpoint</dt><dd className="mono">{selectedEvent.endpoint}</dd></div><div className="detail-item"><dt>Review status</dt><dd>{selectedEvent.review_status || 'UNREVIEWED'}</dd></div></dl><div className="drawer-explanation"><span>Explanation</span><p>{selectedEvent.explanation || selectedEvent.reason || 'WAF event'}</p></div></aside></div>}
        </>
      )}
    </div>
  );
}