import React, { useState, useEffect, useRef } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar } from 'recharts';
import axios from 'axios';

const API = 'http://127.0.0.1:8000';

export default function Dashboard() {
  const [metrics, setMetrics] = useState({ total_threats: 0, auto_fixed: 0, critical: 0, rules_active: 0 });
  const [threats, setThreats] = useState([]);
  const [siem, setSiem] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [status, setStatus] = useState('idle');
  const [lastScan, setLastScan] = useState(null);
  const [autoScan, setAutoScan] = useState(false);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [threatDetail, setThreatDetail] = useState(null);
  const [notifications, setNotifications] = useState([]);
  const notifId = useRef(0);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!autoScan) return;
    const interval = setInterval(() => { runScan(); }, 15000);
    return () => clearInterval(interval);
  }, [autoScan]);

  // Real-time alert stream
  useEffect(() => {
    const es = new EventSource(`${API}/api/alerts/stream`);
    es.onmessage = (e) => {
      const threat = JSON.parse(e.data);
      addNotification(threat);
    };
    return () => es.close();
  }, []);

  const addNotification = (threat) => {
    const id = notifId.current++;
    setNotifications(prev => [...prev, { ...threat, notifId: id }]);
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.notifId !== id));
    }, 5000);
  };

  const fetchData = async () => {
    try {
      const [metricsRes, threatsRes, siemRes, timelineRes] = await Promise.all([
        axios.get(`${API}/api/metrics`),
        axios.get(`${API}/api/threats`),
        axios.get(`${API}/api/siem/risk`),
        axios.get(`${API}/api/siem/timeline`)
      ]);
      setMetrics(metricsRes.data);
      setThreats([...threatsRes.data.threats].reverse());
      setSiem(siemRes.data);
      setTimeline(timelineRes.data.timeline);
    } catch (e) {
      console.error(e);
    }
  };

  const runScan = async () => {
    setScanning(true);
    setStatus('scanning');
    try {
      const res = await axios.post(`${API}/api/scan`);
      if (res.data.detected) setStatus('threat_found');
      else setStatus('clear');
      setLastScan(new Date().toLocaleTimeString());
      fetchData();
    } catch (e) {
      setStatus('error');
    }
    setScanning(false);
  };

  const resetAll = async () => {
    try {
      await Promise.all([
        axios.post(`${API}/api/reset-bucket`),
        axios.post(`${API}/api/reset-versioning`),
        axios.post(`${API}/api/reset-security-group`),
      ]);
      setStatus('idle');
      alert('✅ All vulnerabilities reset for testing!');
    } catch (e) {
      console.error(e);
    }
  };

  const openThreatDetail = async (threat) => {
    setSelectedThreat(threat);
    try {
      const res = await axios.get(`${API}/api/threats/${threat.id}`);
      setThreatDetail(res.data);
    } catch (e) {
      setThreatDetail({ threat, related_correlations: [] });
    }
  };

  const severityColor = (s) => s === 'CRITICAL' ? '#ef4444' : s === 'HIGH' ? '#f59e0b' : '#2dd4bf';

  const chartData = [...threats].reverse().slice(-10).map((t) => ({
    name: new Date(t.timestamp).toLocaleTimeString(),
    score: t.score || 50,
  }));

  const timelineData = timeline.slice(-8).map(t => ({
    name: t.event.split(' ').slice(0, 2).join(' '),
    score: t.score,
    fixed: t.fixed ? 1 : 0,
  }));

  const riskColor = siem?.risk?.level === 'CRITICAL' ? '#ef4444' : siem?.risk?.level === 'HIGH' ? '#f59e0b' : '#2dd4bf';

  return (
    <div style={styles.page}>

      {/* REAL TIME NOTIFICATIONS */}
      <div style={styles.notifContainer}>
        {notifications.map(n => (
          <div key={n.notifId} style={{ ...styles.notif, borderLeft: `4px solid ${severityColor(n.severity)}` }}>
            <div style={{ fontSize: 13, fontWeight: 700, color: severityColor(n.severity) }}>
              🚨 {n.threat.replace(/_/g, ' ')}
            </div>
            <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>{n.detail}</div>
            <div style={{ fontSize: 10, color: '#94a3b8', marginTop: 2 }}>
              {n.fixed ? '✅ Auto-fixed' : '❌ Fix failed'}
            </div>
          </div>
        ))}
      </div>

      {/* THREAT DETAIL MODAL */}
      {selectedThreat && (
        <div style={styles.modalOverlay} onClick={() => { setSelectedThreat(null); setThreatDetail(null); }}>
          <div style={styles.modal} onClick={e => e.stopPropagation()}>
            <div style={styles.modalHeader}>
              <div style={{ fontSize: 15, fontWeight: 700, color: '#0f172a' }}>
                🔍 Threat Investigation
              </div>
              <button style={styles.closeBtn} onClick={() => { setSelectedThreat(null); setThreatDetail(null); }}>✕</button>
            </div>

            <div style={styles.modalSection}>
              <div style={styles.modalLabel}>Threat Type</div>
              <div style={{ ...styles.modalValue, color: severityColor(selectedThreat.severity) }}>
                {selectedThreat.threat.replace(/_/g, ' ')}
              </div>
            </div>

            <div style={styles.modalSection}>
              <div style={styles.modalLabel}>Detail</div>
              <div style={styles.modalValue}>{selectedThreat.detail}</div>
            </div>

            <div style={styles.modalSection}>
              <div style={styles.modalLabel}>CIS Rule Violated</div>
              <div style={{ ...styles.modalValue, color: '#6366f1' }}>{selectedThreat.cis_rule || 'N/A'}</div>
            </div>

            <div style={styles.modalSection}>
              <div style={styles.modalLabel}>Risk Score</div>
              <div style={{ ...styles.modalValue, color: severityColor(selectedThreat.severity) }}>
                {selectedThreat.score}/100
              </div>
            </div>

            <div style={styles.modalSection}>
              <div style={styles.modalLabel}>Status</div>
              <div style={styles.modalValue}>{selectedThreat.fixed ? '✅ Auto-remediated' : '❌ Not fixed'}</div>
            </div>

            <div style={styles.modalSection}>
              <div style={styles.modalLabel}>AI Analysis</div>
              <div style={{ ...styles.modalValue, fontSize: 11, background: '#f8fafc', padding: 10, borderRadius: 6, whiteSpace: 'pre-wrap', maxHeight: 150, overflowY: 'auto' }}>
                {selectedThreat.analysis || 'No analysis available'}
              </div>
            </div>

            {threatDetail?.related_correlations?.length > 0 && (
              <div style={styles.modalSection}>
                <div style={styles.modalLabel}>Related Attack Scenarios</div>
                {threatDetail.related_correlations.map((c, i) => (
                  <div key={i} style={{ background: '#fef2f2', border: '1px solid #fecaca', borderRadius: 6, padding: 8, marginTop: 6 }}>
                    <div style={{ fontSize: 12, fontWeight: 700, color: '#ef4444' }}>{c.name.replace(/_/g, ' ')}</div>
                    <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>{c.recommendation}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* HEADER */}
      <div style={styles.header}>
        <div style={styles.logoGroup}>
          <div style={styles.logoDot} />
          <span style={styles.logoText}>CloudSentinel</span>
          <span style={styles.tagline}>Autonomous SOC Platform</span>
        </div>
        <div style={styles.headerRight}>
          {lastScan && <span style={styles.lastScan}>Last scan: {lastScan}</span>}
          <div style={styles.livePill}>
            <div style={styles.pulse} />
            Live
          </div>
        </div>
      </div>

      <div style={styles.body}>
        {/* SIDEBAR */}
        <div style={styles.sidebar}>
          {['Dashboard', 'Threats', 'Remediation', 'Reports', 'Settings'].map((item, i) => (
            <div key={item} style={{ ...styles.navItem, ...(i === 0 ? styles.navActive : {}) }}>
              {item}
            </div>
          ))}
          <div style={styles.sidebarDivider} />
          <div style={styles.sidebarLabel}>Auto Scan</div>
          <div style={{ ...styles.autoToggle, background: autoScan ? '#2dd4bf' : '#e2e8f0' }} onClick={() => setAutoScan(!autoScan)}>
            <div style={{ ...styles.toggleDot, transform: autoScan ? 'translateX(20px)' : 'translateX(2px)' }} />
          </div>
          {autoScan && <div style={styles.autoLabel}>Scanning every 15s</div>}
        </div>

        {/* MAIN */}
        <div style={styles.main}>

          {/* METRICS */}
          <div style={styles.metricsGrid}>
            {[
              { label: 'Active Threats', value: metrics.critical, color: '#ef4444' },
              { label: 'Auto Fixed', value: metrics.auto_fixed, color: '#2dd4bf' },
              { label: 'Total Detected', value: metrics.total_threats, color: '#6366f1' },
              { label: 'Rules Active', value: metrics.rules_active, color: '#f59e0b' },
            ].map(m => (
              <div key={m.label} style={{ ...styles.metricCard, borderTop: `3px solid ${m.color}` }}>
                <div style={styles.metricLabel}>{m.label}</div>
                <div style={{ ...styles.metricValue, color: m.color }}>{m.value}</div>
              </div>
            ))}
          </div>

          {/* SIEM RISK + CORRELATIONS */}
          {siem && (
            <div style={styles.row}>
              <div style={{ ...styles.card, flex: 1, borderTop: `3px solid ${riskColor}` }}>
                <div style={styles.cardTitle}>Overall Risk Score</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                  <div style={{ fontSize: 52, fontWeight: 800, color: riskColor }}>{siem.risk.score}</div>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: riskColor }}>{siem.risk.level}</div>
                    <div style={{ fontSize: 11, color: '#64748b', maxWidth: 180 }}>{siem.risk.summary}</div>
                  </div>
                </div>
              </div>

              <div style={{ ...styles.card, flex: 2 }}>
                <div style={styles.cardTitle}>Threat Correlations</div>
                {siem.correlations.length === 0
                  ? <div style={styles.emptyState}>No correlations — run a scan first</div>
                  : siem.correlations.map((c, i) => (
                    <div key={i} style={styles.correlationRow}>
                      <div style={styles.correlationName}>{c.name.replace(/_/g, ' ')}</div>
                      <div style={styles.correlationDesc}>{c.recommendation}</div>
                      <span style={{ ...styles.badge, background: '#fef2f2', color: '#ef4444', marginTop: 4, display: 'inline-block' }}>
                        Score: {c.score}
                      </span>
                    </div>
                  ))
                }
              </div>
            </div>
          )}

          {/* CHARTS ROW */}
          <div style={styles.row}>
            <div style={{ ...styles.card, flex: 1 }}>
              <div style={styles.cardTitle}>Threat Score History</div>
              <ResponsiveContainer width="100%" height={120}>
                <AreaChart data={chartData}>
                  <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 9 }} />
                  <YAxis stroke="#94a3b8" tick={{ fontSize: 9 }} domain={[0, 100]} />
                  <Tooltip />
                  <Area type="monotone" dataKey="score" stroke="#ef4444" fill="#fef2f2" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div style={{ ...styles.card, flex: 1 }}>
              <div style={styles.cardTitle}>Attack Timeline</div>
              {timelineData.length === 0
                ? <div style={styles.emptyState}>No timeline data yet</div>
                : <ResponsiveContainer width="100%" height={120}>
                  <BarChart data={timelineData}>
                    <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 9 }} />
                    <YAxis stroke="#94a3b8" tick={{ fontSize: 9 }} domain={[0, 100]} />
                    <Tooltip />
                    <Bar dataKey="score" fill="#6366f1" radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              }
            </div>

            <div style={{ ...styles.card, flex: 1, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={styles.cardTitle}>Controls</div>
              <button style={styles.scanBtn} onClick={runScan} disabled={scanning}>
                {scanning ? '⏳ Scanning...' : '🔍 Run Scan'}
              </button>
              <button style={styles.resetBtn} onClick={resetAll}>
                ⚠️ Reset All
              </button>
              {status === 'threat_found' && <div style={styles.alertBadge}>🚨 Threats detected & fixed!</div>}
              {status === 'clear' && <div style={styles.clearBadge}>✅ All clear!</div>}
            </div>
          </div>

          {/* THREAT FEED */}
          <div style={styles.card}>
            <div style={styles.cardTitleRow}>
              <div style={styles.cardTitle}>Live Threat Feed</div>
              <div style={styles.threatCount}>{threats.length} total — click any row to investigate</div>
            </div>
            {threats.length === 0 && <div style={styles.emptyState}>No threats detected yet — run a scan!</div>}
            {threats.map((t, i) => (
              <div key={i} style={{ ...styles.threatRow, cursor: 'pointer' }} onClick={() => openThreatDetail(t)}>
                <div style={{ ...styles.severityBar, background: severityColor(t.severity) }} />
                <div style={styles.threatInfo}>
                  <div style={styles.threatName}>{t.threat.replace(/_/g, ' ')}</div>
                  <div style={styles.threatDetail}>{t.detail}</div>
                  <div style={{ fontSize: 10, color: '#6366f1', marginTop: 2 }}>{t.cis_rule}</div>
                </div>
                <div style={styles.threatMeta}>
                  <div style={{ ...styles.badge, background: severityColor(t.severity) + '20', color: severityColor(t.severity) }}>
                    {t.severity}
                  </div>
                  <div style={styles.fixedBadge}>{t.fixed ? '✅ AUTO-FIXED' : '❌ FAILED'}</div>
                  <div style={styles.threatTime}>{new Date(t.timestamp).toLocaleTimeString()}</div>
                </div>
              </div>
            ))}
          </div>

        </div>
      </div>
    </div>
  );
}

const styles = {
  page: { minHeight: '100vh', background: '#f8fafc', fontFamily: 'system-ui, sans-serif' },
  notifContainer: { position: 'fixed', top: 16, right: 16, zIndex: 1000, display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 320 },
  notif: { background: '#fff', border: '1px solid #e2e8f0', borderRadius: 8, padding: '10px 14px', boxShadow: '0 4px 12px rgba(0,0,0,0.1)', animation: 'slideIn 0.3s ease' },
  modalOverlay: { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.4)', zIndex: 500, display: 'flex', alignItems: 'center', justifyContent: 'center' },
  modal: { background: '#fff', borderRadius: 12, padding: 24, width: 480, maxHeight: '80vh', overflowY: 'auto', boxShadow: '0 20px 60px rgba(0,0,0,0.2)' },
  modalHeader: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 },
  modalSection: { marginBottom: 14 },
  modalLabel: { fontSize: 10, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 4, fontWeight: 600 },
  modalValue: { fontSize: 13, color: '#0f172a', fontWeight: 500 },
  closeBtn: { background: 'none', border: 'none', fontSize: 16, cursor: 'pointer', color: '#94a3b8' },
  header: { background: '#fff', borderBottom: '1px solid #e2e8f0', padding: '12px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', position: 'sticky', top: 0, zIndex: 10 },
  logoGroup: { display: 'flex', alignItems: 'center', gap: 10 },
  logoText: { fontSize: 18, fontWeight: 700, color: '#0f172a' },
  tagline: { fontSize: 11, color: '#94a3b8', background: '#f1f5f9', borderRadius: 4, padding: '2px 8px' },
  logoDot: { width: 10, height: 10, borderRadius: '50%', background: '#2dd4bf' },
  headerRight: { display: 'flex', alignItems: 'center', gap: 12 },
  lastScan: { fontSize: 11, color: '#94a3b8' },
  livePill: { display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: '#2dd4bf', background: '#f0fdfa', border: '1px solid #99f6e4', borderRadius: 20, padding: '3px 10px' },
  pulse: { width: 6, height: 6, borderRadius: '50%', background: '#2dd4bf' },
  body: { display: 'flex', minHeight: 'calc(100vh - 53px)' },
  sidebar: { width: 180, background: '#fff', borderRight: '1px solid #e2e8f0', padding: '16px 0' },
  navItem: { padding: '10px 20px', fontSize: 13, color: '#64748b', cursor: 'pointer' },
  navActive: { color: '#2dd4bf', background: '#f0fdfa', borderLeft: '2px solid #2dd4bf', fontWeight: 500 },
  sidebarDivider: { borderTop: '1px solid #e2e8f0', margin: '12px 0' },
  sidebarLabel: { fontSize: 11, color: '#94a3b8', padding: '0 20px', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.5px' },
  autoToggle: { width: 44, height: 24, borderRadius: 12, margin: '0 20px', cursor: 'pointer', position: 'relative', transition: 'background 0.2s' },
  toggleDot: { width: 20, height: 20, borderRadius: '50%', background: '#fff', position: 'absolute', top: 2, transition: 'transform 0.2s', boxShadow: '0 1px 3px rgba(0,0,0,0.2)' },
  autoLabel: { fontSize: 10, color: '#2dd4bf', padding: '4px 20px' },
  main: { flex: 1, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 },
  metricsGrid: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 },
  metricCard: { background: '#fff', border: '1px solid #e2e8f0', borderRadius: 10, padding: '14px 16px' },
  metricLabel: { fontSize: 11, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 6 },
  metricValue: { fontSize: 28, fontWeight: 700 },
  row: { display: 'flex', gap: 16 },
  card: { background: '#fff', border: '1px solid #e2e8f0', borderRadius: 10, padding: 16 },
  cardTitle: { fontSize: 11, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12, fontWeight: 600 },
  cardTitleRow: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 },
  threatCount: { fontSize: 11, color: '#94a3b8', background: '#f1f5f9', borderRadius: 10, padding: '2px 8px' },
  scanBtn: { background: '#2dd4bf', color: '#fff', border: 'none', borderRadius: 8, padding: '10px 16px', fontSize: 13, fontWeight: 600, cursor: 'pointer', width: '100%' },
  resetBtn: { background: '#fff', color: '#ef4444', border: '1px solid #fecaca', borderRadius: 8, padding: '10px 16px', fontSize: 13, cursor: 'pointer', width: '100%' },
  alertBadge: { background: '#fef2f2', color: '#ef4444', border: '1px solid #fecaca', borderRadius: 8, padding: '8px 12px', fontSize: 11, textAlign: 'center' },
  clearBadge: { background: '#f0fdfa', color: '#2dd4bf', border: '1px solid #99f6e4', borderRadius: 8, padding: '8px 12px', fontSize: 11, textAlign: 'center' },
  threatRow: { display: 'flex', alignItems: 'center', gap: 12, padding: '10px 0', borderBottom: '1px solid #f1f5f9' },
  severityBar: { width: 3, height: 40, borderRadius: 2, flexShrink: 0 },
  threatInfo: { flex: 1 },
  threatName: { fontSize: 13, fontWeight: 600, color: '#0f172a', marginBottom: 2 },
  threatDetail: { fontSize: 11, color: '#64748b' },
  threatMeta: { display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 },
  badge: { fontSize: 10, fontWeight: 600, borderRadius: 4, padding: '2px 6px' },
  fixedBadge: { fontSize: 11, color: '#2dd4bf', fontWeight: 500 },
  threatTime: { fontSize: 10, color: '#94a3b8' },
  emptyState: { color: '#94a3b8', fontSize: 13, textAlign: 'center', padding: '30px 0' },
  correlationRow: { padding: '8px 0', borderBottom: '1px solid #f1f5f9' },
  correlationName: { fontSize: 12, fontWeight: 700, color: '#0f172a', marginBottom: 2 },
  correlationDesc: { fontSize: 11, color: '#64748b' },
};