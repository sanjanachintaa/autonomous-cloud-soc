import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import axios from 'axios';

const API = 'http://127.0.0.1:8000';

export default function Dashboard() {
  const [metrics, setMetrics] = useState({ total_threats: 0, auto_fixed: 0, critical: 0, rules_active: 0 });
  const [threats, setThreats] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [status, setStatus] = useState('idle');
  const [lastScan, setLastScan] = useState(null);
  const [autoScan, setAutoScan] = useState(false);
  const [siem, setSiem] = useState(null);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!autoScan) return;
    const interval = setInterval(() => {
      runScan();
    }, 15000);
    return () => clearInterval(interval);
  }, [autoScan]);

  const fetchData = async () => {
    try {
      const [metricsRes, threatsRes, siemRes] = await Promise.all([
        axios.get(`${API}/api/metrics`),
        axios.get(`${API}/api/threats`),
        axios.get(`${API}/api/siem/risk`)
      ]);
      setMetrics(metricsRes.data);
      setThreats([...threatsRes.data.threats].reverse());
      setSiem(siemRes.data);
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

  const chartData = [...threats].reverse().slice(-10).map((t, i) => ({
    name: new Date(t.timestamp).toLocaleTimeString(),
    threats: 1,
  }));

  const severityColor = (s) => s === 'CRITICAL' ? '#ef4444' : '#f59e0b';

  return (
    <div style={styles.page}>
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
          {[
            { label: 'Dashboard', active: true },
            { label: 'Threats' },
            { label: 'Remediation' },
            { label: 'Reports' },
            { label: 'Settings' },
          ].map(item => (
            <div key={item.label} style={{ ...styles.navItem, ...(item.active ? styles.navActive : {}) }}>
              {item.label}
            </div>
          ))}

          <div style={styles.sidebarDivider} />
          <div style={styles.sidebarLabel}>Auto Scan</div>
          <div
            style={{ ...styles.autoToggle, background: autoScan ? '#2dd4bf' : '#e2e8f0' }}
            onClick={() => setAutoScan(!autoScan)}
          >
            <div style={{ ...styles.toggleDot, transform: autoScan ? 'translateX(20px)' : 'translateX(2px)' }} />
          </div>
          {autoScan && <div style={styles.autoLabel}>Scanning every 15s</div>}
        </div>

        {/* MAIN */}
        <div style={styles.main}>

          {/* METRICS */}
          <div style={styles.metricsGrid}>
            {[
              { label: 'Active Threats', value: metrics.critical, color: '#ef4444', bg: '#fef2f2' },
              { label: 'Auto Fixed', value: metrics.auto_fixed, color: '#2dd4bf', bg: '#f0fdfa' },
              { label: 'Total Detected', value: metrics.total_threats, color: '#6366f1', bg: '#eef2ff' },
              { label: 'Rules Active', value: metrics.rules_active, color: '#f59e0b', bg: '#fffbeb' },
            ].map(m => (
              <div key={m.label} style={{ ...styles.metricCard, borderTop: `3px solid ${m.color}` }}>
                <div style={styles.metricLabel}>{m.label}</div>
                <div style={{ ...styles.metricValue, color: m.color }}>{m.value}</div>
              </div>
            ))}
          </div>

          {/* SIEM RISK PANEL */}
          {siem && (
            <div style={styles.row}>
              <div style={{ ...styles.card, flex: 1, borderTop: `3px solid ${siem.risk.level === 'CRITICAL' ? '#ef4444' : siem.risk.level === 'HIGH' ? '#f59e0b' : '#2dd4bf'}` }}>
                <div style={styles.cardTitle}>Overall Risk Score</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                  <div style={{ fontSize: 48, fontWeight: 800, color: siem.risk.level === 'CRITICAL' ? '#ef4444' : '#f59e0b' }}>
                    {siem.risk.score}
                  </div>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 700, color: siem.risk.level === 'CRITICAL' ? '#ef4444' : '#f59e0b' }}>
                      {siem.risk.level}
                    </div>
                    <div style={{ fontSize: 11, color: '#64748b', maxWidth: 200 }}>{siem.risk.summary}</div>
                  </div>
                </div>
              </div>

              <div style={{ ...styles.card, flex: 2 }}>
                <div style={styles.cardTitle}>Threat Correlations</div>
                {siem.correlations.length === 0 && (
                  <div style={styles.emptyState}>No correlations detected</div>
                )}
                {siem.correlations.map((c, i) => (
                  <div key={i} style={styles.correlationRow}>
                    <div style={styles.correlationName}>{c.name.replace(/_/g, ' ')}</div>
                    <div style={styles.correlationDesc}>{c.recommendation}</div>
                    <div style={{ ...styles.badge, background: '#fef2f2', color: '#ef4444', marginTop: 4, display: 'inline-block' }}>
                      Score: {c.score}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* CHART + CONTROLS ROW */}
          <div style={styles.row}>
            <div style={{ ...styles.card, flex: 2 }}>
              <div style={styles.cardTitle}>Threat Activity</div>
              <ResponsiveContainer width="100%" height={120}>
                <AreaChart data={chartData}>
                  <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 9 }} />
                  <YAxis stroke="#94a3b8" tick={{ fontSize: 9 }} />
                  <Tooltip />
                  <Area type="monotone" dataKey="threats" stroke="#2dd4bf" fill="#ccfbf1" />
                </AreaChart>
              </ResponsiveContainer>
            </div>

            <div style={{ ...styles.card, flex: 1, display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div style={styles.cardTitle}>Controls</div>
              <button style={styles.scanBtn} onClick={runScan} disabled={scanning}>
                {scanning ? '⏳ Scanning...' : '🔍 Run Scan'}
              </button>
              <button style={styles.resetBtn} onClick={resetAll}>
                ⚠️ Reset All Vulnerabilities
              </button>
              {status === 'threat_found' && <div style={styles.alertBadge}>🚨 Threats detected & fixed!</div>}
              {status === 'clear' && <div style={styles.clearBadge}>✅ All clear!</div>}
              {status === 'scanning' && <div style={styles.scanningBadge}>⏳ Scanning...</div>}
            </div>
          </div>

          {/* THREAT FEED */}
          <div style={styles.card}>
            <div style={styles.cardTitleRow}>
              <div style={styles.cardTitle}>Live Threat Feed</div>
              <div style={styles.threatCount}>{threats.length} total</div>
            </div>
            {threats.length === 0 && (
              <div style={styles.emptyState}>No threats detected yet — run a scan!</div>
            )}
            {threats.map((t, i) => (
              <div key={i} style={styles.threatRow}>
                <div style={{ ...styles.severityBar, background: severityColor(t.severity) }} />
                <div style={styles.threatInfo}>
                  <div style={styles.threatName}>{t.threat.replace(/_/g, ' ')}</div>
                  <div style={styles.threatDetail}>{t.detail}</div>
                </div>
                <div style={styles.threatMeta}>
                  <div style={{ ...styles.badge, background: severityColor(t.severity) + '20', color: severityColor(t.severity) }}>
                    {t.severity}
                  </div>
                  <div style={styles.fixedBadge}>
                    {t.fixed ? '✅ AUTO-FIXED' : '❌ FAILED'}
                  </div>
                  <div style={styles.threatTime}>
                    {new Date(t.timestamp).toLocaleTimeString()}
                  </div>
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
  scanningBadge: { background: '#fffbeb', color: '#f59e0b', border: '1px solid #fde68a', borderRadius: 8, padding: '8px 12px', fontSize: 11, textAlign: 'center' },
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
  correlationDesc: { fontSize: 11, color: '#64748b' }};