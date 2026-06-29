import React, { useState, useEffect } from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';
import axios from 'axios';

const API = 'http://localhost:8000';

export default function Dashboard() {
  const [metrics, setMetrics] = useState({ total_threats: 0, auto_fixed: 0, critical: 0, rules_active: 0 });
  const [threats, setThreats] = useState([]);
  const [scanning, setScanning] = useState(false);
  const [status, setStatus] = useState('idle');

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const [metricsRes, threatsRes] = await Promise.all([
        axios.get(`${API}/api/metrics`),
        axios.get(`${API}/api/threats`)
      ]);
      setMetrics(metricsRes.data);
      setThreats(threatsRes.data.threats.reverse());
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
      fetchData();
    } catch (e) {
      setStatus('error');
    }
    setScanning(false);
  };

  const resetBucket = async () => {
    await axios.post(`${API}/api/reset-bucket`);
    setStatus('idle');
    alert('Bucket reset to vulnerable for testing!');
  };

  const chartData = threats.slice(0, 10).map((t, i) => ({
    name: `T${i + 1}`,
    threats: 1,
  }));

  return (
    <div style={styles.page}>
      {/* HEADER */}
      <div style={styles.header}>
        <div style={styles.logo}>
          <div style={styles.logoDot} />
          CloudSentinel
        </div>
        <div style={styles.headerRight}>
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
        </div>

        {/* MAIN */}
        <div style={styles.main}>

          {/* METRICS */}
          <div style={styles.metricsGrid}>
            {[
              { label: 'Active Threats', value: metrics.critical, color: '#ef4444' },
              { label: 'Auto Fixed', value: metrics.auto_fixed, color: '#2dd4bf' },
              { label: 'Total Detected', value: metrics.total_threats, color: '#94a3b8' },
              { label: 'Rules Active', value: metrics.rules_active, color: '#2dd4bf' },
            ].map(m => (
              <div key={m.label} style={styles.metricCard}>
                <div style={styles.metricLabel}>{m.label}</div>
                <div style={{ ...styles.metricValue, color: m.color }}>{m.value}</div>
              </div>
            ))}
          </div>

          {/* CHART */}
          <div style={styles.card}>
            <div style={styles.cardTitle}>Threat Activity</div>
            <ResponsiveContainer width="100%" height={120}>
              <AreaChart data={chartData}>
                <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 10 }} />
                <YAxis stroke="#94a3b8" tick={{ fontSize: 10 }} />
                <Tooltip />
                <Area type="monotone" dataKey="threats" stroke="#2dd4bf" fill="#ccfbf1" />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* CONTROLS */}
          <div style={styles.controls}>
            <button style={styles.scanBtn} onClick={runScan} disabled={scanning}>
              {scanning ? '⏳ Scanning...' : '🔍 Run Scan'}
            </button>
            <button style={styles.resetBtn} onClick={resetBucket}>
              ⚠️ Reset Bucket (Make Vulnerable)
            </button>
            {status === 'threat_found' && <div style={styles.alertBadge}>🚨 Threat detected and auto-fixed!</div>}
            {status === 'clear' && <div style={styles.clearBadge}>✅ All clear!</div>}
          </div>

          {/* THREAT FEED */}
          <div style={styles.card}>
            <div style={styles.cardTitle}>Live Threat Feed</div>
            {threats.length === 0 && (
              <div style={styles.emptyState}>No threats detected yet — run a scan!</div>
            )}
            {threats.map(t => (
              <div key={t.id} style={styles.threatRow}>
                <div style={{ ...styles.badge, ...(t.severity === 'CRITICAL' ? styles.critical : styles.high) }}>
                  {t.severity}
                </div>
                <div style={styles.threatName}>{t.threat.replace(/_/g, ' ')}</div>
                <div style={styles.fixedBadge}>{t.fixed ? '✅ AUTO-FIXED' : '❌ FAILED'}</div>
                <div style={styles.threatTime}>{new Date(t.timestamp).toLocaleTimeString()}</div>
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
  header: { background: '#fff', borderBottom: '1px solid #e2e8f0', padding: '12px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' },
  logo: { fontSize: 18, fontWeight: 600, color: '#0f172a', display: 'flex', alignItems: 'center', gap: 8 },
  logoDot: { width: 10, height: 10, borderRadius: '50%', background: '#2dd4bf' },
  headerRight: { display: 'flex', alignItems: 'center', gap: 12 },
  livePill: { display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: '#2dd4bf', background: '#f0fdfa', border: '1px solid #99f6e4', borderRadius: 20, padding: '3px 10px' },
  pulse: { width: 6, height: 6, borderRadius: '50%', background: '#2dd4bf', animation: 'pulse 1.5s infinite' },
  body: { display: 'flex', minHeight: 'calc(100vh - 53px)' },
  sidebar: { width: 180, background: '#fff', borderRight: '1px solid #e2e8f0', padding: '16px 0' },
  navItem: { padding: '10px 20px', fontSize: 13, color: '#64748b', cursor: 'pointer' },
  navActive: { color: '#2dd4bf', background: '#f0fdfa', borderLeft: '2px solid #2dd4bf', fontWeight: 500 },
  main: { flex: 1, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 },
  metricsGrid: { display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 },
  metricCard: { background: '#fff', border: '1px solid #e2e8f0', borderRadius: 10, padding: '14px 16px' },
  metricLabel: { fontSize: 11, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 6 },
  metricValue: { fontSize: 28, fontWeight: 600 },
  card: { background: '#fff', border: '1px solid #e2e8f0', borderRadius: 10, padding: 16 },
  cardTitle: { fontSize: 12, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 },
  controls: { display: 'flex', gap: 10, alignItems: 'center' },
  scanBtn: { background: '#2dd4bf', color: '#fff', border: 'none', borderRadius: 8, padding: '10px 20px', fontSize: 13, fontWeight: 500, cursor: 'pointer' },
  resetBtn: { background: '#fff', color: '#ef4444', border: '1px solid #ef4444', borderRadius: 8, padding: '10px 20px', fontSize: 13, cursor: 'pointer' },
  alertBadge: { background: '#fef2f2', color: '#ef4444', border: '1px solid #fecaca', borderRadius: 8, padding: '8px 14px', fontSize: 12 },
  clearBadge: { background: '#f0fdfa', color: '##2dd4bf', border: '1px solid #99f6e4', borderRadius: 8, padding: '8px 14px', fontSize: 12 },
  threatRow: { display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: '1px solid #f1f5f9', fontSize: 12 },
  badge: { fontSize: 10, fontWeight: 500, borderRadius: 4, padding: '2px 6px' },
  critical: { background: '#fef2f2', color: '#ef4444' },
  high: { background: '#fffbeb', color: '#f59e0b' },
  fixedBadge: { fontSize: 11, color: '#2dd4bf', marginLeft: 'auto' },
  threatTime: { fontSize: 10, color: '#94a3b8' },
  threatName: { flex: 1, color: '#0f172a' },
  emptyState: { color: '#94a3b8', fontSize: 13, textAlign: 'center', padding: '20px 0' },
};