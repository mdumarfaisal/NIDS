import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bell,
  Blocks,
  CheckCircle2,
  ChevronRight,
  Cpu,
  Database,
  Download,
  Gauge,
  Globe,
  MonitorCog,
  Network,
  Server,
  Shield,
  ShieldAlert,
  Wifi,
  Zap,
} from 'lucide-react'
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import './App.css'

const API_BASE = 'http://localhost:8002'

const navItems = [
  'Dashboard',
  'Network Topology',
  'Live Packets',
  'Raw Scapy Data',
  'Packet Analysis',
  'Protocol Analysis',
  'IP Analysis',
  'Port Monitoring',
  'Intrusion Detection',
  'Attack Analysis',
  'Alerts',
  'Reports',
  'CN Concepts',
  'Architecture',
  'Settings',
]

const baselineStats = {
  totalPackets: 18420,
  incomingPackets: 10230,
  outgoingPackets: 8190,
  normalPackets: 15890,
  suspiciousPackets: 1685,
  detectedAttacks: 11,
  blockedConnections: 34,
}

const trafficHistory = [
  { time: '10:00', TCP: 160, UDP: 100, ICMP: 26 },
  { time: '10:05', TCP: 188, UDP: 118, ICMP: 32 },
  { time: '10:10', TCP: 176, UDP: 108, ICMP: 35 },
  { time: '10:15', TCP: 214, UDP: 136, ICMP: 28 },
  { time: '10:20', TCP: 260, UDP: 184, ICMP: 42 },
  { time: '10:25', TCP: 286, UDP: 210, ICMP: 65 },
  { time: '10:30', TCP: 318, UDP: 228, ICMP: 72 },
  { time: '10:35', TCP: 292, UDP: 196, ICMP: 48 },
]

const trafficDistribution = [
  { name: 'TCP', value: 46 },
  { name: 'UDP', value: 24 },
  { name: 'ICMP', value: 11 },
  { name: 'DNS', value: 10 },
  { name: 'HTTP/HTTPS', value: 9 },
]

const protocolStats = [
  { protocol: 'TCP', count: 8260, percentage: 42, avgSize: 1420, sourceCount: 18, destCount: 9 },
  { protocol: 'UDP', count: 4310, percentage: 22, avgSize: 980, sourceCount: 11, destCount: 8 },
  { protocol: 'ICMP', count: 2140, percentage: 11, avgSize: 620, sourceCount: 6, destCount: 4 },
  { protocol: 'DNS', count: 1900, percentage: 10, avgSize: 385, sourceCount: 12, destCount: 7 },
  { protocol: 'HTTP', count: 1520, percentage: 8, avgSize: 840, sourceCount: 9, destCount: 5 },
  { protocol: 'HTTPS', count: 1290, percentage: 7, avgSize: 920, sourceCount: 7, destCount: 6 },
]

const ipStats = [
  { ip: '192.168.1.10', packets: 1250, type: 'Internal', risk: 'Normal' },
  { ip: '192.168.1.11', packets: 980, type: 'Internal', risk: 'Normal' },
  { ip: '192.168.1.25', packets: 760, type: 'Suspicious', risk: 'High' },
  { ip: '192.168.1.100', packets: 1420, type: 'Internal', risk: 'Protected' },
]

const portMonitoring = [
  { port: 21, protocol: 'FTP', connections: 48, status: 'Closed', risk: 'Medium' },
  { port: 22, protocol: 'SSH', connections: 130, status: 'Open', risk: 'Low' },
  { port: 23, protocol: 'Telnet', connections: 16, status: 'Closed', risk: 'High' },
  { port: 25, protocol: 'SMTP', connections: 62, status: 'Open', risk: 'Medium' },
  { port: 53, protocol: 'DNS', connections: 188, status: 'Open', risk: 'Low' },
  { port: 80, protocol: 'HTTP', connections: 231, status: 'Open', risk: 'Medium' },
  { port: 443, protocol: 'HTTPS', connections: 214, status: 'Open', risk: 'Low' },
  { port: 3389, protocol: 'RDP', connections: 29, status: 'Closed', risk: 'High' },
]

const alertData = [
  {
    severity: 'HIGH',
    title: 'Port Scanning Detected',
    source: '192.168.1.25',
    target: '192.168.1.100',
    ports: '21, 22, 23, 25, 80',
    protocol: 'TCP',
    confidence: '97.4%',
  },
  {
    severity: 'MEDIUM',
    title: 'Suspicious TCP Handshake',
    source: '192.168.1.33',
    target: '192.168.1.100',
    ports: '22',
    protocol: 'TCP',
    confidence: '86.2%',
  },
]

const attackTimeline = [
  { time: '08:00', DoS: 1, PortScan: 0, BruteForce: 2, Unauthorized: 1 },
  { time: '09:00', DoS: 2, PortScan: 1, BruteForce: 2, Unauthorized: 0 },
  { time: '10:00', DoS: 4, PortScan: 2, BruteForce: 3, Unauthorized: 1 },
  { time: '11:00', DoS: 5, PortScan: 3, BruteForce: 4, Unauthorized: 2 },
  { time: '12:00', DoS: 3, PortScan: 4, BruteForce: 3, Unauthorized: 1 },
]

const modelMetrics = [
  { label: 'Accuracy', value: 96.8 },
  { label: 'Precision', value: 95.2 },
  { label: 'Recall', value: 94.1 },
  { label: 'F1 Score', value: 94.7 },
]

const defaultTopologyDevices = [
  { name: 'Internet', ip: 'N/A', mac: 'N/A', status: 'Connected', protocol: 'IP', risk: 'Low', type: 'globe' },
  { name: 'Router', ip: '192.168.1.1', mac: '00:AA:BB:CC:DD:01', status: 'Active', protocol: 'TCP/IP', risk: 'Low', type: 'router' },
  { name: 'Switch', ip: '192.168.1.2', mac: '00:AA:BB:CC:DD:02', status: 'Active', protocol: 'Ethernet', risk: 'Low', type: 'switch' },
  { name: 'PC-01', ip: '192.168.1.10', mac: '00:AA:BB:CC:DD:10', status: 'Online', protocol: 'TCP', risk: 'Low', type: 'computer' },
  { name: 'PC-02', ip: '192.168.1.11', mac: '00:AA:BB:CC:DD:11', status: 'Online', protocol: 'UDP', risk: 'Medium', type: 'computer' },
  { name: 'Server', ip: '192.168.1.100', mac: '00:AA:BB:CC:DD:99', status: 'Protected', protocol: 'TCP/IP', risk: 'Low', type: 'server' },
]

const conceptData = [
  'OSI Model',
  'TCP/IP Model',
  'IP Addressing',
  'MAC Address',
  'TCP',
  'UDP',
  'ICMP',
  'DNS',
  'HTTP/HTTPS',
  'Ports',
  'Packets',
  'Routing',
  'Switching',
  'Client-Server Communication',
  'Network Security',
]

const pieColors = ['#38bdf8', '#60a5fa', '#a78bfa', '#fbbf24', '#f87171']

const protocolFilterOptions = ['ALL', 'TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SUSPICIOUS', 'NORMAL']

const severityMap = {
  HIGH: 'alert',
  MEDIUM: 'warning',
  LOW: 'normal',
}

function formatStat(n) {
  return n.toLocaleString()
}

function App() {
  const [activeSection, setActiveSection] = useState('Dashboard')
  const [monitoring, setMonitoring] = useState(true)
  const [protocolFilter, setProtocolFilter] = useState('ALL')
  const [topologyDevices, setTopologyDevices] = useState(defaultTopologyDevices)
  const [selectedTopology, setSelectedTopology] = useState(defaultTopologyDevices[3])
  const [rawPackets, setRawPackets] = useState([])
  const [selectedPacket, setSelectedPacket] = useState(null)
  const [packets, setPackets] = useState([])
  const [apiError, setApiError] = useState('')
  const [stats, setStats] = useState({
    totalPackets: 0,
    incomingPackets: 0,
    outgoingPackets: 0,
    normalPackets: 0,
    suspiciousPackets: 0,
    detectedAttacks: 0,
    blockedConnections: 0,
  })
  const [apiTraffic, setApiTraffic] = useState(trafficHistory)
  const [apiProtocols, setApiProtocols] = useState(protocolStats)
  const [apiIps, setApiIps] = useState(ipStats)
  const [apiPorts, setApiPorts] = useState(portMonitoring)
  const [apiAlerts, setApiAlerts] = useState(alertData)
  const [apiAttacks, setApiAttacks] = useState(attackTimeline)
  const [apiMetrics, setApiMetrics] = useState(modelMetrics)
  const [apiReport, setApiReport] = useState({
    tcpPackets: 8260,
    udpPackets: 4310,
    icmpPackets: 2140,
    normalTraffic: 15890,
    suspiciousTraffic: 1685,
    detectedAttacks: 11,
    recommendations: ['Enable firewall restrictions', 'Review suspicious sources', 'Monitor RDP and Telnet'],
  })

  const trafficDistributionData = useMemo(() => {
    if (!apiProtocols?.length) return trafficDistribution
    const total = apiProtocols.reduce((sum, item) => sum + (item.count ?? 0), 0) || 1
    return apiProtocols.map((item, index) => ({
      name: item.protocol,
      value: Math.max(1, Math.round((item.count / total) * 100)),
      color: pieColors[index % pieColors.length],
    }))
  }, [apiProtocols])

  const topIpSummary = useMemo(() => apiIps.slice(0, 3).map((item) => `${item.ip} → ${item.packets} packets`).join(', '), [apiIps])
  const portScanSummary = useMemo(() => {
    if (!apiAlerts.length) return 'No live scan activity detected.'
    return `${apiAlerts[0].source} attempted connections to ${apiAlerts[0].ports}`
  }, [apiAlerts])

  const refreshFromApi = async () => {
    try {
      const [dashboardRes, rawPacketsRes, trafficRes, protocolsRes, ipsRes, portsRes, alertsRes, attacksRes, metricsRes, reportRes, topologyRes] = await Promise.all([
        fetch(`${API_BASE}/api/dashboard`),
        fetch(`${API_BASE}/api/raw-packets`),
        fetch(`${API_BASE}/api/traffic`),
        fetch(`${API_BASE}/api/protocols`),
        fetch(`${API_BASE}/api/ips`),
        fetch(`${API_BASE}/api/ports`),
        fetch(`${API_BASE}/api/alerts`),
        fetch(`${API_BASE}/api/attacks`),
        fetch(`${API_BASE}/api/model-performance`),
        fetch(`${API_BASE}/api/report`),
        fetch(`${API_BASE}/api/network-topology`),
      ])

      const failedResponse = [dashboardRes, rawPacketsRes, trafficRes, protocolsRes, ipsRes, portsRes, alertsRes, attacksRes, metricsRes, reportRes, topologyRes].find((response) => !response.ok)
      if (failedResponse) {
        throw new Error(`Backend request failed: ${failedResponse.status} ${failedResponse.url}`)
      }

      const dashboardData = await dashboardRes.json()
      const rawPacketData = await rawPacketsRes.json()
      const trafficData = await trafficRes.json()
      const protocolData = await protocolsRes.json()
      const ipData = await ipsRes.json()
      const portData = await portsRes.json()
      const alertDataFromApi = await alertsRes.json()
      const attackData = await attacksRes.json()
      const metricsData = await metricsRes.json()
      const reportData = await reportRes.json()
      const topologyData = await topologyRes.json()

      setStats({
        totalPackets: dashboardData.totalPackets ?? 0,
        incomingPackets: dashboardData.incomingPackets ?? 0,
        outgoingPackets: dashboardData.outgoingPackets ?? 0,
        normalPackets: dashboardData.normalPackets ?? 0,
        suspiciousPackets: dashboardData.suspiciousPackets ?? 0,
        detectedAttacks: dashboardData.detectedAttacks ?? 0,
        blockedConnections: dashboardData.blockedConnections ?? 0,
      })

      setRawPackets(Array.isArray(rawPacketData) ? rawPacketData : [])
      setApiTraffic(trafficData.length ? trafficData : [])
      setApiProtocols(protocolData.length ? protocolData : protocolStats)
      setApiIps(ipData.length ? ipData : ipStats)
      setApiPorts(portData.length ? portData : portMonitoring)
      setApiAlerts(alertDataFromApi.length ? alertDataFromApi : alertData)
      setApiAttacks(attackData.length ? attackData : attackTimeline)
      setApiMetrics([
        { label: 'Accuracy', value: metricsData.accuracy ?? 0 },
        { label: 'Precision', value: metricsData.precision ?? 0 },
        { label: 'Recall', value: metricsData.recall ?? 0 },
        { label: 'F1 Score', value: metricsData.f1_score ?? 0 },
      ])
      setApiReport(reportData)
      setTopologyDevices(Array.isArray(topologyData) && topologyData.length ? topologyData : defaultTopologyDevices)
      setSelectedTopology((currentSelected) => {
        const nextTopology = Array.isArray(topologyData) && topologyData.length ? topologyData : defaultTopologyDevices
        return nextTopology.find((device) => device.name === currentSelected?.name) ?? nextTopology[0]
      })
      setMonitoring((dashboardData.monitoringStatus ?? 'ACTIVE') === 'ACTIVE')
      setApiError('')
    } catch (error) {
      setRawPackets([])
      setApiTraffic([])
      setApiProtocols(protocolStats)
      setApiIps(ipStats)
      setApiPorts(portMonitoring)
      setApiAlerts(alertData)
      setApiAttacks(attackTimeline)
      setApiMetrics(modelMetrics)
      setTopologyDevices(defaultTopologyDevices)
      setSelectedTopology(defaultTopologyDevices[0])
      setMonitoring(false)
      setApiError(error instanceof Error ? error.message : 'Unable to connect to the packet monitoring backend.')
    }
  }

  const handleMonitoringToggle = async () => {
    const nextMonitoring = !monitoring
    setMonitoring(nextMonitoring)

    try {
      await fetch(`${API_BASE}/api/${nextMonitoring ? 'start-monitoring' : 'stop-monitoring'}`, {
        method: 'POST',
      })
      await refreshFromApi()
    } catch (error) {
      setMonitoring(!nextMonitoring)
      setApiError(error instanceof Error ? error.message : 'Unable to update packet monitoring.')
    }
  }

  useEffect(() => {
    const timer = setInterval(() => {
      refreshFromApi()
    }, 4000)

    return () => clearInterval(timer)
  }, [])

  useEffect(() => {
    let cancelled = false

    const refreshLivePackets = async () => {
      try {
        const response = await fetch(`${API_BASE}/api/packets?protocol=${encodeURIComponent(protocolFilter)}`)
        if (!response.ok) {
          throw new Error(`Live packet request failed: ${response.status}`)
        }

        const packetData = await response.json()
        if (cancelled) return

        const livePackets = Array.isArray(packetData) ? packetData : []
        setPackets(livePackets)
        setSelectedPacket((current) => livePackets.find((packet) => String(packet.id) === String(current?.id)) ?? livePackets[0] ?? null)
        setApiError('')
      } catch (error) {
        if (cancelled) return
        setPackets([])
        setSelectedPacket(null)
        setApiError(error instanceof Error ? error.message : 'Unable to load live packets.')
      }
    }

    refreshLivePackets()
    const timer = setInterval(refreshLivePackets, 1000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [protocolFilter])

  const filteredPackets = useMemo(() => {
    if (protocolFilter === 'ALL') return packets
    if (protocolFilter === 'SUSPICIOUS') return packets.filter((packet) => packet.status === 'SUSPICIOUS')
    if (protocolFilter === 'NORMAL') return packets.filter((packet) => packet.status === 'NORMAL')
    return packets.filter((packet) => packet.protocol === protocolFilter)
  }, [packets, protocolFilter])

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><Shield size={20} /></div>
          <div>
            <div style={{ fontSize: '0.76rem', color: '#7dd3fc', letterSpacing: '0.14em' }}>CN PROJECT</div>
            <strong style={{ color: '#f8fafc' }}>NIDS</strong>
          </div>
        </div>

        <div className="nav-section">
          {navItems.map((item) => (
            <button
              key={item}
              type="button"
              className={`nav-item ${activeSection === item ? 'active' : ''}`}
              onClick={() => setActiveSection(item)}
            >
              <span className="group">
                {item === 'Dashboard' && <Gauge size={16} />}
                {item === 'Network Topology' && <Network size={16} />}
                {item === 'Live Packets' && <Activity size={16} />}
                {item === 'Raw Scapy Data' && <Database size={16} />}
                {item === 'Packet Analysis' && <Database size={16} />}
                {item === 'Protocol Analysis' && <Blocks size={16} />}
                {item === 'IP Analysis' && <Globe size={16} />}
                {item === 'Port Monitoring' && <Server size={16} />}
                {item === 'Intrusion Detection' && <ShieldAlert size={16} />}
                {item === 'Attack Analysis' && <Zap size={16} />}
                {item === 'Alerts' && <Bell size={16} />}
                {item === 'Reports' && <Download size={16} />}
                {item === 'CN Concepts' && <Cpu size={16} />}
                {item === 'Architecture' && <MonitorCog size={16} />}
                {item === 'Settings' && <Wifi size={16} />}
                <span>{item}</span>
              </span>
              <ChevronRight size={14} />
            </button>
          ))}
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div>
            <h1>{activeSection}</h1>
          </div>

          <div className="status-line">
            <span className="badge">ONLINE</span>
            <span className="badge warning">{monitoring ? 'ACTIVE' : 'IDLE'}</span>
            <span className="badge alert">LIVE CAPTURE</span>
          </div>

          <div className="toolbar">
            <button type="button" className="primary-btn" onClick={handleMonitoringToggle}>
              {monitoring ? 'STOP MONITORING' : 'START MONITORING'}
            </button>
            <button type="button" className="secondary-btn">EXPORT PACKETS</button>
          </div>
        </header>

        <div className="content">
          {activeSection === 'Dashboard' && (
            <>
              <div className="stats-grid">
                <StatCard label="Total Packets" value={formatStat(stats.totalPackets)} icon={<Network size={18} />} delta="+12.4%" />
                <StatCard label="Incoming Packets" value={formatStat(stats.incomingPackets)} icon={<ArrowRight size={18} />} delta="+8.2%" />
                <StatCard label="Outgoing Packets" value={formatStat(stats.outgoingPackets)} icon={<ArrowRight size={18} />} delta="+6.7%" />
                <StatCard label="Normal Packets" value={formatStat(stats.normalPackets)} icon={<CheckCircle2 size={18} />} delta="+10.1%" />
                <StatCard label="Suspicious Packets" value={formatStat(stats.suspiciousPackets)} icon={<AlertTriangle size={18} />} delta="+3.5%" />
                <StatCard label="Detected Attacks" value={formatStat(stats.detectedAttacks)} icon={<ShieldAlert size={18} />} delta="+2" />
                <StatCard label="Blocked Connections" value={formatStat(stats.blockedConnections)} icon={<Shield size={18} />} delta="+5" />
              </div>

              <div className="grid-two">
                <div className="card panel">
                  <div className="panel-header">
                    <h3>Time vs Packet Count</h3>
                    <span className="badge warning">TCP / UDP / ICMP</span>
                  </div>
                  <div className="chart-wrap">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={apiTraffic}>
                        <defs>
                          <linearGradient id="tcpFill" x1="0" x2="0" y1="0" y2="1">
                            <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.8} />
                            <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.1} />
                          </linearGradient>
                          <linearGradient id="udpFill" x1="0" x2="0" y1="0" y2="1">
                            <stop offset="5%" stopColor="#a78bfa" stopOpacity={0.8} />
                            <stop offset="95%" stopColor="#a78bfa" stopOpacity={0.1} />
                          </linearGradient>
                          <linearGradient id="icmpFill" x1="0" x2="0" y1="0" y2="1">
                            <stop offset="5%" stopColor="#fbbf24" stopOpacity={0.8} />
                            <stop offset="95%" stopColor="#fbbf24" stopOpacity={0.1} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                        <XAxis dataKey="time" stroke="#94a3b8" />
                        <YAxis stroke="#94a3b8" />
                        <Tooltip />
                        <Area type="monotone" dataKey="TCP" stroke="#38bdf8" fill="url(#tcpFill)" strokeWidth={2} />
                        <Area type="monotone" dataKey="UDP" stroke="#a78bfa" fill="url(#udpFill)" strokeWidth={2} />
                        <Area type="monotone" dataKey="ICMP" stroke="#fbbf24" fill="url(#icmpFill)" strokeWidth={2} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                <div className="card panel">
                  <div className="panel-header">
                    <h3>Traffic Distribution</h3>
                  </div>
                  <div className="chart-wrap" style={{ height: 240 }}>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={trafficDistributionData} dataKey="value" nameKey="name" innerRadius={48} outerRadius={82} paddingAngle={2}>
                          {trafficDistributionData.map((entry, index) => (
                            <Cell key={`${entry.name}-${index}`} fill={entry.color ?? pieColors[index % pieColors.length]} />
                          ))}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="legend-box">
                    {trafficDistributionData.map((item, index) => (
                      <div key={`${item.name}-${index}`} className="legend-item">
                        <span className="dot" style={{ background: item.color ?? pieColors[index % pieColors.length] }} />
                        {item.name}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </>
          )}

          {activeSection === 'Network Topology' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>Network Topology</h3>
                <span className="badge">Packet Transmission</span>
              </div>

              <div className="topology-wrap">
                <div className="node-grid">
                  {topologyDevices.map((device, index) => (
                    <div
                      key={device.name}
                      className={`device-node ${selectedTopology.name === device.name ? 'selected' : ''}`}
                      onClick={() => setSelectedTopology(device)}
                    >
                      <div className="device-icon">
                        {device.type === 'globe' && <Globe size={20} />}
                        {device.type === 'router' && <Network size={20} />}
                        {device.type === 'switch' && <Blocks size={20} />}
                        {device.type === 'computer' && <Server size={20} />}
                        {device.type === 'server' && <Database size={20} />}
                      </div>
                      <div className="device-meta">
                        <strong>{device.name}</strong>
                        <span>{device.ip}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="device-detail card">
                <div className="panel-header">
                  <h4>{selectedTopology.name}</h4>
                  <span className="status-pill normal">{selectedTopology.status}</span>
                </div>
                <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))' }}>
                  <MetricBox label="IP Address" value={selectedTopology.ip} />
                  <MetricBox label="MAC Address" value={selectedTopology.mac} />
                  <MetricBox label="Protocol" value={selectedTopology.protocol} />
                  <MetricBox label="Risk" value={selectedTopology.risk} />
                </div>
              </div>
            </div>
          )}

          {activeSection === 'Live Packets' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>Live Packet Monitor</h3>
                <span className="badge">Continuously Updating</span>
              </div>

              <div className="filter-row">
                {protocolFilterOptions.map((option) => (
                  <button
                    key={option}
                    type="button"
                    className={protocolFilter === option ? 'active' : ''}
                    onClick={() => setProtocolFilter(option)}
                  >
                    {option}
                  </button>
                ))}
              </div>

              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Source IP</th>
                      <th>Destination IP</th>
                      <th>Source Port</th>
                      <th>Destination Port</th>
                      <th>Protocol</th>
                      <th>Packet Length</th>
                      <th>Flags</th>
                      <th>Status</th>
                      <th>Prediction</th>
                    </tr>
                  </thead>
                  <tbody>
                    {apiError ? (
                      <tr><td colSpan="10" role="alert" style={{ textAlign: 'center', color: '#fca5a5', padding: '18px' }}>{apiError}</td></tr>
                    ) : filteredPackets.length ? filteredPackets.map((packet) => (
                        <tr key={packet.id} onClick={() => setSelectedPacket(packet)} style={{ cursor: 'pointer' }}>
                          <td>{packet.timestamp}</td>
                          <td>{packet.sourceIp}</td>
                          <td>{packet.destinationIp}</td>
                          <td>{packet.sourcePort}</td>
                          <td>{packet.destinationPort}</td>
                          <td>{packet.protocol}</td>
                          <td>{packet.packetLength} bytes</td>
                          <td>{packet.flags}</td>
                          <td>
                            <span className={`status-pill ${packet.status.toLowerCase()}`}>
                              {packet.status}
                            </span>
                          </td>
                          <td>{packet.prediction}</td>
                        </tr>
                      )) : (
                        <tr><td colSpan="10" style={{ textAlign: 'center', color: '#94a3b8', padding: '18px' }}>No live packets captured yet. Generate network traffic and check the ICMP filter for ping packets.</td></tr>
                      )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeSection === 'Raw Scapy Data' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>Raw Scapy Data</h3>
                <span className="badge">Captured via Npcap</span>
              </div>

              <div className="table-wrap" style={{ overflowX: 'auto' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Src IP</th>
                      <th>Dst IP</th>
                      <th>Proto</th>
                      <th>Ports</th>
                      <th>Length</th>
                      <th>Flags</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rawPackets.length ? rawPackets.map((packet, index) => (
                      <tr key={`${packet.timestamp ?? 'packet'}-${index}`}>
                        <td>{packet.timestamp ?? 'N/A'}</td>
                        <td>{packet.sourceIp ?? '0.0.0.0'}</td>
                        <td>{packet.destinationIp ?? '0.0.0.0'}</td>
                        <td>{packet.protocol ?? 'OTHER'}</td>
                        <td>{packet.sourcePort ?? 0}:{packet.destinationPort ?? 0}</td>
                        <td>{packet.packetLength ?? 0}</td>
                        <td>{packet.flags ?? '-'}</td>
                        <td>{packet.status ?? 'UNKNOWN'}</td>
                      </tr>
                    )) : (
                      <tr>
                        <td colSpan="8" style={{ textAlign: 'center', color: '#94a3b8', padding: '18px' }}>No raw packets captured yet.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeSection === 'Packet Analysis' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>Packet Analysis</h3>
                <span className="badge">Selected Packet</span>
              </div>

              {selectedPacket ? (
                <>
                  <div className="stats-grid">
                    <MetricBox label="Source IP" value={selectedPacket.sourceIp} />
                    <MetricBox label="Destination IP" value={selectedPacket.destinationIp} />
                    <MetricBox label="Source Port" value={selectedPacket.sourcePort} />
                    <MetricBox label="Destination Port" value={selectedPacket.destinationPort} />
                    <MetricBox label="Protocol" value={selectedPacket.protocol} />
                    <MetricBox label="Packet Length" value={`${selectedPacket.packetLength} bytes`} />
                    <MetricBox label="TTL" value={selectedPacket.ttl} />
                    <MetricBox label="TCP Flags" value={selectedPacket.tcpFlags ?? selectedPacket.flags} />
                    <MetricBox label="Sequence Number" value={selectedPacket.seq ?? 'N/A'} />
                    <MetricBox label="Ack Number" value={selectedPacket.ack ?? 'N/A'} />
                  </div>

                  <div className="panel" style={{ marginTop: 18 }}>
                    <h4 style={{ color: '#f8fafc', margin: '0 0 14px' }}>Networking Meaning</h4>
                    <div className="concept-list">
                      <div className="concept-item"><strong>Source IP:</strong> Identifies the sender of the packet in the network.</div>
                      <div className="concept-item"><strong>Destination IP:</strong> Indicates the intended receiver or target host.</div>
                      <div className="concept-item"><strong>Source Port / Destination Port:</strong> Maps traffic to application services like HTTP (80), HTTPS (443), SSH (22), and DNS (53).</div>
                      <div className="concept-item"><strong>TTL:</strong> Controls the number of router hops a packet can traverse before being discarded.</div>
                      <div className="concept-item"><strong>TCP Flags:</strong> SYN, ACK, FIN, RST, and PSH control connection setup, transfer, and termination.</div>
                      <div className="concept-item"><strong>Sequence Number:</strong> Helps reconstruct packet ordering and detect retransmissions or missing data.</div>
                    </div>
                  </div>
                </>
              ) : (
                <div className="concept-item">No live packet is available for analysis yet.</div>
              )}
            </div>
          )}

          {activeSection === 'Protocol Analysis' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>Protocol Analysis</h3>
                <span className="badge">TCP / UDP / ICMP / DNS / HTTP / HTTPS</span>
              </div>

              <div className="grid-two">
                <div className="chart-wrap" style={{ height: 280 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={apiProtocols}>
                      <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                      <XAxis dataKey="protocol" stroke="#94a3b8" />
                      <YAxis stroke="#94a3b8" />
                      <Tooltip />
                      <Bar dataKey="count" fill="#38bdf8" radius={[6, 6, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <div className="chart-wrap" style={{ height: 280 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={apiProtocols} dataKey="percentage" nameKey="protocol" innerRadius={45} outerRadius={90} paddingAngle={2}>
                        {apiProtocols.map((entry, index) => (
                          <Cell key={entry.protocol} fill={pieColors[index % pieColors.length]} />
                        ))}
                      </Pie>
                      <Tooltip />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              </div>

              <div className="table-wrap" style={{ marginTop: 18 }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Protocol</th>
                      <th>Packet Count</th>
                      <th>Percentage</th>
                      <th>Avg Packet Size</th>
                      <th>Source Count</th>
                      <th>Destination Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {apiProtocols.map((row) => (
                      <tr key={row.protocol}>
                        <td>{row.protocol}</td>
                        <td>{row.count}</td>
                        <td>{row.percentage}%</td>
                        <td>{row.avgSize} bytes</td>
                        <td>{row.sourceCount}</td>
                        <td>{row.destCount}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {activeSection === 'IP Analysis' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>IP Address Analysis</h3>
                <span className="badge">Source and Destination Traffic</span>
              </div>

              <div className="stats-grid">
                {apiIps.map((item) => (
                  <div className="metric-box" key={item.ip}>
                    <span>{item.ip}</span>
                    <strong>{item.packets}</strong>
                    <small style={{ color: '#cbd5e1' }}>{item.type} · {item.risk}</small>
                  </div>
                ))}
              </div>

              <div className="panel" style={{ marginTop: 18 }}>
                <h4 style={{ color: '#f8fafc', margin: '0 0 12px' }}>Traffic View</h4>
                <div className="concept-list">
                  <div className="concept-item"><strong>Top Source IPs:</strong> {topIpSummary || 'No packet data available yet.'}</div>
                  <div className="concept-item"><strong>Top Destination IPs:</strong> {apiIps[0] ? `${apiIps[0].ip} is receiving the most monitored inbound traffic.` : 'No destination data available yet.'}</div>
                  <div className="concept-item"><strong>Internal / External:</strong> {apiIps.filter((item) => item.type === 'Internal').length} internal sources and {apiIps.filter((item) => item.type === 'External').length} external sources are currently tracked.</div>
                  <div className="concept-item"><strong>Blocked IPs:</strong> {apiIps.filter((item) => item.risk === 'High').length} source IPs currently flagged as high risk.</div>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'Port Monitoring' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>Port Analysis</h3>
                <span className="badge alert">Scan Detection Enabled</span>
              </div>

              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Port</th>
                      <th>Protocol</th>
                      <th>Connection Count</th>
                      <th>Status</th>
                      <th>Risk Level</th>
                    </tr>
                  </thead>
                  <tbody>
                    {apiPorts.map((row) => (
                      <tr key={row.port}>
                        <td>{row.port}</td>
                        <td>{row.protocol}</td>
                        <td>{row.connections}</td>
                        <td>{row.status}</td>
                        <td>{row.risk}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              <div className="panel" style={{ marginTop: 18 }}>
                <h4 style={{ color: '#f8fafc', margin: '0 0 12px' }}>Possible Port Scanning Detected</h4>
                <div className="alert-item">
                  <div className="alert-title">
                    <span>{portScanSummary || 'No port scan activity detected.'}</span>
                    <span className="badge alert">{apiAlerts.length ? 'CRITICAL' : 'NORMAL'}</span>
                  </div>
                  <div className="alert-body">
                    {apiAlerts.length
                      ? 'The source host performed a rapid sequence of port probes across common TCP services, which is consistent with active reconnaissance or port scanning.'
                      : 'No active reconnaissance pattern is currently being observed in the monitored packet stream.'}
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'Intrusion Detection' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>Intrusion Detection</h3>
                <span className="badge">NORMAL / SUSPICIOUS / MALICIOUS</span>
              </div>

              <div className="metric-grid">
                <div className="metric-box"><span>Prediction</span><strong>{apiAlerts[0]?.severity ? 'SUSPICIOUS' : 'NORMAL'}</strong></div>
                <div className="metric-box"><span>Confidence</span><strong>{apiAlerts[0]?.confidence ?? '0%'}</strong></div>
                <div className="metric-box"><span>Attack Type</span><strong>{apiAlerts[0]?.title ?? 'No active alert'}</strong></div>
                <div className="metric-box"><span>Severity</span><strong>{apiAlerts[0]?.severity ?? 'NORMAL'}</strong></div>
              </div>

              <div className="panel" style={{ marginTop: 18 }}>
                <h4 style={{ color: '#f8fafc', margin: '0 0 12px' }}>Attack Categories</h4>
                <div className="concept-list">
                  <div className="concept-item">DoS / DDoS</div>
                  <div className="concept-item">Port Scanning</div>
                  <div className="concept-item">Brute Force</div>
                  <div className="concept-item">Unauthorized Access</div>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'Attack Analysis' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>Attack Analysis</h3>
                <span className="badge">Timeline Overview</span>
              </div>

              <div className="chart-wrap" style={{ height: 300 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={apiAttacks}>
                    <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                    <XAxis dataKey="time" stroke="#94a3b8" />
                    <YAxis stroke="#94a3b8" />
                    <Tooltip />
                    <Line type="monotone" dataKey="DoS" stroke="#f87171" strokeWidth={2} />
                    <Line type="monotone" dataKey="PortScan" stroke="#fbbf24" strokeWidth={2} />
                    <Line type="monotone" dataKey="BruteForce" stroke="#a78bfa" strokeWidth={2} />
                    <Line type="monotone" dataKey="Unauthorized" stroke="#38bdf8" strokeWidth={2} />
                  </LineChart>
                </ResponsiveContainer>
              </div>

              <div className="metric-grid" style={{ marginTop: 14 }}>
                <div className="metric-box"><span>DoS Attacks</span><strong>{apiAttacks.reduce((total, item) => total + (item.DoS ?? 0), 0)}</strong></div>
                <div className="metric-box"><span>Port Scans</span><strong>{apiAttacks.reduce((total, item) => total + (item.PortScan ?? 0), 0)}</strong></div>
                <div className="metric-box"><span>Brute Force</span><strong>{apiAttacks.reduce((total, item) => total + (item.BruteForce ?? 0), 0)}</strong></div>
                <div className="metric-box"><span>Unauthorized Access</span><strong>{apiAttacks.reduce((total, item) => total + (item.Unauthorized ?? 0), 0)}</strong></div>
              </div>
            </div>
          )}

          {activeSection === 'Alerts' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>Security Alerts</h3>
                <span className="badge alert">Real-Time Alert Feed</span>
              </div>

              <div className="alert-stack">
                {apiAlerts.map((alert) => (
                  <div className="alert-item" key={alert.title}>
                    <div className="alert-title">
                      <span>⚠ {alert.severity} SEVERITY</span>
                      <span>{alert.title}</span>
                    </div>
                    <div className="alert-body">
                      Source IP: {alert.source}<br />
                      Target: {alert.target}<br />
                      Ports: {alert.ports}<br />
                      Protocol: {alert.protocol}<br />
                      Confidence: {alert.confidence}
                    </div>
                    <div className="alert-actions">
                      <button type="button" className="small-btn primary">Investigate</button>
                      <button type="button" className="small-btn">Block IP</button>
                      <button type="button" className="small-btn">Dismiss</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeSection === 'Reports' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>Network Security Report</h3>
                <span className="badge">Downloadable Summary</span>
              </div>

              <div className="metric-grid">
                <MetricBox label="Total Packets" value={formatStat(stats.totalPackets)} />
                <MetricBox label="TCP Packets" value={formatStat(apiReport.tcpPackets ?? 0)} />
                <MetricBox label="UDP Packets" value={formatStat(apiReport.udpPackets ?? 0)} />
                <MetricBox label="ICMP Packets" value={formatStat(apiReport.icmpPackets ?? 0)} />
                <MetricBox label="Normal Traffic" value={formatStat(apiReport.normalTraffic ?? 0)} />
                <MetricBox label="Suspicious Traffic" value={formatStat(apiReport.suspiciousTraffic ?? 0)} />
                <MetricBox label="Detected Attacks" value={formatStat(apiReport.detectedAttacks ?? 0)} />
                <MetricBox label="ML Accuracy" value={`${apiMetrics[0]?.value ?? 0}%`} />
              </div>

              <div className="panel" style={{ marginTop: 18 }}>
                <h4 style={{ color: '#f8fafc', margin: '0 0 12px' }}>Security Recommendations</h4>
                <div className="concept-list">
                  {(apiReport.recommendations ?? []).map((item) => (
                    <div className="concept-item" key={item}>{item}</div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeSection === 'CN Concepts' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>CN Concepts</h3>
                <span className="badge">Networking Fundamentals</span>
              </div>

              <div className="concept-list">
                {conceptData.map((concept) => (
                  <div className="concept-item" key={concept}><strong>{concept}:</strong> A core networking concept used in packet inspection, routing, protocol analysis, and intrusion detection.</div>
                ))}
              </div>
            </div>
          )}

          {activeSection === 'Architecture' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>System Architecture</h3>
                <span className="badge">Data Flow</span>
              </div>

              <div className="arch-wrap">
                <div className="arch-flow">
                  <div className="arch-box">Your PC / Network</div>
                  <div className="arch-arrow">↓</div>
                  <div className="arch-box">Real Packets</div>
                  <div className="arch-arrow">↓</div>
                  <div className="arch-box">Scapy</div>
                  <div className="arch-arrow">↓</div>
                  <div className="arch-box">Feature Extraction</div>
                  <div className="arch-arrow">↓</div>
                  <div className="arch-box">Detection Engine</div>
                  <div className="arch-arrow">↓</div>
                  <div className="arch-box">FastAPI Backend</div>
                  <div className="arch-arrow">↓</div>
                  <div className="arch-box">React Dashboard</div>
                  <div className="arch-arrow">↓</div>
                  <div className="arch-box">Live Charts + Alerts</div>
                </div>
              </div>
            </div>
          )}

          {activeSection === 'Settings' && (
            <div className="card panel">
              <div className="panel-header">
                <h3>Monitoring Control Center</h3>
                <span className="badge">Network Interface</span>
              </div>

              <div className="metric-grid">
                <MetricBox label="Network Interface" value="eth0 / Wi-Fi" />
                <MetricBox label="Monitoring Status" value={monitoring ? 'ACTIVE' : 'STOPPED'} />
                <MetricBox label="Packets Captured" value={formatStat(stats.totalPackets)} />
                <MetricBox label="Packets Analyzed" value={formatStat(stats.totalPackets - 120)} />
                <MetricBox label="Attacks Detected" value={formatStat(stats.detectedAttacks)} />
              </div>

              <div className="panel" style={{ marginTop: 18 }}>
                <h4 style={{ color: '#f8fafc', margin: '0 0 12px' }}>AI/ML Section</h4>
                <div className="metric-grid">
                  {apiMetrics.map((metric) => (
                    <div className="metric-box" key={metric.label}>
                      <span>{metric.label}</span>
                      <strong>{metric.value}%</strong>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  )
}

function StatCard({ label, value, icon, delta }) {
  return (
    <div className="card stat-card">
      <div className="stat-header">
        <span>{label}</span>
        <span>{icon}</span>
      </div>
      <div className="stat-value">{value}</div>
      <div className="stat-delta">{delta}</div>
    </div>
  )
}

function MetricBox({ label, value }) {
  return (
    <div className="metric-box">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

export default App
