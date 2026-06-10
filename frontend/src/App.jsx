import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  Copy,
  Edit3,
  Globe2,
  KeyRound,
  LockKeyhole,
  ListFilter,
  LogOut,
  MoreHorizontal,
  Network,
  Plus,
  QrCode,
  RefreshCw,
  Save,
  Server,
  Settings,
  Shield,
  ShieldCheck,
  Trash2,
  UserPlus,
  X
} from 'lucide-react';

const viewTitles = {
  dashboard: 'Dashboard',
  sites: 'Applications',
  rules: 'Detection Rules',
  access: 'Access Control',
  ipGroups: 'IP Groups',
  certificates: 'Certificates',
  logs: 'Request Logs',
  settings: 'Panel Security'
};

const defaultSite = {
  name: '',
  applicationType: 'reverse_proxy',
  origin: 'http://127.0.0.1:9090',
  upstreams: 'http://127.0.0.1:9090',
  hostnames: '',
  listen: '8080',
  ports: '80, 443_ssl',
  redirectStatusCode: '301',
  redirectAddress: '',
  tlsEnabled: 'false',
  certificateId: '',
  redirectHttp: 'false',
  httpListen: '80',
  http2: 'true',
  proxyForceHttps: 'false',
  proxyHsts: 'false',
  proxyHstsMaxAge: '15768000',
  proxyGzip: 'true',
  proxyBrotli: 'false',
  proxyResetXff: 'true',
  proxyDefaultServer: 'false',
  proxyStrictHost: 'false',
  proxyAccessLog: 'true',
  proxyHostHeader: '$http_host',
  proxyXForwardedProto: '$scheme',
  proxyXForwardedHost: '$http_host',
  proxySslServerName: 'true',
  aclEnabled: 'true',
  aclAccessEnabled: 'true',
  aclAccessPeriod: '10',
  aclAccessCount: '200',
  aclAccessAction: 'challenge_v1',
  aclAccessBlockMin: '60',
  aclAttackEnabled: 'true',
  aclAttackPeriod: '60',
  aclAttackCount: '10',
  aclAttackAction: 'block',
  aclAttackBlockMin: '30',
  aclErrorEnabled: 'true',
  aclErrorPeriod: '10',
  aclErrorCount: '10',
  aclErrorAction: 'block',
  aclErrorBlockMin: '30',
  aclErrorStatusCodes: '403, 404',
  featureHttpFlood: 'true',
  featureBotProtection: 'true',
  featureAuth: 'false',
  featureAttacks: 'true',
  mode: 'block',
  enabled: 'true'
};

const siteFeatureLabels = {
  httpFlood: 'HTTP FLOOD',
  botProtection: 'BOT PROTE...',
  auth: 'AUTH',
  attacks: 'ATTACKS',
  acl: 'ACL'
};

const defaultRule = {
  name: '',
  siteId: '*',
  target: 'all',
  matcher: 'regex',
  action: 'block',
  severity: 'medium',
  pattern: '',
  description: '',
  enabled: 'true'
};

const defaultCertificate = {
  name: '',
  source: 'certbot',
  domains: '',
  email: '',
  certificate: '',
  privateKey: '',
  certFile: '',
  keyFile: '',
  autoRenew: true,
  renewBeforeDays: 30
};

const defaultIpGroup = {
  name: '',
  description: '',
  referenceUrl: '',
  items: '',
  enabled: 'true'
};

const defaultAccessRule = {
  name: '',
  siteId: '*',
  action: 'deny',
  insertPosition: 'first',
  ipGroupIds: '',
  ips: '',
  conditionGroups: null,
  continueDetect: 'false',
  enabled: 'true'
};

const defaultUser = {
  username: '',
  displayName: '',
  role: 'admin',
  password: '',
  enabled: 'true',
  totpEnabled: 'false',
  resetTotp: false
};

const accessTargetOptions = [
  { value: 'source_ip', label: 'Source IP' },
  { value: 'uri', label: 'URI' },
  { value: 'host', label: 'Host' },
  { value: 'user_agent', label: 'User-Agent' },
  { value: 'method', label: 'Method' }
];

const accessOperatorOptions = {
  source_ip: [
    { value: 'equals', label: 'Equals' },
    { value: 'cidr', label: 'CIDR' },
    { value: 'in_ip_group', label: 'In IP Group' }
  ],
  uri: [
    { value: 'equals', label: 'Equals' },
    { value: 'contains', label: 'Fuzzy Match' },
    { value: 'regex', label: 'Regex' }
  ],
  host: [
    { value: 'equals', label: 'Equals' },
    { value: 'contains', label: 'Fuzzy Match' },
    { value: 'regex', label: 'Regex' }
  ],
  user_agent: [
    { value: 'equals', label: 'Equals' },
    { value: 'contains', label: 'Fuzzy Match' },
    { value: 'regex', label: 'Regex' }
  ],
  method: [
    { value: 'equals', label: 'Equals' }
  ]
};

export default function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const [auth, setAuth] = useState({ loading: true, authenticated: false, setupRequired: false, user: null });
  const [data, setData] = useState(null);
  const [filter, setFilter] = useState('');
  const [modal, setModal] = useState(null);
  const [toast, setToast] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadAuth();
  }, []);

  async function loadAuth() {
    setLoading(true);
    try {
      const status = await api('/api/auth/status');
      setAuth({ loading: false, ...status });
      if (status.authenticated) {
        await loadState(false, false);
      } else {
        setData(null);
      }
    } catch (error) {
      setAuth({ loading: false, authenticated: false, setupRequired: false, user: null });
      showToast(error.message, true);
    } finally {
      setLoading(false);
    }
  }

  async function loadState(announce = false, manageLoading = true) {
    if (manageLoading) setLoading(true);
    try {
      setData(await api('/api/state'));
      if (announce) showToast('State refreshed');
    } catch (error) {
      if (error.status === 401) {
        const status = await api('/api/auth/status').catch(() => ({ authenticated: false, setupRequired: false, user: null }));
        setAuth({ loading: false, ...status });
        setData(null);
      } else {
        showToast(error.message, true);
      }
    } finally {
      if (manageLoading) setLoading(false);
    }
  }

  async function setupAdmin(payload) {
    setLoading(true);
    try {
      const status = await api('/api/auth/setup', { method: 'POST', body: payload });
      setAuth({ loading: false, ...status });
      await loadState(false, false);
      if (status.user?.totpSetupSecret) {
        setModal({ type: 'totpSetup', user: status.user });
      }
      showToast('Admin user created');
    } catch (error) {
      showToast(error.message, true);
    } finally {
      setLoading(false);
    }
  }

  async function login(payload) {
    setLoading(true);
    try {
      const status = await api('/api/auth/login', { method: 'POST', body: payload });
      setAuth({ loading: false, ...status });
      await loadState(false, false);
      showToast('Signed in');
    } catch (error) {
      showToast(error.message, true);
      throw error;
    } finally {
      setLoading(false);
    }
  }

  async function logout() {
    await api('/api/auth/logout', { method: 'POST' });
    setAuth({ loading: false, authenticated: false, setupRequired: false, user: null });
    setData(null);
    setActiveView('dashboard');
  }

  function showToast(message, danger = false) {
    setToast({ message, danger });
    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(() => setToast(null), 2400);
  }

  async function toggleSite(site, enabled) {
    await api(`/api/sites/${site.id}`, { method: 'PATCH', body: { enabled } });
    await loadState();
  }

  async function toggleRule(rule, enabled) {
    await api(`/api/rules/${rule.id}`, { method: 'PATCH', body: { enabled } });
    await loadState();
  }

  async function toggleIpGroup(group, enabled) {
    await api(`/api/ip-groups/${group.id}`, { method: 'PATCH', body: { enabled } });
    await loadState();
  }

  async function toggleAccessRule(rule, enabled) {
    await api(`/api/access-rules/${rule.id}`, { method: 'PATCH', body: { enabled } });
    await loadState();
  }

  async function saveSite(site) {
    const applicationType = site.applicationType || 'reverse_proxy';
    const upstreams = normalizeUpstreamsPayload(site.upstreams || site.origin, applicationType);
    const ports = normalizeListeningPortsPayload(site.listeningPorts || site.ports);
    const primaryPort = Number(String(ports[0] || '8080').replace('_ssl', '')) || 8080;
    const hasHttpPort = ports.some((port) => !String(port).endsWith('_ssl'));
    const hasHttpsPort = ports.some((port) => String(port).endsWith('_ssl'));
    const forceHttps = applicationType === 'reverse_proxy' && hasHttpPort && hasHttpsPort;
    const payload = {
      id: site.id,
      name: site.name,
      applicationType,
      origin: upstreams[0] || site.origin || '',
      upstreams,
      ports,
      enabled: boolValue(site.enabled),
      listen: primaryPort,
      hostnames: listFromText(site.hostnames, /[\s,]+/),
      redirectStatusCode: Number(site.redirectStatusCode || 301),
      redirect: {
        statusCode: Number(site.redirectStatusCode || 301),
        address: site.redirectAddress || ''
      },
      static: {
        root: site.staticRoot || ''
      },
      tls: {
        enabled: boolValue(site.tlsEnabled),
        certificateId: site.certificateId || '',
        redirectHttp: forceHttps,
        httpListen: Number(site.httpListen || 80),
        http2: boolValue(site.http2)
      },
      proxy: {
        forceHttps,
        redirectStatusCode: Number(site.redirectStatusCode || 301),
        hsts: boolValue(site.proxyHsts),
        hstsMaxAge: String(site.proxyHstsMaxAge || '15768000'),
        gzip: boolValue(site.proxyGzip),
        brotli: boolValue(site.proxyBrotli),
        http2: boolValue(site.http2),
        resetXff: boolValue(site.proxyResetXff),
        defaultServer: boolValue(site.proxyDefaultServer),
        strictHost: boolValue(site.proxyStrictHost),
        accessLog: boolValue(site.proxyAccessLog),
        hostHeader: '$http_host',
        xForwardedProto: '$scheme',
        xForwardedHost: '$http_host',
        proxySslServerName: boolValue(site.proxySslServerName)
      },
      acl: {
        enabled: boolValue(site.aclEnabled),
        accessLimit: {
          enabled: boolValue(site.aclAccessEnabled),
          period: Number(site.aclAccessPeriod || 10),
          count: Number(site.aclAccessCount || 200),
          action: site.aclAccessAction || 'challenge_v1',
          blockMin: Number(site.aclAccessBlockMin || 60)
        },
        attackLimit: {
          enabled: boolValue(site.aclAttackEnabled),
          period: Number(site.aclAttackPeriod || 60),
          count: Number(site.aclAttackCount || 10),
          action: site.aclAttackAction || 'block',
          blockMin: Number(site.aclAttackBlockMin || 30)
        },
        errorLimit: {
          enabled: boolValue(site.aclErrorEnabled),
          period: Number(site.aclErrorPeriod || 10),
          count: Number(site.aclErrorCount || 10),
          action: site.aclErrorAction || 'block',
          blockMin: Number(site.aclErrorBlockMin || 30),
          statusCodes: listFromText(site.aclErrorStatusCodes, /[\s,]+/)
        }
      },
      features: {
        httpFlood: boolValue(site.featureHttpFlood),
        botProtection: boolValue(site.featureBotProtection),
        auth: boolValue(site.featureAuth),
        attacks: boolValue(site.featureAttacks)
      }
    };
    const id = payload.id;
    delete payload.id;
    await api(id ? `/api/sites/${id}` : '/api/sites', {
      method: id ? 'PUT' : 'POST',
      body: payload
    });
    setModal(null);
    await loadState();
    showToast('Site saved');
  }

  async function saveRule(rule) {
    const payload = {
      ...rule,
      enabled: rule.enabled === 'true' || rule.enabled === true
    };
    const id = payload.id;
    delete payload.id;
    await api(id ? `/api/rules/${id}` : '/api/rules', {
      method: id ? 'PUT' : 'POST',
      body: payload
    });
    setModal(null);
    await loadState();
    showToast('Rule saved');
  }

  async function saveCertificate(certificate) {
    try {
      const payload = {
        ...certificate,
        domains: listFromText(certificate.domains, /[\s,]+/),
        autoRenew: certificate.autoRenew !== false && certificate.autoRenew !== 'false',
        renewBeforeDays: Number(certificate.renewBeforeDays || 30)
      };
      const id = payload.id;
      delete payload.id;
      await api(id ? `/api/certificates/${id}` : '/api/certificates', {
        method: id ? 'PUT' : 'POST',
        body: payload
      });
      setModal(null);
      await loadState();
      showToast('Certificate saved');
    } catch (error) {
      showToast(error.message, true);
    }
  }

  async function saveIpGroup(group) {
    const payload = {
      ...group,
      enabled: group.enabled === 'true' || group.enabled === true,
      items: listFromText(group.items, /[\n,]+/)
    };
    const id = payload.id;
    delete payload.id;
    await api(id ? `/api/ip-groups/${id}` : '/api/ip-groups', {
      method: id ? 'PUT' : 'POST',
      body: payload
    });
    setModal(null);
    await loadState();
    showToast('IP group saved');
  }

  async function syncIpGroup(group) {
    const saved = await api(`/api/ip-groups/${group.id}/sync`, { method: 'POST' });
    await loadState();
    showToast(
      saved.lastSyncStatus === 'failed'
        ? saved.lastSyncMessage || 'IP group sync failed'
        : `IP group synced: ${saved.items?.length || 0} entries`,
      saved.lastSyncStatus === 'failed'
    );
  }

  async function saveAccessRule(rule) {
    const conditionGroups = normalizeAccessConditionGroupsPayload(rule.conditionGroups, rule);
    const flattened = flattenAccessConditions(conditionGroups);
    const payload = {
      ...rule,
      enabled: rule.enabled === 'true' || rule.enabled === true,
      continueDetect: rule.continueDetect === 'true' || rule.continueDetect === true,
      insertPosition: rule.insertPosition || 'first',
      ipGroupIds: flattened.ipGroupIds,
      ips: flattened.ips,
      methods: flattened.methods,
      uriPatterns: flattened.uriPatterns,
      hostPatterns: flattened.hostPatterns,
      userAgentPatterns: flattened.userAgentPatterns,
      conditionGroups
    };
    const id = payload.id;
    delete payload.id;
    await api(id ? `/api/access-rules/${id}` : '/api/access-rules', {
      method: id ? 'PUT' : 'POST',
      body: payload
    });
    setModal(null);
    await loadState();
    showToast('Access rule saved');
  }

  async function deleteSite(site) {
    if (!window.confirm(`Delete ${site.name}?`)) return;
    try {
      await api(`/api/sites/${site.id}`, { method: 'DELETE' });
      await loadState();
      showToast('Site deleted');
    } catch (error) {
      showToast(error.message, true);
    }
  }

  async function deleteRule(rule) {
    if (!window.confirm(`Delete ${rule.name}?`)) return;
    await api(`/api/rules/${rule.id}`, { method: 'DELETE' });
    await loadState();
    showToast('Rule deleted');
  }

  async function deleteCertificate(certificate) {
    if (!window.confirm(`Delete ${certificate.name}?`)) return;
    try {
      await api(`/api/certificates/${certificate.id}`, { method: 'DELETE' });
      await loadState();
      showToast('Certificate deleted');
    } catch (error) {
      showToast(error.message, true);
    }
  }

  async function deleteIpGroup(group) {
    if (!window.confirm(`Delete ${group.name}?`)) return;
    await api(`/api/ip-groups/${group.id}`, { method: 'DELETE' });
    await loadState();
    showToast('IP group deleted');
  }

  async function deleteAccessRule(rule) {
    if (!window.confirm(`Delete ${rule.name}?`)) return;
    await api(`/api/access-rules/${rule.id}`, { method: 'DELETE' });
    await loadState();
    showToast('Access rule deleted');
  }

  async function clearLogs() {
    if (!window.confirm('Clear all logs?')) return;
    await api('/api/logs', { method: 'DELETE' });
    await loadState();
    showToast('Logs cleared');
  }

  async function copyText(value) {
    await navigator.clipboard.writeText(value);
    showToast('Copied');
  }

  async function previewNginx() {
    const result = await api('/api/nginx/render');
    setModal({ type: 'nginx', result });
  }

  async function applyNginx(options = {}) {
    const result = await api('/api/nginx/apply', {
      method: 'POST',
      body: options
    });
    setModal({ type: 'nginx', result });
    showToast(result.ok ? 'Nginx config written' : 'Nginx command failed', !result.ok);
  }

  async function savePanelSettings(panel) {
    await api('/api/settings', {
      method: 'PATCH',
      body: { panel }
    });
    await loadState();
    showToast('Panel settings saved');
  }

  async function saveUser(user) {
    const payload = {
      ...user,
      enabled: user.enabled === 'true' || user.enabled === true,
      totpEnabled: user.totpEnabled === 'true' || user.totpEnabled === true,
      resetTotp: user.resetTotp === true
    };
    if (!payload.password) delete payload.password;
    const id = payload.id;
    delete payload.id;
    const saved = await api(id ? `/api/users/${id}` : '/api/users', {
      method: id ? 'PUT' : 'POST',
      body: payload
    });
    await loadState();
    if (saved.totpSetupSecret) {
      setModal({ type: 'totpSetup', user: saved });
    } else {
      setModal(null);
    }
    showToast('User saved');
  }

  async function deleteUser(user) {
    if (!window.confirm(`Delete ${user.username}?`)) return;
    await api(`/api/users/${user.id}`, { method: 'DELETE' });
    await loadState();
    showToast('User deleted');
  }

  const content = useMemo(() => {
    if (!data) return <LoadingPanel />;
    const props = {
      data,
      filter,
      setFilter,
      setModal,
      toggleSite,
      toggleRule,
      toggleIpGroup,
      toggleAccessRule,
      deleteSite,
      deleteRule,
      deleteCertificate,
      deleteIpGroup,
      deleteAccessRule,
      syncIpGroup,
      clearLogs,
      copyText,
      previewNginx,
      applyNginx,
      savePanelSettings,
      saveUser,
      deleteUser,
      auth,
      logout
    };
    if (activeView === 'sites') return <SitesView {...props} />;
    if (activeView === 'rules') return <RulesView {...props} />;
    if (activeView === 'access') return <AccessView {...props} />;
    if (activeView === 'ipGroups') return <IpGroupsView {...props} />;
    if (activeView === 'certificates') return <CertificatesView {...props} />;
    if (activeView === 'logs') return <LogsView {...props} />;
    if (activeView === 'settings') return <SettingsView {...props} />;
    return <DashboardView {...props} />;
  }, [activeView, data, filter, auth]);

  if (auth.loading) {
    return <LoadingPanel />;
  }

  if (auth.setupRequired) {
    return <AuthScreen mode="setup" loading={loading} onSubmit={setupAdmin} />;
  }

  if (!auth.authenticated) {
    return <AuthScreen mode="login" loading={loading} onSubmit={login} />;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark"><Shield size={22} /></span>
          <span>
            <strong>FreeWAF</strong>
            <small>Reverse proxy WAF</small>
          </span>
        </div>
        <nav className="nav">
          <NavButton active={activeView === 'dashboard'} icon={<Activity />} label="Dashboard" onClick={() => setActiveView('dashboard')} />
          <NavButton active={activeView === 'sites'} icon={<Server />} label="Sites" onClick={() => setActiveView('sites')} />
          <NavButton active={activeView === 'rules'} icon={<ShieldCheck />} label="Rules" onClick={() => setActiveView('rules')} />
          <NavButton active={activeView === 'access'} icon={<ListFilter />} label="Access" onClick={() => setActiveView('access')} />
          <NavButton active={activeView === 'ipGroups'} icon={<Network />} label="IP Groups" onClick={() => setActiveView('ipGroups')} />
          <NavButton active={activeView === 'certificates'} icon={<KeyRound />} label="Certs" onClick={() => setActiveView('certificates')} />
          <NavButton active={activeView === 'logs'} icon={<ListFilter />} label="Logs" onClick={() => setActiveView('logs')} />
          <NavButton active={activeView === 'settings'} icon={<Settings />} label="Settings" onClick={() => setActiveView('settings')} />
        </nav>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">Protected traffic</p>
            <h1>{viewTitles[activeView]}</h1>
          </div>
          <div className="toolbar">
            <button className="icon-button" onClick={() => loadState(true)} title="Refresh" disabled={loading}>
              <RefreshCw size={18} className={loading ? 'spin' : ''} />
            </button>
            <button className="icon-button" onClick={logout} title="Sign out">
              <LogOut size={18} />
            </button>
          </div>
        </header>
        <section className="view">{content}</section>
      </main>

      {modal?.type === 'site' && (
        <SiteModal
          site={modal.site}
          certificates={data?.certificates || []}
          onClose={() => setModal(null)}
          onSave={saveSite}
        />
      )}
      {modal?.type === 'rule' && (
        <RuleModal
          rule={modal.rule}
          sites={data?.sites || []}
          onClose={() => setModal(null)}
          onSave={saveRule}
        />
      )}
      {modal?.type === 'certificate' && (
        <CertificateModal
          certificate={modal.certificate}
          onClose={() => setModal(null)}
          onSave={saveCertificate}
        />
      )}
      {modal?.type === 'ipGroup' && (
        <IpGroupModal
          group={modal.group}
          onClose={() => setModal(null)}
          onSave={saveIpGroup}
        />
      )}
      {modal?.type === 'accessRule' && (
        <AccessRuleModal
          rule={modal.rule}
          sites={data?.sites || []}
          ipGroups={data?.ipGroups || []}
          onClose={() => setModal(null)}
          onSave={saveAccessRule}
        />
      )}
      {modal?.type === 'nginx' && (
        <NginxModal
          result={modal.result}
          onClose={() => setModal(null)}
          onCopy={copyText}
        />
      )}
      {modal?.type === 'user' && (
        <UserModal
          user={modal.user}
          onClose={() => setModal(null)}
          onSave={saveUser}
        />
      )}
      {modal?.type === 'totpSetup' && (
        <TotpSetupModal
          user={modal.user}
          onClose={() => setModal(null)}
          onCopy={copyText}
        />
      )}
      {toast && <div className={`toast ${toast.danger ? 'danger' : ''}`}>{toast.message}</div>}
    </div>
  );
}

function NavButton({ active, icon, label, onClick }) {
  return (
    <button className={`nav-item ${active ? 'active' : ''}`} onClick={onClick}>
      {icon}
      <span>{label}</span>
    </button>
  );
}

function LoadingPanel() {
  return <section className="panel">Loading state...</section>;
}

function AuthScreen({ mode, loading, onSubmit }) {
  const [form, setForm] = useState({
    username: 'admin',
    displayName: 'Administrator',
    password: '',
    totpCode: '',
    totpEnabled: false
  });
  const [needsTotp, setNeedsTotp] = useState(false);
  const isSetup = mode === 'setup';

  function update(name, value) {
    setForm((current) => ({ ...current, [name]: value }));
  }

  async function submit(event) {
    event.preventDefault();
    try {
      await onSubmit(form);
    } catch (error) {
      if (error.payload?.totpRequired || String(error.message || '').toLowerCase().includes('google authenticator')) {
        setNeedsTotp(true);
      }
    }
  }

  return (
    <main className="auth-page">
      <form className="auth-panel" onSubmit={submit}>
        <div className="brand auth-brand">
          <span className="brand-mark"><Shield size={22} /></span>
          <span>
            <strong>FreeWAF</strong>
            <small>{isSetup ? 'Create admin account' : 'Admin panel sign in'}</small>
          </span>
        </div>
        <TextField label="Username" value={form.username} onChange={(value) => update('username', value)} required full />
        {isSetup && <TextField label="Display Name" value={form.displayName} onChange={(value) => update('displayName', value)} full />}
        <TextField label="Password" type="password" value={form.password} onChange={(value) => update('password', value)} required full />
        {isSetup && (
          <CheckboxField label="Enable Google Authenticator for this admin" checked={form.totpEnabled} onChange={(checked) => update('totpEnabled', checked)} />
        )}
        {!isSetup && needsTotp && (
          <TextField label="Google Authenticator Code" value={form.totpCode} onChange={(value) => update('totpCode', value)} placeholder="123456" full />
        )}
        <button className="tool-button primary auth-submit" disabled={loading}>
          <LockKeyhole size={18} /> {isSetup ? 'Create Admin' : 'Sign In'}
        </button>
      </form>
    </main>
  );
}

function DashboardView({ data }) {
  const { stats, logs } = data;
  const recentBlocks = logs.filter((entry) => entry.verdict === 'block').slice(0, 6);
  const topRule = stats.topRules[0]?.name || 'None';

  return (
    <>
      <div className="metric-grid">
        <Metric label="Requests" value={stats.total} note="Stored request events" />
        <Metric label="Blocked" value={stats.blocked} note={`${stats.blockRate}% block rate`} />
        <Metric label="Monitor" value={stats.monitored} note="Matched without blocking" />
        <Metric label="Top Signal" value={topRule} note="Most frequent matched rule" />
      </div>
      <div className="grid-two">
        <section className="panel">
          <div className="panel-heading">
            <h2>Traffic Window</h2>
            <span className="pill">5 minute buckets</span>
          </div>
          <Timeline points={stats.timeline} />
        </section>
        <section className="panel">
          <div className="panel-heading">
            <h2>Recent Blocks</h2>
            <span className="pill">{recentBlocks.length}</span>
          </div>
          <div className="incident-list">
            {recentBlocks.length ? recentBlocks.map((entry) => <Incident key={entry.id} entry={entry} />) : <p className="muted">No blocked requests recorded.</p>}
          </div>
        </section>
      </div>
    </>
  );
}

function SitesView({ data, setModal, toggleSite, deleteSite }) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <h2>Applications</h2>
        <button className="tool-button primary" onClick={() => setModal({ type: 'site', site: null })}>
          <Plus size={18} /> Add Application
        </button>
      </div>
      <div className="application-grid">
        {data.sites.map((site) => (
          <ApplicationCard
            key={site.id}
            site={site}
            logs={data.logs}
            onEdit={() => setModal({ type: 'site', site })}
            onDelete={() => deleteSite(site)}
            onToggle={(checked) => toggleSite(site, checked)}
          />
        ))}
      </div>
    </section>
  );
}

function ApplicationCard({ site, logs, onEdit, onDelete, onToggle }) {
  const features = normalizedSiteFeatures(site);
  const counters = siteCounters(site, logs);
  const domain = site.hostnames?.[0] || site.name;
  const ports = site.ports?.length ? site.ports : [site.tls?.enabled ? `${site.listen || 443}_ssl` : String(site.listen || 8080)];
  const protocol = ports.some((port) => String(port).endsWith('_ssl')) ? 'HTTPS' : 'HTTP';
  const upstream = site.upstreams?.[0] || site.origin;
  const appType = applicationTypeLabel(site.applicationType);

  return (
    <article className="application-card">
      <div className="application-status">
        <span className="app-globe"><Globe2 size={22} /></span>
        <button className={`defense-button ${site.enabled ? 'active' : ''}`} type="button" onClick={() => onToggle(!site.enabled)}>
          DEFENSE
        </button>
        <div className="app-metric-pair">
          <div>
            <span>RQS TD</span>
            <strong>{formatCompact(counters.requests)}</strong>
          </div>
          <div>
            <span>BLK TD</span>
            <strong>{formatCompact(counters.blocked)}</strong>
          </div>
        </div>
      </div>
      <div className="application-main">
        <div className="application-topline">
          <h3>{site.name}</h3>
          <div className="row-actions">
            <span className="pill">{appType}</span>
            <button className="link-button" onClick={onEdit}>DETAIL</button>
            <button className="table-action" onClick={onDelete} title="Delete"><MoreHorizontal size={17} /></button>
          </div>
        </div>
        <div className="app-field">
          <Globe2 size={15} />
          <span className="muted">Domain:</span>
          <strong>{domain}</strong>
          {site.hostnames?.length > 1 && <span className="code chip">...</span>}
        </div>
        <div className="app-field">
          <Server size={15} />
          <span className="muted">Ports:</span>
          <strong>{ports.join(', ')}</strong>
          <span className="protocol-text">{protocol}</span>
        </div>
        {site.applicationType !== 'static_files' && (
          <div className="app-field">
            <Network size={15} />
            <span className="muted">{site.applicationType === 'redirect' ? 'Address:' : 'Upstream:'}</span>
            <strong>{site.applicationType === 'redirect' ? site.redirect?.address || '-' : upstream}</strong>
            {site.applicationType !== 'redirect' && (site.upstreams?.length || 0) > 1 && <span className="code chip">+{site.upstreams.length - 1}</span>}
          </div>
        )}
        <div className="feature-chip-row">
          {Object.entries(siteFeatureLabels).map(([key, label]) => (
            <span className={`feature-chip ${features[key] ? 'active' : ''}`} key={key}>{label}</span>
          ))}
        </div>
      </div>
    </article>
  );
}

function RulesView({ data, filter, setFilter, setModal, toggleRule, deleteRule }) {
  const rules = data.rules.filter((rule) => {
    if (!filter.trim()) return true;
    return [rule.name, rule.description, rule.pattern, rule.target, rule.action, rule.severity]
      .join(' ')
      .toLowerCase()
      .includes(filter.trim().toLowerCase());
  });

  return (
    <section className="table-panel">
      <div className="filters">
        <div className="panel-heading compact">
          <h2>Rules</h2>
          <button className="tool-button primary" onClick={() => setModal({ type: 'rule', rule: null })}>
            <Plus size={18} /> Add Rule
          </button>
        </div>
        <input className="search" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter rules" />
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Severity</th>
              <th>Target</th>
              <th>Pattern</th>
              <th>Action</th>
              <th>Enabled</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={rule.id}>
                <td>
                  <strong>{rule.name}</strong>
                  {rule.builtin && <span className="pill inline">built-in</span>}
                  <br />
                  <span className="muted">{rule.description || 'Custom rule'}</span>
                </td>
                <td><span className={`status ${rule.severity}`}>{rule.severity}</span></td>
                <td>{rule.target} / {rule.matcher}</td>
                <td className="path-cell"><span className="code">{rule.pattern}</span></td>
                <td><span className={`status ${rule.action}`}>{rule.action}</span></td>
                <td><Switch checked={rule.enabled} onChange={(checked) => toggleRule(rule, checked)} /></td>
                <td>
                  <div className="row-actions">
                    <button className="table-action" onClick={() => setModal({ type: 'rule', rule })} title="Edit"><Edit3 size={17} /></button>
                    {!rule.builtin && <button className="table-action" onClick={() => deleteRule(rule)} title="Delete"><Trash2 size={17} /></button>}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function AccessView({ data, setModal, toggleAccessRule, deleteAccessRule }) {
  const siteName = (id) => (id === '*' ? 'All sites' : data.sites.find((site) => site.id === id)?.name || id);
  return (
    <section className="table-panel">
      <div className="panel-heading">
        <h2>Access Rules</h2>
        <button className="tool-button primary" onClick={() => setModal({ type: 'accessRule', rule: null })}>
          <Plus size={18} /> Add Access Rule
        </button>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Action</th>
              <th>Site</th>
              <th>Match</th>
              <th>Enabled</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {data.accessRules.length ? data.accessRules.map((rule) => (
              <tr key={rule.id}>
                <td><strong>{rule.name}</strong><br /><span className="muted">{rule.description || 'Access control rule'}</span></td>
                <td><span className={`status ${rule.action === 'deny' ? 'block' : rule.action}`}>{rule.action}</span></td>
                <td>{siteName(rule.siteId)}</td>
                <td className="path-cell">{accessRuleMatch(rule, data.ipGroups)}</td>
                <td><Switch checked={rule.enabled} onChange={(checked) => toggleAccessRule(rule, checked)} /></td>
                <td>
                  <div className="row-actions">
                    <button className="table-action" onClick={() => setModal({ type: 'accessRule', rule })} title="Edit"><Edit3 size={17} /></button>
                    <button className="table-action" onClick={() => deleteAccessRule(rule)} title="Delete"><Trash2 size={17} /></button>
                  </div>
                </td>
              </tr>
            )) : (
              <tr><td colSpan="6" className="muted">No access rules.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function IpGroupsView({ data, setModal, toggleIpGroup, deleteIpGroup, syncIpGroup }) {
  return (
    <section className="table-panel">
      <div className="panel-heading">
        <h2>IP Groups</h2>
        <button className="tool-button primary" onClick={() => setModal({ type: 'ipGroup', group: null })}>
          <Plus size={18} /> Add IP Group
        </button>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Reference</th>
              <th>Content</th>
              <th>Sync</th>
              <th>Enabled</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {data.ipGroups.map((group) => (
              <tr key={group.id}>
                <td><strong>{group.name}</strong><br /><span className="muted">{group.description || 'IP/CIDR list'}</span></td>
                <td className="path-cell">
                  {group.referenceUrl ? <span className="code">{group.referenceUrl}</span> : <span className="muted">Manual</span>}
                </td>
                <td className="path-cell">
                  <span className="pill">{group.items.length} entries</span>
                  <br />
                  {group.items.slice(0, 8).map((item) => <span className="code chip" key={item}>{item}</span>)}
                  {group.items.length > 8 && <span className="muted">+{group.items.length - 8} more</span>}
                </td>
                <td>
                  {group.referenceUrl ? (
                    <div className="sync-cell">
                      <span className={`status ${group.lastSyncStatus === 'failed' ? 'block' : 'allow'}`}>{group.lastSyncStatus || 'pending'}</span>
                      <span className="muted">{group.lastSyncedAt ? formatTime(group.lastSyncedAt) : 'Never'}</span>
                      {group.lastSyncMessage && <span className="muted">{group.lastSyncMessage}</span>}
                    </div>
                  ) : (
                    <span className="muted">Manual</span>
                  )}
                </td>
                <td><Switch checked={group.enabled} onChange={(checked) => toggleIpGroup(group, checked)} /></td>
                <td>
                  <div className="row-actions">
                    {group.referenceUrl && <button className="table-action" onClick={() => syncIpGroup(group)} title="Sync now"><RefreshCw size={17} /></button>}
                    <button className="table-action" onClick={() => setModal({ type: 'ipGroup', group })} title="Edit"><Edit3 size={17} /></button>
                    <button className="table-action" onClick={() => deleteIpGroup(group)} title="Delete"><Trash2 size={17} /></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function CertificatesView({ data, setModal, deleteCertificate }) {
  return (
    <section className="table-panel">
      <div className="panel-heading">
        <h2>Certificates</h2>
        <button className="tool-button primary" onClick={() => setModal({ type: 'certificate', certificate: null })}>
          <Plus size={18} /> Add Certificate
        </button>
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Source</th>
              <th>Domains</th>
              <th>Certificate</th>
              <th>Private Key</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {data.certificates.length ? data.certificates.map((certificate) => (
              <tr key={certificate.id}>
                <td><strong>{certificate.name}</strong><br /><span className="muted">{certificate.status || 'ready'}</span></td>
                <td><span className={`status ${certificate.source === 'certbot' ? 'allow' : 'low'}`}>{certificate.source || 'upload'}</span></td>
                <td className="path-cell">{inlineList(certificate.domains || [])}</td>
                <td className="path-cell"><span className="code">{certificate.certFile}</span></td>
                <td className="path-cell"><span className="code">{certificate.keyFile}</span></td>
                <td>
                  <div className="row-actions">
                    <button className="table-action" onClick={() => setModal({ type: 'certificate', certificate })} title="Edit"><Edit3 size={17} /></button>
                    <button className="table-action" onClick={() => deleteCertificate(certificate)} title="Delete"><Trash2 size={17} /></button>
                  </div>
                </td>
              </tr>
            )) : (
              <tr><td colSpan="6" className="muted">No certificates.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function LogsView({ data, filter, setFilter, clearLogs }) {
  const logs = data.logs.filter((entry) => {
    if (!filter.trim()) return true;
    return [entry.siteName, entry.host, entry.path, entry.ip, entry.reason, entry.verdict]
      .join(' ')
      .toLowerCase()
      .includes(filter.trim().toLowerCase());
  });

  return (
    <section className="table-panel">
      <div className="filters">
        <div className="panel-heading compact">
          <h2>Logs</h2>
          <button className="tool-button danger" onClick={clearLogs}><Trash2 size={18} /> Clear</button>
        </div>
        <input className="search" value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter logs" />
      </div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Verdict</th>
              <th>Time</th>
              <th>Site</th>
              <th>Method</th>
              <th>Path</th>
              <th>IP</th>
              <th>Reason</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {logs.length ? logs.map((entry) => (
              <tr key={entry.id}>
                <td><span className={`status ${entry.verdict}`}>{entry.verdict}</span></td>
                <td>{formatTime(entry.at)}<br /><span className="muted">{entry.durationMs} ms</span></td>
                <td>{entry.siteName}<br /><span className="muted">{entry.host}</span></td>
                <td>{entry.method}</td>
                <td className="path-cell">{entry.path}</td>
                <td>{entry.ip}</td>
                <td>{entry.reason}</td>
                <td>{entry.upstreamStatus || entry.statusCode || ''}</td>
              </tr>
            )) : (
              <tr><td colSpan="8" className="muted">No log entries.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function SettingsView({ data, setModal, savePanelSettings, deleteUser, previewNginx, applyNginx, auth, logout }) {
  const panel = data.settings?.panel || {};
  const [panelForm, setPanelForm] = useState(() => ({
    httpsEnabled: String(panel.httpsEnabled ?? false),
    certificateId: panel.certificateId || '',
    publicUrl: panel.publicUrl || '',
    sessionHours: panel.sessionHours || 12
  }));

  function updatePanel(name, value) {
    setPanelForm((current) => ({ ...current, [name]: value }));
  }

  function submitPanel(event) {
    event.preventDefault();
    savePanelSettings({
      httpsEnabled: boolValue(panelForm.httpsEnabled),
      certificateId: panelForm.certificateId,
      publicUrl: panelForm.publicUrl,
      sessionHours: Number(panelForm.sessionHours || 12)
    });
  }

  return (
    <>
      <section className="panel">
        <div className="panel-heading">
          <h2>Panel SSL</h2>
          <span className="pill">{panel.httpsEnabled ? 'HTTPS after restart' : 'HTTP'}</span>
        </div>
        <form className="settings-form" onSubmit={submitPanel}>
          <CheckboxField label="Use HTTPS for admin panel" checked={boolValue(panelForm.httpsEnabled)} onChange={(checked) => updatePanel('httpsEnabled', checked)} />
          <SelectField
            label="SSL Certificate"
            value={panelForm.certificateId}
            onChange={(value) => updatePanel('certificateId', value)}
            options={[{ value: '', label: 'No certificate' }, ...data.certificates.map((certificate) => ({ value: certificate.id, label: certificate.name || certificate.id }))]}
          />
          <TextField label="Panel URL" value={panelForm.publicUrl} onChange={(value) => updatePanel('publicUrl', value)} placeholder="https://waf.example.com:7001" full />
          <TextField label="Session Hours" value={panelForm.sessionHours} onChange={(value) => updatePanel('sessionHours', value)} />
          <div className="settings-actions full">
            <button className="tool-button primary"><Save size={18} /> Save Panel SSL</button>
          </div>
          <p className="form-note full">Changing HTTPS certificate or protocol requires restarting the FreeWAF admin service.</p>
        </form>
      </section>

      <section className="table-panel">
        <div className="panel-heading">
          <h2>Users</h2>
          <button className="tool-button primary" onClick={() => setModal({ type: 'user', user: null })}>
            <UserPlus size={18} /> Add User
          </button>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Google Auth</th>
                <th>Last Login</th>
                <th>Enabled</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {data.users?.length ? data.users.map((user) => (
                <tr key={user.id}>
                  <td><strong>{user.displayName || user.username}</strong><br /><span className="muted">{user.username}</span></td>
                  <td><span className="status low">{user.role}</span></td>
                  <td><span className={`status ${user.totpEnabled ? 'allow' : 'disabled'}`}>{user.totpEnabled ? 'enabled' : 'disabled'}</span></td>
                  <td>{user.lastLoginAt ? formatTime(user.lastLoginAt) : <span className="muted">Never</span>}</td>
                  <td><span className={`status ${user.enabled ? 'enabled' : 'disabled'}`}>{user.enabled ? 'enabled' : 'disabled'}</span></td>
                  <td>
                    <div className="row-actions">
                      <button className="table-action" onClick={() => setModal({ type: 'user', user })} title="Edit"><Edit3 size={17} /></button>
                      <button className="table-action" onClick={() => deleteUser(user)} title="Delete" disabled={auth.user?.id === user.id}><Trash2 size={17} /></button>
                    </div>
                  </td>
                </tr>
              )) : (
                <tr><td colSpan="6" className="muted">No users.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <h2>Nginx Config</h2>
          <span className="pill">native enforcement</span>
        </div>
        <div className="settings-actions">
          <button className="tool-button" onClick={previewNginx}><ListFilter size={18} /> Preview</button>
          <button className="tool-button primary" onClick={() => applyNginx({})}><Save size={18} /> Write Config</button>
          <button className="tool-button" onClick={() => applyNginx({ test: true })}><ShieldCheck size={18} /> Write + Test</button>
          <button className="tool-button" onClick={() => applyNginx({ test: true, reload: true })}><RefreshCw size={18} /> Test + Reload</button>
          <button className="tool-button" onClick={logout}><LogOut size={18} /> Sign Out</button>
        </div>
      </section>
    </>
  );
}

function Metric({ label, value, note }) {
  return (
    <article className="metric-card">
      <div className="metric-label"><span>{label}</span></div>
      <div className="metric-value">{value}</div>
      <div className="metric-note">{note}</div>
    </article>
  );
}

function Timeline({ points }) {
  const max = Math.max(1, ...points.map((point) => point.total));
  return (
    <div className="chart" aria-label="Traffic chart">
      {points.map((point) => {
        const height = Math.max(4, Math.round((point.total / max) * 100));
        const blockedHeight = point.total ? Math.round((point.blocked / point.total) * 100) : 0;
        return (
          <div
            className="bar"
            key={point.at}
            title={`${point.label}: ${point.total} total, ${point.blocked} blocked`}
            style={{ height: `${height}%` }}
          >
            <span style={{ height: `${blockedHeight}%` }} />
          </div>
        );
      })}
    </div>
  );
}

function Incident({ entry }) {
  return (
    <article className="incident-item">
      <div className="incident-top">
        <strong>{entry.reason}</strong>
        <span className="status block">block</span>
      </div>
      <div className="muted">{entry.method} {entry.path}</div>
      <div className="muted">{entry.ip} / {formatTime(entry.at)}</div>
    </article>
  );
}

function SettingTile({ label, value, onCopy }) {
  return (
    <article className="settings-tile">
      <strong>{label}</strong>
      <p className="code">{value}</p>
      {onCopy && (
        <button className="tool-button" onClick={onCopy}>
          <Copy size={18} /> Copy
        </button>
      )}
    </article>
  );
}

function Switch({ checked, onChange }) {
  return (
    <label className="switch" title={checked ? 'Enabled' : 'Disabled'}>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <span />
    </label>
  );
}

function NginxModal({ result, onClose, onCopy }) {
  const config = result?.config || '';
  return (
    <Modal title="Nginx Config" onClose={onClose} wide>
      <div className="nginx-modal-body">
        <div className="settings-actions">
          <button className="tool-button" onClick={() => onCopy(config)}><Copy size={18} /> Copy Config</button>
          {result?.outputFile && <span className="pill">{result.outputFile}</span>}
          {result?.runtime?.outputFile && <span className="pill">{result.runtime.outputFile}</span>}
        </div>
        {result?.test && <CommandResult label="nginx -t" result={result.test} />}
        {result?.reload && <CommandResult label="reload" result={result.reload} />}
        <pre className="config-preview">{config}</pre>
      </div>
      <div className="modal-footer">
        <button type="button" className="tool-button primary" onClick={onClose}>Done</button>
      </div>
    </Modal>
  );
}

function CommandResult({ label, result }) {
  return (
    <div className={`command-result ${result.ok ? 'ok' : 'bad'}`}>
      <strong>{label}: {result.ok ? 'ok' : 'failed'}</strong>
      {(result.stdout || result.stderr) && (
        <pre>{[result.stdout, result.stderr].filter(Boolean).join('\n')}</pre>
      )}
    </div>
  );
}

function SiteModal({ site, certificates, onClose, onSave }) {
  const [form, setForm] = useState(() => ({
    ...defaultSite,
    ...(site || {}),
    applicationType: site?.applicationType || defaultSite.applicationType,
    hostnames: Array.isArray(site?.hostnames) ? site.hostnames.join(', ') : defaultSite.hostnames,
    listeningPorts: listeningPortsFromSite(site),
    upstreams: upstreamsFromSite(site),
    redirectStatusCode: String(site?.redirectStatusCode ?? site?.proxy?.redirectStatusCode ?? defaultSite.redirectStatusCode),
    redirectAddress: site?.redirect?.address || defaultSite.redirectAddress,
    staticRoot: site?.static?.root || '',
    tlsEnabled: String(site?.tls?.enabled ?? false),
    certificateId: site?.tls?.certificateId || '',
    http2: String(site?.tls?.http2 ?? true),
    proxyForceHttps: String(site?.proxy?.forceHttps ?? site?.tls?.redirectHttp ?? false),
    featureHttpFlood: String(site?.features?.httpFlood ?? true),
    featureBotProtection: String(site?.features?.botProtection ?? true),
    featureAuth: String(site?.features?.auth ?? false),
    featureAttacks: String(site?.features?.attacks ?? true),
    enabled: String(site?.enabled ?? true)
  }));

  function update(name, value) {
    setForm((current) => ({ ...current, [name]: value }));
  }

  function updatePort(index, patch) {
    setForm((current) => ({
      ...current,
      listeningPorts: current.listeningPorts.map((row, rowIndex) => rowIndex === index ? { ...row, ...patch } : row)
    }));
  }

  function addPort() {
    setForm((current) => ({
      ...current,
      listeningPorts: [...current.listeningPorts, { port: '', protocol: 'http' }]
    }));
  }

  function removePort(index) {
    setForm((current) => ({
      ...current,
      listeningPorts: current.listeningPorts.filter((_, rowIndex) => rowIndex !== index)
    }));
  }

  function updateUpstream(index, value) {
    setForm((current) => ({
      ...current,
      upstreams: current.upstreams.map((item, itemIndex) => itemIndex === index ? value : item)
    }));
  }

  function addUpstream() {
    setForm((current) => ({ ...current, upstreams: [...current.upstreams, ''] }));
  }

  function removeUpstream(index) {
    setForm((current) => ({ ...current, upstreams: current.upstreams.filter((_, itemIndex) => itemIndex !== index) }));
  }

  function submit(event) {
    event.preventDefault();
    const hostnames = listFromText(form.hostnames, /[\s,]+/);
    if (!hostnames.length) {
      window.alert('Enter at least one application domain.');
      return;
    }
    const hasHttpsPort = form.listeningPorts.some((row) => row.protocol === 'https');
    if (form.applicationType === 'reverse_proxy' && !form.upstreams.some((item) => String(item).trim())) {
      window.alert('Add at least one upstream.');
      return;
    }
    if (hasHttpsPort && !form.certificateId) {
      window.alert('Select an SSL cert for HTTPS ports.');
      return;
    }
    if (form.applicationType === 'redirect' && !String(form.redirectAddress || '').trim()) {
      window.alert('Redirect address is required.');
      return;
    }
    onSave({
      ...form,
      tlsEnabled: String(hasHttpsPort || boolValue(form.tlsEnabled)),
      redirectHttp: String(hasHttpsPort && form.listeningPorts.some((row) => row.protocol === 'http')),
      hostnames: hostnames.join('\n'),
      upstreams: form.upstreams,
      listeningPorts: form.listeningPorts
    });
  }

  return (
    <Modal title={site ? 'Edit Application' : 'Add Application'} onClose={onClose} wide>
      <form onSubmit={submit}>
        <div className="safe-form">
          <DomainChipField label="Domain" value={form.hostnames} onChange={(value) => update('hostnames', value)} placeholder="www.example.com, support *" required />

          <div className="safe-fieldset">
            {form.listeningPorts.map((row, index) => (
              <div className="listen-row" key={`${index}-${row.protocol}`}>
                <TextField label="Port" value={row.port} onChange={(value) => updatePort(index, { port: value })} required />
                <ProtocolToggle value={row.protocol} onChange={(protocol) => updatePort(index, { protocol })} />
                <button type="button" className="table-action ghost" onClick={() => removePort(index)} title="Remove port" disabled={form.listeningPorts.length <= 1}>
                  <Trash2 size={17} />
                </button>
              </div>
            ))}
            <button type="button" className="outline-action" onClick={addPort}><Plus size={16} /> Add Listening Port</button>
          </div>

          <label className="field full">
            <span>SSL Cert</span>
            <select value={form.certificateId} onChange={(event) => update('certificateId', event.target.value)}>
              <option value=""></option>
              {certificates.map((certificate) => (
                <option key={certificate.id} value={certificate.id}>{certificate.name || certificate.id}</option>
              ))}
            </select>
          </label>

          <div className="mode-grid">
            <ModeChoice active={form.applicationType === 'reverse_proxy'} label="Reverse Proxy" onClick={() => update('applicationType', 'reverse_proxy')} />
            <ModeChoice active={form.applicationType === 'static_files'} label="Static Files" onClick={() => update('applicationType', 'static_files')} />
            <ModeChoice active={form.applicationType === 'redirect'} label="Redirect" onClick={() => update('applicationType', 'redirect')} />
          </div>

          {form.applicationType === 'reverse_proxy' && (
            <div className="safe-fieldset">
              {form.upstreams.map((upstream, index) => (
                <div className="upstream-row" key={index}>
                  <TextField label="Upstream" value={upstream} onChange={(value) => updateUpstream(index, value)} placeholder="http://192.168.1.10:8080, not support path" full required />
                  <button type="button" className="table-action ghost" onClick={() => removeUpstream(index)} title="Remove upstream" disabled={form.upstreams.length <= 1}>
                    <Trash2 size={17} />
                  </button>
                </div>
              ))}
              <button type="button" className="outline-action" onClick={addUpstream}><Plus size={16} /> Add Upstream</button>
            </div>
          )}

          {form.applicationType === 'static_files' && (
            <div className="notice full">
              After the site is successfully added, you can manage static files on the site details page.
            </div>
          )}

          {form.applicationType === 'redirect' && (
            <div className="redirect-grid">
              <SelectField label="Status Code" value={form.redirectStatusCode} onChange={(value) => update('redirectStatusCode', value)} options={['301', '302', '307', '308']} />
              <TextField label="Address" value={form.redirectAddress} onChange={(value) => update('redirectAddress', value)} placeholder="http://192.168.1.10:8080, not support path" required />
            </div>
          )}

          <TextField label="Application Name" value={form.name} onChange={(value) => update('name', value)} placeholder="Application Name" full required />
        </div>
        <div className="modal-footer">
          <button type="button" className="tool-button" onClick={onClose}>Cancel</button>
          <button className="tool-button primary">Submit</button>
        </div>
      </form>
    </Modal>
  );
}

function listeningPortsFromSite(site) {
  const tokens = Array.isArray(site?.ports) && site.ports.length ? site.ports : ['80', '443_ssl'];
  return tokens.map((token) => {
    const value = String(token);
    const isHttps = value.endsWith('_ssl');
    return {
      port: value.replace('_ssl', ''),
      protocol: isHttps ? 'https' : 'http'
    };
  });
}

function upstreamsFromSite(site) {
  if (Array.isArray(site?.upstreams) && site.upstreams.length) return site.upstreams;
  if (site?.origin) return [site.origin];
  return ['http://127.0.0.1:9090'];
}

function ProtocolToggle({ value, onChange }) {
  return (
    <div className="protocol-toggle">
      <button type="button" className={value === 'http' ? 'active' : ''} onClick={() => onChange('http')}>HTTP</button>
      <button type="button" className={value === 'https' ? 'active' : ''} onClick={() => onChange('https')}>HTTPS</button>
    </div>
  );
}

function ModeChoice({ active, label, onClick }) {
  return (
    <button type="button" className={`mode-choice ${active ? 'active' : ''}`} onClick={onClick}>
      <span />
      {label}
    </button>
  );
}

function CertificateModal({ certificate, onClose, onSave }) {
  const [form, setForm] = useState(() => ({
    ...defaultCertificate,
    ...(certificate || {}),
    source: certificate?.source || defaultCertificate.source,
    domains: textFromList(certificate?.domains || ''),
    autoRenew: certificate?.autoRenew ?? true,
    renewBeforeDays: certificate?.renewBeforeDays || 30
  }));

  function update(name, value) {
    setForm((current) => ({ ...current, [name]: value }));
  }

  function submit(event) {
    event.preventDefault();
    const domains = listFromText(form.domains, /[\s,]+/);
    if (!domains.length) {
      window.alert('Enter at least one certificate domain.');
      return;
    }
    if (form.source === 'upload' && Boolean(form.certificate.trim()) !== Boolean(form.privateKey.trim())) {
      window.alert('Paste both certificate and private key PEM.');
      return;
    }
    onSave({
      ...form,
      name: form.name || domains[0],
      domains: domains.join('\n')
    });
  }

  return (
    <Modal title={certificate ? 'Edit Cert' : 'Add Cert'} onClose={onClose} className="certificate-modal">
      <form onSubmit={submit} className="cert-form">
        <div className="cert-source-grid">
          <button type="button" className={`cert-source-choice ${form.source === 'upload' ? 'active' : ''}`} onClick={() => update('source', 'upload')}>
            <span className="radio-dot" />
            Upload cert file
          </button>
          <button type="button" className={`cert-source-choice ${form.source === 'certbot' ? 'active' : ''}`} onClick={() => update('source', 'certbot')}>
            <span className="radio-dot" />
            Get free cert
          </button>
        </div>

        {form.source === 'upload' ? (
          <>
            <DomainChipField label="Domain" value={form.domains} onChange={(value) => update('domains', value)} required />
            <label className="field cert-text-field full">
              <span>Name <b>*</b></span>
              <input value={form.name} onChange={(event) => update('name', event.target.value)} placeholder="Certificate name" required />
            </label>
            <label className="field full">
              <span>Certificate PEM</span>
              <textarea
                value={form.certificate}
                onChange={(event) => update('certificate', event.target.value)}
                required={!certificate && !form.certFile}
                placeholder="-----BEGIN CERTIFICATE-----"
              />
            </label>
            <label className="field full">
              <span>Private Key PEM</span>
              <textarea
                value={form.privateKey}
                onChange={(event) => update('privateKey', event.target.value)}
                required={!certificate && !form.keyFile}
                placeholder="-----BEGIN PRIVATE KEY-----"
              />
            </label>
            {(form.certFile || form.keyFile) && (
              <div className="notice full">
                <div>Current certificate: <span className="code">{form.certFile || 'not set'}</span></div>
                <div>Current key: <span className="code">{form.keyFile || 'not set'}</span></div>
              </div>
            )}
          </>
        ) : (
          <>
            <DomainChipField label="Domain" value={form.domains} onChange={(value) => update('domains', value)} required />
            <label className="field cert-text-field full">
              <span>Email Address <b>*</b></span>
              <input type="email" value={form.email} onChange={(event) => update('email', event.target.value)} placeholder="admin@example.com" required />
            </label>
            <div className="notice full">
              Online required, follows Let's Encrypt HTTP-01 method. Automatically renew 30 days before expiration.
            </div>
          </>
        )}
        <div className="modal-footer cert-footer">
          <button type="button" className="tool-button cert-cancel" onClick={onClose}>Cancel</button>
          <button className="tool-button primary cert-submit">Submit</button>
        </div>
      </form>
    </Modal>
  );
}

function IpGroupModal({ group, onClose, onSave }) {
  const [form, setForm] = useState(() => ({
    ...defaultIpGroup,
    ...(group || {}),
    items: textFromList(group?.items || defaultIpGroup.items),
    referenceUrl: group?.referenceUrl || '',
    enabled: String(group?.enabled ?? true)
  }));

  function update(name, value) {
    setForm((current) => ({ ...current, [name]: value }));
  }

  return (
    <Modal title={group ? 'Edit IP Group' : 'Add IP Group'} onClose={onClose}>
      <form onSubmit={(event) => { event.preventDefault(); onSave(form); }}>
        <div className="form-grid">
          <TextField label="Name" value={form.name} onChange={(value) => update('name', value)} full required />
          <TextField label="Reference" value={form.referenceUrl} onChange={(value) => update('referenceUrl', value)} placeholder="http://example.com/ip-list.txt" full />
          <TextAreaField label="Content" value={form.items} onChange={(value) => update('items', value)} placeholder="192.0.2.10/32" />
          <SelectField label="Enabled" value={form.enabled} onChange={(value) => update('enabled', value)} options={['true', 'false']} />
          <TextAreaField label="Description" value={form.description} onChange={(value) => update('description', value)} />
          <p className="form-note full">Reference URL is fetched when Content is empty, then refreshed once per day by the backend.</p>
        </div>
        <ModalFooter onClose={onClose} />
      </form>
    </Modal>
  );
}

function AccessRuleModal({ rule, sites, ipGroups, onClose, onSave }) {
  const [form, setForm] = useState(() => ({
    ...defaultAccessRule,
    ...(rule || {}),
    action: rule?.action === 'allow' ? 'allow' : 'deny',
    siteId: rule?.siteId || '*',
    insertPosition: rule?.insertPosition || 'first',
    enabled: String(rule?.enabled ?? true),
    continueDetect: String(rule?.continueDetect ?? false),
    conditionGroups: accessGroupsFromRule(rule, ipGroups)
  }));
  const siteOptions = [{ value: '*', label: 'All applications' }, ...sites.map((site) => ({ value: site.id, label: site.name || site.id }))];

  function update(name, value) {
    setForm((current) => ({ ...current, [name]: value }));
  }

  function updateGroup(groupIndex, mutator) {
    setForm((current) => {
      const conditionGroups = current.conditionGroups.map((group, index) => {
        if (index !== groupIndex) return group;
        return mutator(group);
      });
      return { ...current, conditionGroups };
    });
  }

  function updateCondition(groupIndex, conditionIndex, mutator) {
    updateGroup(groupIndex, (group) => ({
      ...group,
      conditions: group.conditions.map((condition, index) => (
        index === conditionIndex ? mutator(condition) : condition
      ))
    }));
  }

  function addGroup() {
    setForm((current) => ({
      ...current,
      conditionGroups: [...current.conditionGroups, createAccessConditionGroup(ipGroups)]
    }));
  }

  function removeGroup(groupIndex) {
    setForm((current) => {
      if (current.conditionGroups.length <= 1) return current;
      return {
        ...current,
        conditionGroups: current.conditionGroups.filter((_, index) => index !== groupIndex)
      };
    });
  }

  function addCondition(groupIndex) {
    updateGroup(groupIndex, (group) => ({
      ...group,
      conditions: [...group.conditions, createAccessCondition('source_ip', 'equals', '', ipGroups)]
    }));
  }

  function removeCondition(groupIndex, conditionIndex) {
    setForm((current) => {
      const group = current.conditionGroups[groupIndex];
      if (!group) return current;
      if (group.conditions.length <= 1) {
        if (current.conditionGroups.length <= 1) return current;
        return {
          ...current,
          conditionGroups: current.conditionGroups.filter((_, index) => index !== groupIndex)
        };
      }
      return {
        ...current,
        conditionGroups: current.conditionGroups.map((item, index) => (
          index === groupIndex
            ? { ...item, conditions: item.conditions.filter((_, conditionOffset) => conditionOffset !== conditionIndex) }
            : item
        ))
      };
    });
  }

  function submit(event) {
    event.preventDefault();
    const hasCondition = form.conditionGroups.some((group) => group.conditions.some((condition) => String(condition.content || '').trim()));
    if (!hasCondition) {
      window.alert('Add at least one condition.');
      return;
    }
    onSave(form);
  }

  return (
    <Modal title={rule ? 'Edit Rules' : 'Add rules'} onClose={onClose} wide>
      <form onSubmit={submit}>
        <div className="access-form">
          <div className="access-choice-grid full">
            <button
              type="button"
              className={`access-choice ${form.action === 'allow' ? 'active' : ''}`}
              onClick={() => update('action', 'allow')}
            >
              <ShieldCheck size={18} />
              <span>Allow</span>
            </button>
            <button
              type="button"
              className={`access-choice ${form.action !== 'allow' ? 'active' : ''}`}
              onClick={() => setForm((current) => ({ ...current, action: 'deny', continueDetect: 'false' }))}
            >
              <Shield size={18} />
              <span>Deny Rule</span>
            </button>
          </div>

          <div className="access-top-grid full">
            <TextField label="Name *" value={form.name} onChange={(value) => update('name', value)} required full />
            <SelectField label="Insert Position" value={form.insertPosition} onChange={(value) => update('insertPosition', value)} options={[{ value: 'first', label: 'First' }, { value: 'last', label: 'Last' }]} />
          </div>

          <SelectField label="Application" value={form.siteId} onChange={(value) => update('siteId', value)} options={siteOptions} full />

          <div className="condition-builder full">
            {form.conditionGroups.map((group, groupIndex) => (
              <div className="condition-group" key={groupIndex}>
                {groupIndex > 0 && <div className="condition-connector">OR</div>}
                {group.conditions.map((condition, conditionIndex) => (
                  <div className="condition-row" key={conditionIndex}>
                    <SelectField
                      label="Match Target"
                      value={condition.target}
                      onChange={(value) => updateCondition(groupIndex, conditionIndex, (current) => {
                        const operator = defaultAccessOperator(value);
                        return {
                          ...current,
                          target: value,
                          operator,
                          content: defaultAccessContent(value, operator, ipGroups)
                        };
                      })}
                      options={accessTargetOptions}
                    />
                    <SelectField
                      label="Operator *"
                      value={condition.operator}
                      onChange={(value) => updateCondition(groupIndex, conditionIndex, (current) => ({
                        ...current,
                        operator: value,
                        content: defaultAccessContent(current.target, value, ipGroups)
                      }))}
                      options={accessOperatorsFor(condition.target, ipGroups)}
                    />
                    {renderAccessConditionContent(condition, ipGroups, (value) => updateCondition(groupIndex, conditionIndex, (current) => ({ ...current, content: value })))}
                    <button
                      type="button"
                      className="table-action ghost"
                      onClick={() => removeCondition(groupIndex, conditionIndex)}
                      title="Remove condition"
                      disabled={group.conditions.length <= 1 && form.conditionGroups.length <= 1}
                    >
                      <Trash2 size={17} />
                    </button>
                  </div>
                ))}
                <div className="condition-actions">
                  <button type="button" className="outline-action" onClick={() => addCondition(groupIndex)}>
                    <Plus size={16} /> Add an AND condition
                  </button>
                  {form.conditionGroups.length > 1 && (
                    <button type="button" className="outline-action danger" onClick={() => removeGroup(groupIndex)}>
                      Remove this condition group
                    </button>
                  )}
                </div>
              </div>
            ))}
            <button type="button" className="outline-action full" onClick={addGroup}>
              <Plus size={16} /> Add an OR condition
            </button>
          </div>

          {form.action === 'allow' && (
            <CheckboxField
              label="Continue to detect and log attack after whitelisting."
              checked={boolValue(form.continueDetect)}
              onChange={(checked) => update('continueDetect', checked)}
            />
          )}
          <CheckboxField label="Enabled" checked={boolValue(form.enabled)} onChange={(checked) => update('enabled', checked)} />
        </div>
        <ModalFooter onClose={onClose} />
      </form>
    </Modal>
  );
}

function RuleModal({ rule, sites, onClose, onSave }) {
  const [form, setForm] = useState(() => ({
    ...defaultRule,
    ...(rule || {}),
    enabled: String(rule?.enabled ?? true)
  }));
  const siteOptions = ['*', ...sites.map((site) => site.id)];

  function update(name, value) {
    setForm((current) => ({ ...current, [name]: value }));
  }

  return (
    <Modal title={rule ? 'Edit Rule' : 'Add Rule'} onClose={onClose}>
      <form onSubmit={(event) => { event.preventDefault(); onSave(form); }}>
        <div className="form-grid">
          <TextField label="Name" value={form.name} onChange={(value) => update('name', value)} required />
          <SelectField label="Site" value={form.siteId} onChange={(value) => update('siteId', value)} options={siteOptions} />
          <SelectField label="Target" value={form.target} onChange={(value) => update('target', value)} options={['all', 'url', 'headers', 'body', 'method', 'ip']} />
          <SelectField label="Matcher" value={form.matcher} onChange={(value) => update('matcher', value)} options={['regex', 'contains', 'equals']} />
          <SelectField label="Action" value={form.action} onChange={(value) => update('action', value)} options={['block', 'monitor', 'allow']} />
          <SelectField label="Severity" value={form.severity} onChange={(value) => update('severity', value)} options={['low', 'medium', 'high', 'critical']} />
          <TextField label="Pattern" value={form.pattern} onChange={(value) => update('pattern', value)} full required />
          <TextAreaField label="Description" value={form.description} onChange={(value) => update('description', value)} />
          <SelectField label="Enabled" value={form.enabled} onChange={(value) => update('enabled', value)} options={['true', 'false']} />
        </div>
        <ModalFooter onClose={onClose} />
      </form>
    </Modal>
  );
}

function UserModal({ user, onClose, onSave }) {
  const [form, setForm] = useState(() => ({
    ...defaultUser,
    ...(user || {}),
    password: '',
    enabled: String(user?.enabled ?? true),
    totpEnabled: String(user?.totpEnabled ?? false),
    resetTotp: false
  }));

  function update(name, value) {
    setForm((current) => ({ ...current, [name]: value }));
  }

  function submit(event) {
    event.preventDefault();
    if (!user && form.password.length < 10) {
      window.alert('Password must be at least 10 characters.');
      return;
    }
    onSave(form);
  }

  return (
    <Modal title={user ? 'Edit User' : 'Add User'} onClose={onClose}>
      <form onSubmit={submit}>
        <div className="form-grid">
          <TextField label="Username" value={form.username} onChange={(value) => update('username', value)} required full={!user} />
          <TextField label="Display Name" value={form.displayName} onChange={(value) => update('displayName', value)} />
          <SelectField label="Role" value={form.role} onChange={(value) => update('role', value)} options={['admin', 'viewer']} />
          <SelectField label="Enabled" value={form.enabled} onChange={(value) => update('enabled', value)} options={['true', 'false']} />
          <TextField label={user ? 'New Password' : 'Password'} type="password" value={form.password} onChange={(value) => update('password', value)} required={!user} full />
          <CheckboxField label="Enable Google Authenticator" checked={boolValue(form.totpEnabled)} onChange={(checked) => update('totpEnabled', checked)} />
          {user && boolValue(form.totpEnabled) && (
            <CheckboxField label="Generate new Google Authenticator secret" checked={form.resetTotp} onChange={(checked) => update('resetTotp', checked)} />
          )}
        </div>
        <ModalFooter onClose={onClose} />
      </form>
    </Modal>
  );
}

function TotpSetupModal({ user, onClose, onCopy }) {
  return (
    <Modal title="Google Authenticator" onClose={onClose}>
      <div className="totp-panel">
        <div className="totp-icon"><QrCode size={34} /></div>
        <div>
          <h3>{user.username}</h3>
          <p className="muted">Add this secret to Google Authenticator, then use the 6-digit code when signing in.</p>
        </div>
        <label className="field full">
          <span>Secret</span>
          <input value={user.totpSetupSecret || ''} readOnly />
        </label>
        <label className="field full">
          <span>Authenticator URI</span>
          <textarea value={user.totpSetupUri || ''} readOnly />
        </label>
        <div className="modal-footer compact">
          <button type="button" className="tool-button" onClick={() => onCopy(user.totpSetupSecret || '')}>Copy Secret</button>
          <button type="button" className="tool-button primary" onClick={onClose}>Done</button>
        </div>
      </div>
    </Modal>
  );
}

function Modal({ title, onClose, children, wide = false, className = '' }) {
  return (
    <div className="modal-root">
      <div className={`modal ${wide ? 'wide' : ''} ${className}`}>
        <div className="modal-header">
          <h2>{title}</h2>
          <button type="button" className="icon-button" onClick={onClose} title="Close"><X size={18} /></button>
        </div>
        {children}
      </div>
    </div>
  );
}

function DomainChipField({ label, value, onChange, placeholder = 'Support multiple', required = false }) {
  const inputRef = useRef(null);
  const domains = useMemo(() => listFromText(value, /[\s,]+/), [value]);
  const [draft, setDraft] = useState('');

  function emit(nextItems) {
    const unique = Array.from(new Set(nextItems.map((item) => item.trim()).filter(Boolean)));
    onChange(unique.join('\n'));
  }

  function commit(raw = draft) {
    const items = listFromText(raw, /[\s,]+/);
    if (!items.length) {
      setDraft('');
      return;
    }
    emit([...domains, ...items]);
    setDraft('');
  }

  function remove(item) {
    emit(domains.filter((domain) => domain !== item));
  }

  function clear() {
    emit([]);
    setDraft('');
    inputRef.current?.focus();
  }

  function handleChange(event) {
    const next = event.target.value;
    if (/[\s,]/.test(next)) {
      const endsWithSeparator = /[\s,]$/.test(next);
      const parts = listFromText(next, /[\s,]+/);
      if (endsWithSeparator) {
        emit([...domains, ...parts]);
        setDraft('');
        return;
      }
      if (parts.length > 1) {
        const tail = parts.pop();
        emit([...domains, ...parts]);
        setDraft(tail || '');
        return;
      }
    }
    setDraft(next);
  }

  function handleKeyDown(event) {
    if (['Enter', ',', ' '].includes(event.key)) {
      if (draft.trim()) {
        event.preventDefault();
        commit();
      }
      return;
    }
    if (event.key === 'Backspace' && !draft && domains.length) {
      remove(domains[domains.length - 1]);
    }
  }

  function handlePaste(event) {
    const text = event.clipboardData.getData('text');
    if (/[\s,]/.test(text)) {
      event.preventDefault();
      commit(text);
    }
  }

  return (
    <div className="domain-chip-field full">
      <span className="domain-chip-label">{label}{required && <b>*</b>}</span>
      <div className="domain-chip-box" onClick={() => inputRef.current?.focus()}>
        {domains.map((domain) => (
          <span className="domain-chip" key={domain}>
            {domain}
            <button type="button" onClick={(event) => { event.stopPropagation(); remove(domain); }} title={`Remove ${domain}`}>
              <X size={13} />
            </button>
          </span>
        ))}
        <input
          ref={inputRef}
          value={draft}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          onPaste={handlePaste}
          onBlur={() => commit()}
          placeholder={placeholder}
          aria-required={required}
        />
        {(domains.length > 0 || draft) && (
          <button type="button" className="domain-chip-clear" onClick={(event) => { event.stopPropagation(); clear(); }} title="Clear domains">
            <X size={18} />
          </button>
        )}
      </div>
    </div>
  );
}

function ModalFooter({ onClose }) {
  return (
    <div className="modal-footer">
      <button type="button" className="tool-button" onClick={onClose}>Cancel</button>
      <button className="tool-button primary"><Save size={18} /> Save</button>
    </div>
  );
}

function TextField({ label, value, onChange, required = false, full = false, placeholder = '', type = 'text' }) {
  return (
    <label className={`field ${full ? 'full' : ''}`}>
      <span>{label}</span>
      <input type={type} value={value} onChange={(event) => onChange(event.target.value)} required={required} placeholder={placeholder} />
    </label>
  );
}

function TextAreaField({ label, value, onChange, placeholder = '' }) {
  return (
    <label className="field full">
      <span>{label}</span>
      <textarea value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} />
    </label>
  );
}

function CheckboxField({ label, checked, onChange }) {
  return (
    <label className="checkbox-field">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <span>{label}</span>
    </label>
  );
}

function SelectField({ label, value, onChange, options, full = false }) {
  return (
    <label className={`field ${full ? 'full' : ''}`}>
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => {
          const normalized = typeof option === 'object' ? option : { value: option, label: option };
          return <option key={normalized.value} value={normalized.value}>{normalized.label}</option>;
        })}
      </select>
    </label>
  );
}

async function api(path, options = {}) {
  const init = { method: options.method || 'GET', headers: { ...(options.headers || {}) } };
  if (options.body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(options.body);
  }
  const response = await fetch(path, init);
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const error = new Error(payload.error || response.statusText);
    error.status = response.status;
    error.payload = payload;
    throw error;
  }
  if (response.status === 204) return null;
  return response.json();
}

function formatTime(value) {
  return new Date(value).toLocaleString([], {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  });
}

function listFromText(value, splitter) {
  if (Array.isArray(value)) return value.filter(Boolean);
  return String(value || '').split(splitter).map((item) => item.trim()).filter(Boolean);
}

function boolValue(value) {
  return value === true || value === 'true';
}

function normalizeUpstreamsPayload(value, applicationType) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }
  const items = listFromText(value, /[\n,]+/);
  if (applicationType === 'static_files') return [];
  return items;
}

function normalizeListeningPortsPayload(value) {
  if (Array.isArray(value)) {
    return value
      .map((row) => {
        const port = String(row.port || '').trim();
        if (!port) return null;
        return `${port}${row.protocol === 'https' ? '_ssl' : ''}`;
      })
      .filter(Boolean);
  }
  return listFromText(value, /[\s,]+/);
}

function textFromList(value) {
  return Array.isArray(value) ? value.join('\n') : String(value || '');
}

function inlineList(items) {
  return items?.length ? items.map((item) => <span className="code chip" key={item}>{item}</span>) : <span className="muted">Any</span>;
}

function createAccessCondition(target = 'source_ip', operator = defaultAccessOperator(target), content = '', ipGroups = []) {
  return {
    target,
    operator,
    content: content || defaultAccessContent(target, operator, ipGroups)
  };
}

function createAccessConditionGroup(ipGroups = []) {
  return {
    conditions: [createAccessCondition('source_ip', 'equals', '', ipGroups)]
  };
}

function accessGroupsFromRule(rule, ipGroups) {
  if (Array.isArray(rule?.conditionGroups) && rule.conditionGroups.length) {
    return rule.conditionGroups.map((group) => ({
      conditions: Array.isArray(group?.conditions) && group.conditions.length
        ? group.conditions.map((condition) => normalizeAccessCondition(condition, ipGroups))
        : [createAccessCondition('source_ip', 'equals', '', ipGroups)]
    }));
  }

  const groups = [];
  for (const ipGroupId of rule?.ipGroupIds || []) {
    groups.push({
      conditions: [createAccessCondition('source_ip', 'in_ip_group', ipGroupId, ipGroups)]
    });
  }
  for (const item of rule?.ips || []) {
    const value = String(item || '').trim();
    if (!value) continue;
    groups.push({
      conditions: [createAccessCondition('source_ip', value.includes('/') ? 'cidr' : 'equals', value, ipGroups)]
    });
  }
  for (const method of rule?.methods || []) {
    groups.push({
      conditions: [createAccessCondition('method', 'equals', method, ipGroups)]
    });
  }
  for (const pattern of rule?.uriPatterns || []) {
    groups.push({
      conditions: [createAccessCondition('uri', 'regex', pattern, ipGroups)]
    });
  }
  for (const pattern of rule?.hostPatterns || []) {
    groups.push({
      conditions: [createAccessCondition('host', 'regex', pattern, ipGroups)]
    });
  }
  for (const pattern of rule?.userAgentPatterns || []) {
    groups.push({
      conditions: [createAccessCondition('user_agent', 'regex', pattern, ipGroups)]
    });
  }
  return groups.length ? groups : [createAccessConditionGroup(ipGroups)];
}

function normalizeAccessCondition(condition, ipGroups = []) {
  const target = accessTargetOptions.some((option) => option.value === condition?.target) ? condition.target : 'source_ip';
  const operator = accessOperatorsFor(target, ipGroups).some((option) => option.value === condition?.operator)
    ? condition.operator
    : defaultAccessOperator(target);
  return {
    target,
    operator,
    content: String(condition?.content || '').trim() || defaultAccessContent(target, operator, ipGroups)
  };
}

function defaultAccessOperator(target) {
  const options = accessOperatorOptions[target] || accessOperatorOptions.source_ip;
  return options[0]?.value || 'equals';
}

function defaultAccessContent(target, operator, ipGroups) {
  if (target === 'source_ip' && operator === 'in_ip_group') {
    return ipGroups[0]?.id || '';
  }
  if (target === 'source_ip') return '';
  if (target === 'method') return 'GET';
  return '';
}

function accessOperatorsFor(target, ipGroups) {
  const options = accessOperatorOptions[target] || accessOperatorOptions.source_ip;
  if (target !== 'source_ip') return options;
  return options.map((option) => {
    if (option.value !== 'in_ip_group') return option;
    return {
      ...option,
      label: ipGroups.length ? 'In IP Group' : 'In IP Group'
    };
  });
}

function renderAccessConditionContent(condition, ipGroups, onChange) {
  const target = condition.target || 'source_ip';
  if (target === 'source_ip' && condition.operator === 'in_ip_group') {
    return (
      <label className="field condition-content">
        <span>Content *</span>
        <select value={condition.content} onChange={(event) => onChange(event.target.value)}>
          {ipGroups.length ? ipGroups.map((group) => <option key={group.id} value={group.id}>{group.name || group.id}</option>) : <option value="">No IP groups</option>}
        </select>
      </label>
    );
  }
  return (
    <label className="field condition-content">
      <span>Content *</span>
      <input
        value={condition.content}
        onChange={(event) => onChange(event.target.value)}
        placeholder={accessConditionPlaceholder(target, condition.operator)}
      />
      <small className="field-hint">{accessConditionHint(target, condition.operator)}</small>
    </label>
  );
}

function accessConditionPlaceholder(target, operator) {
  if (target === 'source_ip' && operator === 'cidr') return '192.168.0.0/24';
  if (target === 'method') return 'GET';
  if (target === 'uri') return '/admin';
  if (target === 'host') return 'example.com';
  if (target === 'user_agent') return 'curl';
  return '192.168.10.10';
}

function accessConditionHint(target, operator) {
  if (target === 'source_ip' && operator === 'cidr') return 'CIDR block';
  if (target === 'source_ip') return 'Single IP';
  if (target === 'method') return 'GET, POST, PUT...';
  if (operator === 'regex') return 'Regex pattern';
  if (operator === 'contains') return 'Substring match';
  return '';
}

function normalizeAccessConditionGroupsPayload(groups, rule) {
  const source = Array.isArray(groups) && groups.length ? groups : accessGroupsFromRule(rule, []);
  return source.map((group) => ({
    conditions: (group.conditions || [])
      .map((condition) => normalizeAccessConditionForPayload(condition))
      .filter((condition) => condition.target && condition.operator && String(condition.content || '').trim())
  })).filter((group) => group.conditions.length);
}

function normalizeAccessConditionForPayload(condition) {
  const target = String(condition?.target || 'source_ip');
  const operator = String(condition?.operator || defaultAccessOperator(target));
  const content = String(condition?.content || '').trim();
  return { target, operator, content };
}

function flattenAccessConditions(groups) {
  const flattened = {
    ipGroupIds: [],
    ips: [],
    methods: [],
    uriPatterns: [],
    hostPatterns: [],
    userAgentPatterns: []
  };

  for (const group of groups || []) {
    for (const condition of group.conditions || []) {
      if (condition.target === 'source_ip') {
        if (condition.operator === 'in_ip_group') {
          flattened.ipGroupIds.push(condition.content);
        } else if (condition.operator === 'equals' || condition.operator === 'cidr') {
          flattened.ips.push(condition.content);
        }
      } else if (condition.target === 'method' && condition.operator === 'equals') {
        flattened.methods.push(condition.content.toUpperCase());
      } else if (condition.target === 'uri') {
        flattened.uriPatterns.push(accessPatternFromCondition(condition));
      } else if (condition.target === 'host') {
        flattened.hostPatterns.push(accessPatternFromCondition(condition));
      } else if (condition.target === 'user_agent') {
        flattened.userAgentPatterns.push(accessPatternFromCondition(condition));
      }
    }
  }

  return {
    ipGroupIds: Array.from(new Set(flattened.ipGroupIds)),
    ips: Array.from(new Set(flattened.ips)),
    methods: Array.from(new Set(flattened.methods)),
    uriPatterns: Array.from(new Set(flattened.uriPatterns)),
    hostPatterns: Array.from(new Set(flattened.hostPatterns)),
    userAgentPatterns: Array.from(new Set(flattened.userAgentPatterns))
  };
}

function accessPatternFromCondition(condition) {
  if (condition.operator === 'contains') {
    return escapeRegex(condition.content);
  }
  if (condition.operator === 'equals') {
    return `^${escapeRegex(condition.content)}$`;
  }
  return condition.content;
}

function accessRuleMatch(rule, ipGroups) {
  const groups = Array.isArray(rule?.conditionGroups) && rule.conditionGroups.length ? rule.conditionGroups : accessGroupsFromRule(rule, ipGroups);
  const summary = groups.map((group) => group.conditions.map((condition) => accessConditionSummary(condition, ipGroups)).join(' AND '));
  return summary.length ? summary.map((item) => <span className="code chip" key={item}>{item}</span>) : <span className="muted">Any</span>;
}

function accessConditionSummary(condition, ipGroups) {
  const targetLabel = accessTargetOptions.find((option) => option.value === condition.target)?.label || condition.target;
  const operatorLabel = accessOperatorsFor(condition.target, ipGroups).find((option) => option.value === condition.operator)?.label || condition.operator;
  let content = condition.content;
  if (condition.target === 'source_ip' && condition.operator === 'in_ip_group') {
    content = ipGroups.find((group) => group.id === condition.content)?.name || condition.content;
  }
  return `${targetLabel} ${operatorLabel} ${content}`;
}

function escapeRegex(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizedSiteFeatures(site) {
  const features = site?.features || {};
  return {
    httpFlood: features.httpFlood !== false,
    botProtection: features.botProtection !== false,
    auth: features.auth === true,
    attacks: features.attacks !== false,
    acl: site?.acl?.enabled !== false
  };
}

function applicationTypeLabel(value) {
  if (value === 'static_files') return 'Static Files';
  if (value === 'redirect') return 'Redirect';
  return 'Reverse Proxy';
}

function siteCounters(site, logs) {
  const hosts = new Set(site.hostnames || []);
  const today = new Date().toDateString();
  return (logs || []).reduce((totals, entry) => {
    const entryDate = entry.at ? new Date(entry.at) : null;
    const sameDay = entryDate && entryDate.toDateString() === today;
    const matches = entry.siteId === site.id || hosts.has(entry.host) || hosts.has(entry.siteName);
    if (!sameDay || !matches) return totals;
    totals.requests += 1;
    if (entry.verdict === 'block') totals.blocked += 1;
    return totals;
  }, { requests: 0, blocked: 0 });
}

function formatCompact(value) {
  const number = Number(value || 0);
  if (number >= 1000000) return `${(number / 1000000).toFixed(1)}m`;
  if (number >= 1000) return `${(number / 1000).toFixed(1)}k`;
  return String(number);
}
