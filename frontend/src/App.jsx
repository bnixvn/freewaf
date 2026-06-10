import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  BarChart3,
  Copy,
  Edit3,
  Globe2,
  Info,
  KeyRound,
  Loader2,
  LockKeyhole,
  ListFilter,
  LogOut,
  Network,
  Plus,
  QrCode,
  RefreshCw,
  Save,
  Server,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  Trash2,
  Upload,
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
  logs: 'Access Logs',
  settings: 'Panel Security'
};

const emptyStats = {
  total: 0,
  blocked: 0,
  challenged: 0,
  protected: 0,
  monitored: 0,
  allowed: 0,
  blockRate: 0,
  protectedRate: 0,
  botTypes: [],
  botTypeCount: 0,
  botRequestTotal: 0,
  botChallengeTotal: 0,
  topCountries: [],
  blockedCountries: [],
  countryCount: 0,
  blockedCountryCount: 0,
  protectedCountryCount: 0,
  geoAttribution: null,
  topRules: [],
  topSites: [],
  siteStats: [],
  statusGroups: [],
  qps: 0,
  qpsTimeline: [],
  timeline: []
};

function createEmptyData() {
  return {
    sites: [],
    rules: [],
    accessRules: [],
    ipGroups: [],
    certificates: [],
    users: [],
    logs: [],
    settings: { panel: {}, applicationDefaults: { proxy: {}, modSecurity: {} }, challengePage: {} },
    stats: { ...emptyStats, timeline: [] }
  };
}

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
  proxyModifyHostHeader: 'true',
  proxyForwardedHeaders: 'true',
  proxyHostHeader: '$http_host',
  proxyXForwardedProto: '$scheme',
  proxyXForwardedHost: '$http_host',
  proxySslServerName: 'true',
  modSecurityEnabled: 'true',
  modSecurityMode: 'on',
  modSecurityRuleset: 'comodo',
  modSecurityRequestBodyLimit: '13107200',
  aclEnabled: 'true',
  aclRateLimitMode: 'custom',
  aclWaitingRoom: 'false',
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
  featureGeoBlock: 'false',
  featureAuth: 'false',
  featureAttacks: 'true',
  mode: 'block',
  enabled: 'true'
};

const defaultApplicationDefaults = {
  proxyForceHttps: 'false',
  proxyHsts: 'false',
  proxyHstsMaxAge: '15768000',
  proxyGzip: 'true',
  proxyBrotli: 'false',
  proxyHttp2: 'true',
  proxyResetXff: 'true',
  proxyModifyHostHeader: 'true',
  proxyForwardedHeaders: 'true',
  proxyHostHeader: '$http_host',
  proxyXForwardedHost: '$http_host',
  proxyXForwardedProto: '$scheme',
  proxySslServerName: 'true',
  modSecurityEnabled: 'true',
  modSecurityMode: 'on',
  modSecurityRuleset: 'comodo',
  modSecurityRequestBodyLimit: '13107200'
};

const defaultChallengePage = {
  brandName: 'FreeWAF',
  title: 'Security check',
  message: 'We are verifying your browser before continuing.',
  logoUrl: '',
  supportUrl: '',
  primaryColor: '#18a69a',
  backgroundColor: '#f5f7f8',
  textColor: '#17202a',
  tokenTtlMinutes: '30',
  waitSeconds: '5'
};

const defaultBotLoginPathPatterns = [
  '^/wp-login\\.php(?:\\?|$)',
  '^/wp-admin/?(?:\\?|$)',
  '^/(?:admin|administrator)(?:/login)?/?(?:\\?|$)',
  '^/(?:login|user/login|account/login)(?:/|\\?|$)',
  '^/clientarea\\.php(?:\\?|$)',
  '^/cart\\.php(?:\\?[^#]*\\ba=login\\b|$)',
  '^/index\\.php/(?:login|admin)(?:/|\\?|$)',
  '^/admin/index\\.php(?:\\?|$)'
];

const defaultBotRateChallenge = {
  enabled: true,
  windowSeconds: 10,
  challengeCount: 100,
  blockCount: 200
};

const botRateWindowOptions = [5, 10, 15, 20, 30, 60].map((seconds) => ({
  value: String(seconds),
  label: `${seconds} seconds`
}));

const siteFeatureLabels = {
  httpFlood: 'HTTP FLOOD',
  botProtection: 'BOT PROTECT',
  geoBlock: 'GEO BLOCK',
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

const floodActionOptions = [
  { value: 'challenge_v1', label: 'Anti-Bot challenge' },
  { value: 'block', label: 'Block' },
  { value: 'monitor', label: 'Monitor only' }
];

const geoBlockActionOptions = [
  { value: 'block', label: 'Block' },
  { value: 'monitor', label: 'Monitor only' }
];

const geoQuickCountries = [
  { code: 'US', name: 'United States' },
  { code: 'CN', name: 'China' },
  { code: 'RU', name: 'Russia' },
  { code: 'VN', name: 'Vietnam' },
  { code: 'SG', name: 'Singapore' },
  { code: 'ID', name: 'Indonesia' },
  { code: 'JP', name: 'Japan' },
  { code: 'KR', name: 'South Korea' },
  { code: 'IN', name: 'India' },
  { code: 'BR', name: 'Brazil' },
  { code: 'DE', name: 'Germany' },
  { code: 'FR', name: 'France' }
];

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
  const [logsLoading, setLogsLoading] = useState(false);
  const [logDomain, setLogDomain] = useState('');
  const [logPage, setLogPage] = useState(1);
  const [logPageSize, setLogPageSize] = useState(50);
  const [logResult, setLogResult] = useState({ logs: [], total: 0, page: 1, pages: 1, domains: [] });

  useEffect(() => {
    loadAuth();
  }, []);

  useEffect(() => {
    if (!auth.authenticated || auth.loading || !['dashboard', 'sites'].includes(activeView)) {
      return undefined;
    }
    const refreshTimer = window.setInterval(() => {
      loadState(false, false);
    }, 10000);
    return () => window.clearInterval(refreshTimer);
  }, [auth.authenticated, auth.loading, activeView]);

  useEffect(() => {
    if (!auth.authenticated || auth.loading || activeView !== 'logs') {
      return undefined;
    }
    const loadTimer = window.setTimeout(() => {
      loadLogs({}, false, true);
    }, 250);
    const refreshTimer = window.setInterval(() => {
      loadLogs({}, false, false);
    }, 10000);
    return () => {
      window.clearTimeout(loadTimer);
      window.clearInterval(refreshTimer);
    };
  }, [auth.authenticated, auth.loading, activeView, filter, logDomain, logPage, logPageSize]);

  async function loadAuth() {
    setLoading(true);
    try {
      const status = await api('/api/auth/status');
      if (status.authenticated) {
        setData((current) => current || createEmptyData());
        setAuth({ loading: false, ...status });
        await loadState(false, false);
      } else {
        setData(null);
        setAuth({ loading: false, ...status });
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
      setData(await api('/api/state?logLimit=1000'));
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

  async function loadLogs(overrides = {}, announce = false, manageLoading = true) {
    const nextPage = Number(overrides.page || logPage || 1);
    const nextPageSize = Number(overrides.pageSize || logPageSize || 50);
    const nextDomain = overrides.domain ?? logDomain;
    const nextSearch = overrides.search ?? filter;
    const params = new URLSearchParams({
      page: String(nextPage),
      pageSize: String(nextPageSize)
    });
    if (nextDomain) params.set('domain', nextDomain);
    if (nextSearch.trim()) params.set('search', nextSearch.trim());

    if (manageLoading) setLogsLoading(true);
    try {
      const result = await api(`/api/logs?${params.toString()}`);
      setLogResult(result);
      if (result.page && result.page !== nextPage) {
        setLogPage(result.page);
      }
      if (announce) showToast('Logs refreshed');
      return result;
    } catch (error) {
      if (error.status === 401) {
        const status = await api('/api/auth/status').catch(() => ({ authenticated: false, setupRequired: false, user: null }));
        setAuth({ loading: false, ...status });
        setData(null);
      } else {
        showToast(error.message, true);
      }
      return null;
    } finally {
      if (manageLoading) setLogsLoading(false);
    }
  }

  async function setupAdmin(payload) {
    setLoading(true);
    try {
      const status = await api('/api/auth/setup', { method: 'POST', body: payload });
      setData(createEmptyData());
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
      setData(createEmptyData());
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

  function updateDataItem(collection, id, updater) {
    setData((current) => {
      if (!current) return current;
      return {
        ...current,
        [collection]: (current[collection] || []).map((item) => (
          item.id === id ? (typeof updater === 'function' ? updater(item) : { ...item, ...updater }) : item
        ))
      };
    });
  }

  function updateSettingsLocal(settings) {
    setData((current) => (current ? { ...current, settings } : current));
  }

  async function toggleSite(site, enabled) {
    updateDataItem('sites', site.id, { enabled });
    try {
      const saved = await api(`/api/sites/${site.id}`, { method: 'PATCH', body: { enabled } });
      updateDataItem('sites', site.id, saved);
    } catch (error) {
      showToast(error.message, true);
      await loadState(false, false);
    }
  }

  async function toggleUnderAttack(site, enabled) {
    const underAttack = { ...(site.underAttack || {}), enabled };
    updateDataItem('sites', site.id, { underAttack });
    try {
      const saved = await api(`/api/sites/${site.id}`, {
        method: 'PATCH',
        body: { underAttack }
      });
      updateDataItem('sites', site.id, saved);
      showToast(enabled ? 'Under Attack Mode enabled' : 'Under Attack Mode disabled');
    } catch (error) {
      showToast(error.message, true);
      await loadState(false, false);
    }
  }

  async function toggleRule(rule, enabled) {
    updateDataItem('rules', rule.id, { enabled });
    try {
      const saved = await api(`/api/rules/${rule.id}`, { method: 'PATCH', body: { enabled } });
      updateDataItem('rules', rule.id, saved);
    } catch (error) {
      showToast(error.message, true);
      await loadState(false, false);
    }
  }

  async function toggleIpGroup(group, enabled) {
    updateDataItem('ipGroups', group.id, { enabled });
    try {
      const saved = await api(`/api/ip-groups/${group.id}`, { method: 'PATCH', body: { enabled } });
      updateDataItem('ipGroups', group.id, saved);
    } catch (error) {
      showToast(error.message, true);
      await loadState(false, false);
    }
  }

  async function toggleAccessRule(rule, enabled) {
    updateDataItem('accessRules', rule.id, { enabled });
    try {
      const saved = await api(`/api/access-rules/${rule.id}`, { method: 'PATCH', body: { enabled } });
      updateDataItem('accessRules', rule.id, saved);
    } catch (error) {
      showToast(error.message, true);
      await loadState(false, false);
    }
  }

  async function saveSite(site) {
    try {
      const applicationType = site.applicationType || 'reverse_proxy';
      const upstreams = normalizeUpstreamsPayload(site.upstreams || site.origin, applicationType);
      const ports = normalizeListeningPortsPayload(site.listeningPorts || site.ports);
      const primaryPort = Number(String(ports[0] || '8080').replace('_ssl', '')) || 8080;
      const hasHttpPort = ports.some((port) => !String(port).endsWith('_ssl'));
      const hasHttpsPort = ports.some((port) => String(port).endsWith('_ssl'));
      const forceHttps = hasHttpPort && hasHttpsPort && boolValue(site.proxyForceHttps);
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
          modifyHostHeader: boolValue(site.proxyModifyHostHeader),
          forwardedHeaders: boolValue(site.proxyForwardedHeaders),
          hostHeader: site.proxyHostHeader || '$http_host',
          xForwardedProto: site.proxyXForwardedProto || '$scheme',
          xForwardedHost: site.proxyXForwardedHost || '$http_host',
          proxySslServerName: boolValue(site.proxySslServerName)
        },
        modSecurity: {
          enabled: boolValue(site.modSecurityEnabled),
          mode: site.modSecurityMode === 'detection_only' ? 'detection_only' : 'on',
          ruleset: site.modSecurityRuleset === 'owasp' ? 'owasp' : 'comodo',
          requestBodyLimit: Number(site.modSecurityRequestBodyLimit || 13107200)
        },
        acl: {
          enabled: boolValue(site.aclEnabled),
          rateLimitMode: site.aclRateLimitMode || 'custom',
          waitingRoom: boolValue(site.aclWaitingRoom),
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
          geoBlock: boolValue(site.featureGeoBlock),
          auth: boolValue(site.featureAuth),
          attacks: boolValue(site.featureAttacks)
        },
        botProtection: botProtectPayloadFromConfig(site.botProtection, boolValue(site.featureBotProtection)),
        geoBlock: geoBlockPayloadFromConfig(site.geoBlock, boolValue(site.featureGeoBlock)),
        underAttack: site.underAttack || { enabled: false }
      };
      const id = payload.id;
      delete payload.id;
      await api(id ? `/api/sites/${id}` : '/api/sites', {
        method: id ? 'PUT' : 'POST',
        body: payload
      });
      setModal(null);
      await loadState();
      showToast('Site saved and Nginx reloaded');
    } catch (error) {
      showToast(error.message, true);
    }
  }

  async function saveHttpFlood(site, flood) {
    try {
      const currentAcl = site.acl || {};
      const currentFeatures = site.features || {};
      await api(`/api/sites/${site.id}`, {
        method: 'PATCH',
        body: {
          acl: {
            ...currentAcl,
            enabled: true,
            rateLimitMode: flood.rateLimitMode,
            waitingRoom: flood.waitingRoom,
            accessLimit: flood.accessLimit,
            attackLimit: flood.attackLimit,
            errorLimit: flood.errorLimit
          },
          features: {
            ...currentFeatures,
            httpFlood: true
          }
        }
      });
      setModal(null);
      await loadState();
      showToast('HTTP Flood settings saved and Nginx reloaded');
    } catch (error) {
      showToast(error.message, true);
    }
  }

  async function saveBotProtection(site, protection) {
    try {
      const currentFeatures = site.features || {};
      await api(`/api/sites/${site.id}`, {
        method: 'PATCH',
        body: {
          botProtection: protection,
          features: {
            ...currentFeatures,
            botProtection: protection.enabled
          }
        }
      });
      setModal(null);
      await loadState();
      showToast('Bot Protect settings saved and Nginx reloaded');
    } catch (error) {
      showToast(error.message, true);
    }
  }

  async function saveGeoBlock(site, geoBlock) {
    try {
      const currentFeatures = site.features || {};
      await api(`/api/sites/${site.id}`, {
        method: 'PATCH',
        body: {
          geoBlock,
          features: {
            ...currentFeatures,
            geoBlock: geoBlock.enabled
          }
        }
      });
      setModal(null);
      await loadState();
      showToast('Geo Block settings saved and Nginx reloaded');
    } catch (error) {
      showToast(error.message, true);
    }
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
      enabled: group.enabled === 'true' || group.enabled === true
    };
    if (!group.itemsExternal || String(group.items || '').trim()) {
      payload.items = group.items;
    }
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
    setLogPage(1);
    setLogResult({ logs: [], total: 0, page: 1, pages: 1, domains: [] });
    await loadState();
    if (activeView === 'logs') {
      await loadLogs({ page: 1 }, false, false);
    }
    showToast('Logs cleared');
  }

  async function resetStatistics() {
    if (!window.confirm('Reset all statistics and delete all access logs? This cannot be undone.')) return;
    await api('/api/stats', { method: 'DELETE' });
    setLogPage(1);
    setLogResult({ logs: [], total: 0, page: 1, pages: 1, domains: [] });
    await loadState();
    showToast('Statistics reset');
  }

  async function refreshCurrentView() {
    if (activeView === 'logs') {
      await loadLogs({}, true, true);
      return;
    }
    await loadState(true);
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
    const saved = await api('/api/settings', {
      method: 'PATCH',
      body: { panel }
    });
    updateSettingsLocal(saved);
    showToast('Panel settings saved');
  }

  async function saveApplicationDefaults(applicationDefaults) {
    const saved = await api('/api/settings', {
      method: 'PATCH',
      body: { applicationDefaults }
    });
    updateSettingsLocal(saved);
    const result = await api('/api/nginx/apply', {
      method: 'POST',
      body: { test: true, reload: true }
    });
    await loadState(false, false);
    showToast(result.ok ? 'Global defaults saved and Nginx reloaded' : 'Global defaults saved, but Nginx reload failed', !result.ok);
  }

  async function saveChallengePage(challengePage) {
    const saved = await api('/api/settings', {
      method: 'PATCH',
      body: { challengePage }
    });
    updateSettingsLocal(saved);
    showToast('Challenge page saved');
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
      toggleUnderAttack,
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
      resetStatistics,
      copyText,
      previewNginx,
      applyNginx,
      savePanelSettings,
      saveApplicationDefaults,
      saveChallengePage,
      saveUser,
      saveHttpFlood,
      saveBotProtection,
      saveGeoBlock,
      deleteUser,
      logsLoading,
      logResult,
      logDomain,
      setLogDomain,
      logPage,
      setLogPage,
      logPageSize,
      setLogPageSize,
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
  }, [activeView, data, filter, auth, logsLoading, logResult, logDomain, logPage, logPageSize]);

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
            <button className="icon-button" onClick={refreshCurrentView} title="Refresh" disabled={loading || logsLoading}>
              <RefreshCw size={18} className={loading || logsLoading ? 'spin' : ''} />
            </button>
            {activeView === 'dashboard' && (
              <button className="icon-button danger" onClick={resetStatistics} title="Reset statistics" disabled={loading}>
                <Trash2 size={18} />
              </button>
            )}
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
      {modal?.type === 'httpFlood' && (
        <HttpFloodModal
          site={modal.site}
          settings={data?.settings || {}}
          onClose={() => setModal(null)}
          onSave={(flood) => saveHttpFlood(modal.site, flood)}
        />
      )}
      {modal?.type === 'botProtect' && (
        <BotProtectModal
          site={modal.site}
          onClose={() => setModal(null)}
          onSave={(protection) => saveBotProtection(modal.site, protection)}
        />
      )}
      {modal?.type === 'geoBlock' && (
        <GeoBlockModal
          site={modal.site}
          onClose={() => setModal(null)}
          onSave={(geoBlock) => saveGeoBlock(modal.site, geoBlock)}
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
  const stats = { ...emptyStats, ...(data?.stats || {}) };
  const topRule = stats.topRules[0]?.name || 'None';
  const timeline = stats.timeline || [];
  const protectedTotal = Number(stats.protected ?? (Number(stats.blocked || 0) + Number(stats.challenged || 0)));
  const challengedTotal = Number(stats.challenged || 0);
  const blockedTotal = Number(stats.blocked || 0);
  const botTypes = stats.botTypes || [];
  const countries = stats.topCountries || [];
  const blockedCountries = stats.blockedCountries || countries.filter((country) => Number(country.blocked || 0) > 0);
  const qpsTimeline = stats.qpsTimeline || [];
  const qpsValue = Number(stats.qps ?? qpsTimeline[qpsTimeline.length - 1]?.qps ?? 0);
  const requestsMax = Math.max(0, ...timeline.map((point) => Number(point.total || 0)));
  const blockedMax = Math.max(0, ...timeline.map((point) => Number(point.blocked || 0)));
  const trafficWindow = timeline.reduce((totals, point) => ({
    total: totals.total + Number(point.total || 0),
    protected: totals.protected + Number(point.protected ?? (Number(point.blocked || 0) + Number(point.challenged || 0))),
    challenged: totals.challenged + Number(point.challenged || 0),
    blocked: totals.blocked + Number(point.blocked || 0)
  }), { total: 0, protected: 0, challenged: 0, blocked: 0 });

  return (
    <>
      <div className="metric-grid">
        <Metric label="Requests" value={formatCompact(stats.total)} note="Analyzed request events" />
        <Metric label="Protected" value={formatCompact(protectedTotal)} note={`${stats.protectedRate ?? stats.blockRate}% challenge or block rate`} />
        <Metric label="Challenges" value={formatCompact(challengedTotal)} note={`${formatCompact(blockedTotal)} hard blocks`} />
        <Metric label="Bot Types" value={formatCompact(stats.botTypeCount)} note={`${formatCompact(stats.botRequestTotal)} bot-like requests`} />
        <Metric label="Blocked Requests" value={formatCompact(blockedTotal)} note={`${stats.blockRate ?? 0}% hard block rate`} />
      </div>
      <div className="dashboard-grid">
        <section className="panel dashboard-traffic-panel">
          <div className="panel-heading traffic-heading">
            <h2>Traffic Window</h2>
            <div className="traffic-pills">
              <span className="pill">{formatCompact(trafficWindow.total)} requests</span>
              <span className="pill">{formatCompact(trafficWindow.protected)} protected</span>
              <span className="pill">{formatCompact(trafficWindow.challenged)} challenged</span>
              <span className="pill">{formatCompact(trafficWindow.blocked)} blocked</span>
              <span className="pill">5 minute buckets</span>
            </div>
          </div>
          <Timeline points={timeline} compact />
        </section>
        <section className="panel traffic-widget dashboard-qps-panel">
          <div className="traffic-widget-heading">
            <div className="traffic-title-row">
              <h2>Query Per Second</h2>
              <span className="qps-badge"><BarChart3 size={14} /> {formatQps(qpsValue)}</span>
            </div>
            <RefreshCw size={17} className="traffic-refresh-icon" />
          </div>
          <QpsBars points={qpsTimeline} />
        </section>
        <section className="dashboard-insight-band">
          <CompactInsightColumn
            title="Top 10 Bot Types"
            pill={`${formatCompact(stats.botChallengeTotal)} challenged`}
            rows={botTypes}
            empty="No bot-like traffic detected."
            maxValue={Math.max(1, ...botTypes.map((item) => Number(item.count || 0)))}
            barValue={(item) => Number(item.count || 0)}
            valueLabel={(item) => `${formatCompact(item.count)} requests`}
            detailLabel={(item) => `${formatCompact(item.challenged)} challenged / ${formatCompact(item.blocked)} blocked`}
          />
          <CompactInsightColumn
            title="Top 10 Country Requests"
            pill={`${formatCompact(stats.countryCount)} seen`}
            rows={countries}
            empty="No country data available."
            maxValue={Math.max(1, ...countries.map((item) => Number(item.count || 0)))}
            label={(item) => countryDisplayName(item)}
            barValue={(item) => Number(item.count || 0)}
            valueLabel={(item) => `${formatCompact(item.count)} requests`}
            detailLabel={(item) => `${formatCompact(item.protected)} protected`}
            footer={stats.geoAttribution?.available ? (
              <a className="attribution-link" href={stats.geoAttribution.url} target="_blank" rel="noreferrer">
                IP geolocation by {stats.geoAttribution.provider}
              </a>
            ) : null}
          />
          <CompactInsightColumn
            title="Top 10 Countries With Blocks"
            pill={`${formatCompact(stats.blockedCountryCount)}`}
            rows={blockedCountries}
            empty="No countries with hard blocks."
            maxValue={Math.max(1, ...blockedCountries.map((item) => Number(item.blocked || 0)))}
            label={(item) => countryDisplayName(item)}
            barValue={(item) => Number(item.blocked || 0)}
            valueLabel={(item) => `${formatCompact(item.blocked)} blocked`}
            detailLabel={(item) => `${formatCompact(item.challenged)} challenged`}
            footer={<div className="insight-note">Top signal: {topRule}</div>}
          />
        </section>
        <section className="panel traffic-widget dashboard-status-panel">
          <div className="traffic-widget-heading">
            <h2>Requests Status</h2>
            <span className="traffic-max">Max <strong>{formatCompact(requestsMax)}</strong></span>
          </div>
          <RequestsStatusChart points={timeline} />
        </section>
        <section className="panel traffic-widget dashboard-blocking-panel">
          <div className="traffic-widget-heading">
            <h2>Blocking Status</h2>
            <span className="traffic-max">Max <strong>{formatCompact(blockedMax)}</strong></span>
          </div>
          <RequestsStatusChart points={timeline} valueKey="blocked" tone="blocking" />
        </section>
      </div>
    </>
  );
}

function CompactInsightColumn({ title, pill, rows, empty, maxValue, label, barValue, valueLabel, detailLabel, footer }) {
  return (
    <div className="compact-insight-column">
      <div className="compact-insight-heading">
        <h2>{title}</h2>
        <span className="pill">{pill}</span>
      </div>
      <div className="compact-insight-scroll">
        <InsightRows
          rows={rows}
          empty={empty}
          maxValue={maxValue}
          label={label}
          barValue={barValue}
          valueLabel={valueLabel}
          detailLabel={detailLabel}
        />
      </div>
      {footer}
    </div>
  );
}

function SitesView({ data, setModal, toggleSite, toggleUnderAttack, deleteSite }) {
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
            stats={data.stats?.siteStats?.find((item) => item.siteId === site.id)}
            onEdit={() => setModal({ type: 'site', site })}
            onDelete={() => deleteSite(site)}
            onToggle={(checked) => toggleSite(site, checked)}
            onToggleUnderAttack={(checked) => toggleUnderAttack(site, checked)}
            onConfigureFlood={() => setModal({ type: 'httpFlood', site })}
            onConfigureBot={() => setModal({ type: 'botProtect', site })}
            onConfigureGeo={() => setModal({ type: 'geoBlock', site })}
          />
        ))}
      </div>
    </section>
  );
}

function ApplicationCard({ site, stats, onEdit, onDelete, onToggle, onToggleUnderAttack, onConfigureFlood, onConfigureBot, onConfigureGeo }) {
  const features = normalizedSiteFeatures(site);
  const counters = stats || { requests: 0, protected: 0 };
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
        <button
          className={`under-attack-button ${site.underAttack?.enabled ? 'active' : ''}`}
          type="button"
          onClick={() => onToggleUnderAttack(!site.underAttack?.enabled)}
          title="Challenge new visitors while the application is under attack"
        >
          <ShieldAlert size={14} /> UNDER ATTACK
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
            <button className="table-action delete-action" onClick={onDelete} title="Delete application" aria-label="Delete application">
              <Trash2 size={17} />
            </button>
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
          {Object.entries(siteFeatureLabels).map(([key, label]) => key === 'httpFlood' ? (
            <button className={`feature-chip feature-chip-button ${features[key] ? 'active' : ''}`} key={key} type="button" onClick={onConfigureFlood} title="Configure HTTP Flood">
              <SlidersHorizontal size={13} />
              {label}
            </button>
          ) : key === 'botProtection' ? (
            <button className={`feature-chip feature-chip-button ${features[key] ? 'active' : ''}`} key={key} type="button" onClick={onConfigureBot} title="Configure Bot Protect">
              <ShieldCheck size={13} />
              {label}
            </button>
          ) : key === 'geoBlock' ? (
            <button className={`feature-chip feature-chip-button ${features[key] ? 'active' : ''}`} key={key} type="button" onClick={onConfigureGeo} title="Configure Geo Block">
              <Globe2 size={13} />
              {label}
            </button>
          ) : (
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
                  <span className="pill">{ipGroupItemCount(group)} entries</span>
                  {group.itemsExternal && <span className="pill inline">file</span>}
                  <br />
                  {ipGroupPreviewItems(group).map((item) => <span className="code chip" key={item}>{item}</span>)}
                  {ipGroupItemCount(group) > ipGroupPreviewItems(group).length && <span className="muted">+{ipGroupItemCount(group) - ipGroupPreviewItems(group).length} more</span>}
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

function LogsView({
  data,
  filter,
  setFilter,
  clearLogs,
  logsLoading,
  logResult,
  logDomain,
  setLogDomain,
  logPage,
  setLogPage,
  logPageSize,
  setLogPageSize
}) {
  const logs = logResult.logs || [];
  const total = Number(logResult.total || 0);
  const page = Number(logResult.page || logPage || 1);
  const pages = Number(logResult.pages || 1);
  const pageSize = Number(logResult.pageSize || logPageSize || 50);
  const firstRow = total ? ((page - 1) * pageSize) + 1 : 0;
  const lastRow = total ? Math.min(total, (page - 1) * pageSize + logs.length) : 0;
  const domainOptions = Array.from(new Set([
    ...(logResult.domains || []),
    ...data.sites.flatMap((site) => site.hostnames || [])
  ].filter(Boolean))).sort();

  return (
    <section className="table-panel">
      <div className="filters log-filters">
        <div className="panel-heading compact">
          <h2>Access Logs</h2>
          <span className="pill">{formatCompact(total)} entries</span>
          <button className="tool-button danger" onClick={clearLogs}><Trash2 size={18} /> Clear</button>
        </div>
        <div className="log-filter-controls">
          <select
            className="search domain-select"
            value={logDomain}
            onChange={(event) => {
              setLogDomain(event.target.value);
              setLogPage(1);
            }}
          >
            <option value="">All domains</option>
            {domainOptions.map((domain) => <option key={domain} value={domain}>{domain}</option>)}
          </select>
          <input
            className="search"
            value={filter}
            onChange={(event) => {
              setFilter(event.target.value);
              setLogPage(1);
            }}
            placeholder="Filter logs"
          />
          <select
            className="search page-size-select"
            value={logPageSize}
            onChange={(event) => {
              setLogPageSize(Number(event.target.value));
              setLogPage(1);
            }}
          >
            {[25, 50, 100, 200].map((size) => <option key={size} value={size}>{size} / page</option>)}
          </select>
        </div>
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
            {logsLoading ? (
              <tr><td colSpan="8" className="muted">Loading logs...</td></tr>
            ) : logs.length ? logs.map((entry) => (
              <tr key={entry.id}>
                <td><span className={`status ${entry.verdict}`}>{entry.verdict}</span></td>
                <td>{formatTime(entry.at)}<br /><span className="muted">{entry.durationMs} ms</span></td>
                <td>{entry.siteName}<br /><span className="muted">{entry.host}</span></td>
                <td>{entry.method}</td>
                <td className="path-cell">{entry.path}</td>
                <td>
                  {entry.ip}
                  {entry.country && <><br /><span className="muted">{countryLogLabel(entry.country)}</span></>}
                </td>
                <td>{entry.reason}</td>
                <td>{entry.upstreamStatus || entry.statusCode || ''}</td>
              </tr>
            )) : (
              <tr><td colSpan="8" className="muted">No log entries.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="pagination">
        <span className="muted">{firstRow}-{lastRow} of {formatCompact(total)}</span>
        <div className="pagination-actions">
          <button className="tool-button" onClick={() => setLogPage(Math.max(1, page - 1))} disabled={page <= 1 || logsLoading}>
            Previous
          </button>
          <span className="pill">Page {page} / {pages}</span>
          <button className="tool-button" onClick={() => setLogPage(Math.min(pages, page + 1))} disabled={page >= pages || logsLoading}>
            Next
          </button>
        </div>
      </div>
    </section>
  );
}

function SettingsView({ data, setModal, savePanelSettings, saveApplicationDefaults, saveChallengePage, deleteUser, previewNginx, applyNginx, auth, logout }) {
  const panel = data.settings?.panel || {};
  const applicationDefaults = data.settings?.applicationDefaults || {};
  const challengePage = data.settings?.challengePage || {};
  const [panelForm, setPanelForm] = useState(() => ({
    httpsEnabled: String(panel.httpsEnabled ?? false),
    certificateId: panel.certificateId || '',
    publicUrl: panel.publicUrl || '',
    sessionHours: panel.sessionHours || 12
  }));
  const [applicationForm, setApplicationForm] = useState(() => applicationDefaultsFormFromSettings(applicationDefaults));
  const [challengeForm, setChallengeForm] = useState(() => challengePageFormFromSettings(challengePage));

  useEffect(() => {
    setPanelForm({
      httpsEnabled: String(panel.httpsEnabled ?? false),
      certificateId: panel.certificateId || '',
      publicUrl: panel.publicUrl || '',
      sessionHours: panel.sessionHours || 12
    });
  }, [panel.httpsEnabled, panel.certificateId, panel.publicUrl, panel.sessionHours]);

  useEffect(() => {
    setApplicationForm(applicationDefaultsFormFromSettings(applicationDefaults));
  }, [applicationDefaults]);

  useEffect(() => {
    setChallengeForm(challengePageFormFromSettings(challengePage));
  }, [challengePage]);

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

  function updateApplication(name, value) {
    setApplicationForm((current) => ({ ...current, [name]: value }));
  }

  function submitApplicationDefaults(event) {
    event.preventDefault();
    saveApplicationDefaults(applicationDefaultsPayload(applicationForm));
  }

  function updateChallenge(name, value) {
    setChallengeForm((current) => ({ ...current, [name]: value }));
  }

  function submitChallengePage(event) {
    event.preventDefault();
    saveChallengePage(challengePagePayload(challengeForm));
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

      <section className="panel">
        <div className="panel-heading">
          <h2>Transport and Protection</h2>
          <span className="pill">all applications</span>
        </div>
        <form className="settings-form" onSubmit={submitApplicationDefaults}>
          <section className="application-option-section full">
            <div className="application-option-grid">
              <ApplicationOption label="Enable HTTP/2" checked={boolValue(applicationForm.proxyHttp2)} onChange={(value) => updateApplication('proxyHttp2', String(value))} />
              <ApplicationOption label="Redirect HTTP to HTTPS" checked={boolValue(applicationForm.proxyForceHttps)} onChange={(value) => updateApplication('proxyForceHttps', String(value))} />
              <ApplicationOption label="Enable HSTS" checked={boolValue(applicationForm.proxyHsts)} onChange={(value) => updateApplication('proxyHsts', String(value))} />
              <ApplicationOption label="Gzip Compression" checked={boolValue(applicationForm.proxyGzip)} onChange={(value) => updateApplication('proxyGzip', String(value))} />
              <ApplicationOption label="Brotli Compression" checked={boolValue(applicationForm.proxyBrotli)} onChange={(value) => updateApplication('proxyBrotli', String(value))} />
              <ApplicationOption label="Clear and Rewrite X-Forwarded-For" checked={boolValue(applicationForm.proxyResetXff)} onChange={(value) => updateApplication('proxyResetXff', String(value))} />
              <ApplicationOption label="Modify Host Header" checked={boolValue(applicationForm.proxyModifyHostHeader)} onChange={(value) => updateApplication('proxyModifyHostHeader', String(value))} />
              <ApplicationOption label="Pass Forwarded Headers" checked={boolValue(applicationForm.proxyForwardedHeaders)} onChange={(value) => updateApplication('proxyForwardedHeaders', String(value))} />
              <ApplicationOption label="Proxy SSL Server Name" checked={boolValue(applicationForm.proxySslServerName)} onChange={(value) => updateApplication('proxySslServerName', String(value))} />
              <ApplicationOption label="ModSecurity" checked={boolValue(applicationForm.modSecurityEnabled)} onChange={(value) => updateApplication('modSecurityEnabled', String(value))} />
            </div>
            <div className="application-option-inputs">
              {boolValue(applicationForm.modSecurityEnabled) && (
                <>
                  <SelectField
                    label="Rule Set"
                    value={applicationForm.modSecurityRuleset}
                    onChange={(value) => updateApplication('modSecurityRuleset', value)}
                    options={[
                      { value: 'comodo', label: 'Comodo WAF Rules' },
                      { value: 'owasp', label: 'OWASP Core Rule Set' }
                    ]}
                  />
                  <SelectField
                    label="Engine Mode"
                    value={applicationForm.modSecurityMode}
                    onChange={(value) => updateApplication('modSecurityMode', value)}
                    options={[
                      { value: 'on', label: 'Block' },
                      { value: 'detection_only', label: 'Detection Only' }
                    ]}
                  />
                  <TextField label="Request Body Limit (bytes)" value={applicationForm.modSecurityRequestBodyLimit} onChange={(value) => updateApplication('modSecurityRequestBodyLimit', value)} type="number" />
                </>
              )}
              {boolValue(applicationForm.proxyHsts) && (
                <TextField label="HSTS Max Age (seconds)" value={applicationForm.proxyHstsMaxAge} onChange={(value) => updateApplication('proxyHstsMaxAge', value)} type="number" />
              )}
              {boolValue(applicationForm.proxyModifyHostHeader) && (
                <TextField label="Host Header" value={applicationForm.proxyHostHeader} onChange={(value) => updateApplication('proxyHostHeader', value)} placeholder="$http_host" />
              )}
              {boolValue(applicationForm.proxyForwardedHeaders) && (
                <>
                  <TextField label="X-Forwarded-Host" value={applicationForm.proxyXForwardedHost} onChange={(value) => updateApplication('proxyXForwardedHost', value)} placeholder="$http_host" />
                  <TextField label="X-Forwarded-Proto" value={applicationForm.proxyXForwardedProto} onChange={(value) => updateApplication('proxyXForwardedProto', value)} placeholder="$scheme" />
                </>
              )}
            </div>
          </section>
          <div className="settings-actions full">
            <button className="tool-button primary"><Save size={18} /> Save Global Defaults</button>
          </div>
        </form>
      </section>

      <section className="panel">
        <div className="panel-heading">
          <h2>Challenge Page</h2>
          <span className="pill">signed browser token</span>
        </div>
        <form className="challenge-settings-layout" onSubmit={submitChallengePage}>
          <div className="settings-form challenge-settings-form">
            <TextField label="Brand Name" value={challengeForm.brandName} onChange={(value) => updateChallenge('brandName', value)} />
            <TextField label="Title" value={challengeForm.title} onChange={(value) => updateChallenge('title', value)} />
            <TextAreaField label="Message" value={challengeForm.message} onChange={(value) => updateChallenge('message', value)} full />
            <TextField label="Logo URL" value={challengeForm.logoUrl} onChange={(value) => updateChallenge('logoUrl', value)} placeholder="https://example.com/logo.png" full />
            <TextField label="Support URL" value={challengeForm.supportUrl} onChange={(value) => updateChallenge('supportUrl', value)} placeholder="https://example.com/support" full />
            <TextField label="Primary Color" value={challengeForm.primaryColor} onChange={(value) => updateChallenge('primaryColor', value)} type="color" />
            <TextField label="Background Color" value={challengeForm.backgroundColor} onChange={(value) => updateChallenge('backgroundColor', value)} type="color" />
            <TextField label="Text Color" value={challengeForm.textColor} onChange={(value) => updateChallenge('textColor', value)} type="color" />
            <TextField label="Token TTL (minutes)" value={challengeForm.tokenTtlMinutes} onChange={(value) => updateChallenge('tokenTtlMinutes', value)} type="number" />
            <SelectField
              label="Challenge Wait"
              value={String(challengeForm.waitSeconds)}
              onChange={(value) => updateChallenge('waitSeconds', value)}
              options={[
                { value: '3', label: '3 seconds' },
                { value: '5', label: '5 seconds (recommended)' },
                { value: '10', label: '10 seconds' }
              ]}
            />
            <div className="settings-actions full">
              <button className="tool-button primary"><Save size={18} /> Save Challenge Page</button>
            </div>
          </div>
          <ChallengePagePreview form={challengeForm} />
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

function ChallengePagePreview({ form }) {
  const waitSeconds = challengeWaitSeconds(form.waitSeconds);
  const previewStyle = {
    '--challenge-primary': form.primaryColor,
    '--challenge-background': form.backgroundColor,
    '--challenge-text': form.textColor
  };
  return (
    <div className="challenge-preview-wrap">
      <span className="muted">Live preview</span>
      <div className="challenge-preview" style={previewStyle}>
        {form.logoUrl ? (
          <img src={form.logoUrl} alt="" />
        ) : (
          <div className="challenge-preview-mark">{String(form.brandName || 'F').slice(0, 1)}</div>
        )}
        <h3>{form.title || 'Security check'}</h3>
        <p>{form.message || 'We are verifying your browser before continuing.'}</p>
        <strong>Example Application</strong>
        <span className="challenge-preview-loader" />
        <small>Checking browser integrity... {waitSeconds}s</small>
      </div>
    </div>
  );
}

function Timeline({ points = [], compact = false }) {
  const [hovered, setHovered] = useState(null);
  const max = Math.max(1, ...points.map((point) => Number(point.total || 0)));
  return (
    <div className={`chart ${compact ? 'compact' : ''}`} aria-label="Traffic chart" onMouseLeave={() => setHovered(null)}>
      {points.map((point, index) => {
        const total = Number(point.total || 0);
        const protectedCount = Number(point.protected ?? (Number(point.blocked || 0) + Number(point.challenged || 0)));
        const challenged = Number(point.challenged || 0);
        const blocked = Number(point.blocked || 0);
        const height = total ? Math.max(8, Math.round((total / max) * 100)) : 4;
        const protectedHeight = total ? Math.round((protectedCount / total) * 100) : 0;
        const showTick = index % 4 === 0 || index === points.length - 1;
        const tooltipSide = index > points.length - 6 ? 'left' : 'right';
        return (
          <div className="bar-wrap" key={point.at} onMouseEnter={() => setHovered(index)} onFocus={() => setHovered(index)}>
            <span className={`bar-value ${total ? '' : 'zero'}`}>{formatCompact(total)}</span>
            {hovered === index && (
              <div className={`chart-tooltip ${tooltipSide}`}>
                <strong>{formatBucketRange(point)}</strong>
                <span>{formatCompact(total)} requests</span>
                <span>{formatCompact(protectedCount)} protected</span>
                <span>{formatCompact(challenged)} challenged</span>
                <span>{formatCompact(blocked)} blocked</span>
              </div>
            )}
            <div
              tabIndex={0}
              className={`bar ${total ? 'has-data' : ''}`}
              style={{ height: `${height}%` }}
            >
              <span className="bar-protected" style={{ height: `${protectedHeight}%` }} />
            </div>
            <span className="bar-time">{showTick ? point.label : ''}</span>
          </div>
        );
      })}
    </div>
  );
}

function QpsBars({ points = [] }) {
  const displayPoints = padSeries(points, 30, { qps: 0, count: 0 });
  const max = Math.max(1, ...displayPoints.map((point) => Number(point.qps || 0)));

  return (
    <div className="qps-bars" aria-label="Query per second chart">
      {displayPoints.map((point, index) => {
        const qps = Number(point.qps || 0);
        const height = qps ? Math.max(10, Math.round((qps / max) * 100)) : 5;
        const title = `${formatPreciseBucketRange(point)}: ${formatQps(qps)} qps`;
        return (
          <span className="qps-bar-wrap" key={`${point.at || 'empty'}-${index}`} title={title}>
            <span className={`qps-bar ${qps ? 'has-data' : ''}`} style={{ height: `${height}%` }} />
          </span>
        );
      })}
    </div>
  );
}

function RequestsStatusChart({ points = [], valueKey = 'total', tone = 'requests' }) {
  const displayPoints = padSeries(points, 24, { total: 0 });
  const width = 360;
  const height = 166;
  const values = displayPoints.map((point) => Number(point[valueKey] || 0));
  const path = smoothLinePath(values, width, height);
  const areaPath = `${path} L ${width} ${height - 14} L 0 ${height - 14} Z`;

  return (
    <svg className={`request-status-chart ${tone}`} viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Traffic status chart">
      {[28, 60, 92, 124, 152].map((y) => <line key={y} x1="0" y1={y} x2={width} y2={y} />)}
      <path className="request-status-area" d={areaPath} />
      <path className="request-status-line" d={path} />
    </svg>
  );
}

function padSeries(points, count, emptyPoint) {
  const source = Array.isArray(points) ? points.slice(-count) : [];
  const missing = Math.max(0, count - source.length);
  return [
    ...Array.from({ length: missing }, (_, index) => ({ ...emptyPoint, at: `empty-${index}` })),
    ...source
  ];
}

function smoothLinePath(values, width, height) {
  const max = Math.max(1, ...values);
  const bottom = height - 14;
  const top = 16;
  const range = Math.max(1, bottom - top);
  const lastIndex = Math.max(1, values.length - 1);
  const coords = values.map((value, index) => ({
    x: (index / lastIndex) * width,
    y: bottom - (Number(value || 0) / max) * range
  }));

  if (!coords.length) return `M 0 ${bottom} L ${width} ${bottom}`;
  return coords.reduce((path, point, index) => {
    if (index === 0) return `M ${point.x.toFixed(2)} ${point.y.toFixed(2)}`;
    const previous = coords[index - 1];
    const midX = (previous.x + point.x) / 2;
    return `${path} C ${midX.toFixed(2)} ${previous.y.toFixed(2)}, ${midX.toFixed(2)} ${point.y.toFixed(2)}, ${point.x.toFixed(2)} ${point.y.toFixed(2)}`;
  }, '');
}

function InsightRows({ rows = [], empty, maxValue = 1, label, barValue, valueLabel, detailLabel }) {
  if (!rows.length) {
    return <p className="muted">{empty}</p>;
  }
  return (
    <div className="insight-list">
      {rows.map((item) => {
        const value = Number(barValue ? barValue(item) : item.count ?? item.blocked ?? item.protected ?? 0);
        const width = Math.max(4, Math.round((value / maxValue) * 100));
        return (
          <div className="insight-row" key={`${item.code || ''}-${item.name}`}>
            <div className="insight-row-top">
              <strong>{label ? label(item) : item.name}</strong>
              <span>{valueLabel(item)}</span>
            </div>
            <div className="insight-bar"><span style={{ width: `${width}%` }} /></div>
            <div className="insight-detail">{detailLabel(item)}</div>
          </div>
        );
      })}
    </div>
  );
}

function Incident({ entry }) {
  const verdict = entry.verdict || 'block';
  return (
    <article className="incident-item">
      <div className="incident-top">
        <strong>{entry.reason}</strong>
        <span className={`status ${verdict}`}>{verdict}</span>
      </div>
      <div className="incident-path"><span>{entry.method}</span> {entry.path}</div>
      <div className="incident-meta">{entry.ip} / {formatTime(entry.at)}</div>
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

function HttpFloodModal({ site, settings, onClose, onSave }) {
  const [form, setForm] = useState(() => httpFloodFormFromSite(site, settings));
  const [editing, setEditing] = useState('');

  function update(name, value) {
    setForm((current) => ({ ...current, [name]: value }));
  }

  function updateLimit(prefix, name, value) {
    setForm((current) => ({ ...current, [`${prefix}${name}`]: value }));
  }

  function submit(event) {
    event.preventDefault();
    onSave(httpFloodPayload(form));
  }

  function editAccess() {
    setForm((current) => ({ ...current, rateLimitMode: 'custom' }));
    setEditing(editing === 'access' ? '' : 'access');
  }

  const accessDisabled = form.rateLimitMode === 'global';

  return (
    <Modal title="HTTP Flood" onClose={onClose} className="http-flood-modal">
      <form onSubmit={submit} className="http-flood-form">
        <div className="flood-control-row">
          <span className="flood-accent" />
          <strong>Waiting Room</strong>
          <Switch checked={boolValue(form.waitingRoom)} onChange={(checked) => update('waitingRoom', String(checked))} />
          <Info size={16} />
          <span className="muted">Queues excess visitors inside Nginx burst handling instead of sending them immediately.</span>
        </div>

        <div className="flood-control-row">
          <span className="flood-accent" />
          <strong>Rate Limiting</strong>
          <div className="flood-segmented">
            <button type="button" className={form.rateLimitMode === 'global' ? 'active' : ''} onClick={() => update('rateLimitMode', 'global')}>Use Global</button>
            <button type="button" className={form.rateLimitMode === 'custom' ? 'active' : ''} onClick={() => update('rateLimitMode', 'custom')}>Customize</button>
          </div>
          <Info size={16} />
          <span className="muted">Limits traffic by source IP and by IP plus request header fingerprint.</span>
        </div>

        <FloodSection
          title="Access Limiting"
          action={<button type="button" className="tool-button" onClick={editAccess}><Plus size={16} /> Add Rules</button>}
        >
          <FloodLimitCard
            title="Basic Access Limit"
            enabled={boolValue(form.accessEnabled)}
            onToggle={(checked) => updateLimit('access', 'Enabled', String(checked))}
            summary={accessLimitSummary(form, settings)}
            editing={editing === 'access'}
            onEdit={editAccess}
            disabled={accessDisabled}
          >
            <LimitEditFields prefix="access" form={form} updateLimit={updateLimit} />
          </FloodLimitCard>
        </FloodSection>

        <FloodSection title="Attack Limiting">
          <FloodLimitCard
            title="Basic Attack Limit"
            enabled={boolValue(form.attackEnabled)}
            onToggle={(checked) => updateLimit('attack', 'Enabled', String(checked))}
            summary={attackLimitSummary(form)}
            editing={editing === 'attack'}
            onEdit={() => setEditing(editing === 'attack' ? '' : 'attack')}
          >
            <LimitEditFields prefix="attack" form={form} updateLimit={updateLimit} />
          </FloodLimitCard>
        </FloodSection>

        <FloodSection title="Error Limiting">
          <FloodLimitCard
            title="Basic Error Limit"
            enabled={boolValue(form.errorEnabled)}
            onToggle={(checked) => updateLimit('error', 'Enabled', String(checked))}
            summary={errorLimitSummary(form)}
            editing={editing === 'error'}
            onEdit={() => setEditing(editing === 'error' ? '' : 'error')}
          >
            <LimitEditFields prefix="error" form={form} updateLimit={updateLimit} includeStatusCodes />
          </FloodLimitCard>
        </FloodSection>

        <div className="modal-footer">
          <button type="button" className="tool-button" onClick={onClose}>Cancel</button>
          <button className="tool-button primary">Save</button>
        </div>
      </form>
    </Modal>
  );
}

function BotProtectModal({ site, onClose, onSave }) {
  const [form, setForm] = useState(() => botProtectFormFromSite(site));

  function update(name, value) {
    setForm((current) => ({ ...current, [name]: value }));
  }

  function submit(event) {
    event.preventDefault();
    onSave(botProtectPayload(form));
  }

  return (
    <Modal title="BOT Protect" onClose={onClose} className="bot-protect-modal">
      <form onSubmit={submit} className="bot-protect-form">
        <div className="bot-control-row">
          <span className="flood-accent" />
          <strong>Anti-Bot Challenge</strong>
          <Switch checked={boolValue(form.antiBotChallenge)} onChange={(checked) => update('antiBotChallenge', String(checked))} />
          <Info size={16} />
          <span className="muted">Login pages and request spikes are challenged without challenging crawlers by User-Agent.</span>
        </div>

        <div className="bot-option-panel">
          <div className="bot-control-row">
            <span className="flood-accent" />
            <strong>Login pages</strong>
            <Switch checked={boolValue(form.loginChallenge)} onChange={(checked) => update('loginChallenge', String(checked))} />
            <Info size={16} />
            <span className="muted">Paths below will require the browser challenge before the request reaches origin.</span>
          </div>
          <TextAreaField
            label="Login path regex"
            value={form.loginPathPatterns}
            onChange={(value) => update('loginPathPatterns', value)}
            placeholder="^/wp-login\\.php(?:\\?|$)"
            full
          />
        </div>

        <div className="bot-option-panel">
          <div className="bot-control-row">
            <span className="flood-accent" />
            <strong>Traffic rate</strong>
            <Switch checked={boolValue(form.rateChallenge)} onChange={(checked) => update('rateChallenge', String(checked))} />
            <Info size={16} />
            <span className="muted">Count source IP requests in short windows, then challenge first and block harder bursts.</span>
          </div>
          <div className="bot-threshold-grid">
            <SelectField label="Window" value={form.rateWindowSeconds} onChange={(value) => update('rateWindowSeconds', value)} options={botRateWindowOptions} />
            <TextField label="Challenge after" value={form.rateChallengeCount} onChange={(value) => update('rateChallengeCount', value)} type="number" />
            <TextField label="Block after" value={form.rateBlockCount} onChange={(value) => update('rateBlockCount', value)} type="number" />
          </div>
        </div>

        <div className="bot-control-row">
          <span className="flood-accent" />
          <strong>Dynamic Protection</strong>
          <Info size={16} />
          <span className="muted">Marks protected responses and prepares native-safe dynamic protection directives.</span>
        </div>

        <div className="bot-option-panel">
          <BotOptionCheckbox
            label="HTML dynamic encryption"
            checked={boolValue(form.dynamicHtml)}
            onChange={(checked) => update('dynamicHtml', String(checked))}
            badge="Recommend"
          />
          <BotOptionCheckbox
            label="JS dynamic encryption"
            checked={boolValue(form.dynamicJs)}
            onChange={(checked) => update('dynamicJs', String(checked))}
            note="Consumes a lot. Please test it thoroughly"
          />
          <BotOptionCheckbox
            label="Picture dynamic watermark"
            checked={boolValue(form.dynamicWatermark)}
            onChange={(checked) => update('dynamicWatermark', String(checked))}
            note="Consumes a lot. Please test it thoroughly"
          />
        </div>

        <div className="bot-control-row">
          <span className="flood-accent" />
          <strong>Anti-Replay</strong>
          <ShieldCheck size={16} />
          <Switch checked={boolValue(form.antiReplay)} onChange={(checked) => update('antiReplay', String(checked))} />
          <Info size={16} />
          <span className="muted">Repeated captured requests with the same IP, URI, method, and User-Agent are rate limited.</span>
        </div>

        <div className="modal-footer">
          <button type="button" className="tool-button" onClick={onClose}>Cancel</button>
          <button className="tool-button primary">Save</button>
        </div>
      </form>
    </Modal>
  );
}

function BotOptionCheckbox({ label, checked, onChange, badge = '', note = '' }) {
  return (
    <label className="bot-option-checkbox">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <span>{label}</span>
      {badge && <b>{badge}</b>}
      {note && <small>{note}</small>}
    </label>
  );
}

function GeoBlockModal({ site, onClose, onSave }) {
  const [form, setForm] = useState(() => geoBlockFormFromSite(site));
  const selected = new Set(normalizeCountryCodes(form.countries));

  function update(name, value) {
    setForm((current) => ({ ...current, [name]: value }));
  }

  function toggleCountry(code) {
    const next = new Set(normalizeCountryCodes(form.countries));
    if (next.has(code)) {
      next.delete(code);
    } else {
      next.add(code);
    }
    update('countries', Array.from(next).join(', '));
  }

  function submit(event) {
    event.preventDefault();
    onSave(geoBlockPayload(form));
  }

  return (
    <Modal title="GEO Block" onClose={onClose} className="geo-block-modal">
      <form onSubmit={submit} className="geo-block-form">
        <div className="bot-control-row">
          <span className="flood-accent" />
          <strong>Geo Block</strong>
          <Switch checked={boolValue(form.enabled)} onChange={(checked) => update('enabled', String(checked))} />
          <Info size={16} />
          <span className="muted">Traffic from selected countries is handled before proxying to the origin.</span>
        </div>

        <div className="form-grid">
          <SelectField label="Action" value={form.action} onChange={(value) => update('action', value)} options={geoBlockActionOptions} />
          <TextAreaField label="Countries" value={form.countries} onChange={(value) => update('countries', value)} placeholder="US, CN, RU" full />
        </div>

        <div className="country-picker">
          {geoQuickCountries.map((country) => (
            <button
              key={country.code}
              type="button"
              className={selected.has(country.code) ? 'active' : ''}
              onClick={() => toggleCountry(country.code)}
            >
              <span>{country.code}</span>
              {country.name}
            </button>
          ))}
        </div>

        <div className="modal-footer">
          <button type="button" className="tool-button" onClick={onClose}>Cancel</button>
          <button className="tool-button primary">Save</button>
        </div>
      </form>
    </Modal>
  );
}

function FloodSection({ title, action, children }) {
  return (
    <section className="flood-section">
      <div className="flood-section-heading">
        <h3>{title}</h3>
        {action}
      </div>
      {children}
    </section>
  );
}

function FloodLimitCard({ title, enabled, onToggle, summary, editing, onEdit, disabled = false, children }) {
  return (
    <article className={`flood-limit-card ${disabled ? 'disabled' : ''}`}>
      <Switch checked={enabled} onChange={onToggle} />
      <div className="flood-limit-content">
        <div className="flood-limit-top">
          <strong>{title}</strong>
          <button type="button" className="link-button" onClick={onEdit}>{disabled ? 'Customize' : 'Edit'}</button>
        </div>
        <p>{summary}</p>
        {editing && <div className="flood-edit-grid">{children}</div>}
      </div>
    </article>
  );
}

function LimitEditFields({ prefix, form, updateLimit, includeStatusCodes = false }) {
  return (
    <>
      <TextField label="Requests" value={form[`${prefix}Count`]} onChange={(value) => updateLimit(prefix, 'Count', value)} type="number" />
      <TextField label="Within seconds" value={form[`${prefix}Period`]} onChange={(value) => updateLimit(prefix, 'Period', value)} type="number" />
      <SelectField label="Action" value={form[`${prefix}Action`]} onChange={(value) => updateLimit(prefix, 'Action', value)} options={floodActionOptions} />
      <TextField label="Block minutes" value={form[`${prefix}BlockMin`]} onChange={(value) => updateLimit(prefix, 'BlockMin', value)} type="number" />
      {includeStatusCodes && (
        <TextField label="Status codes" value={form.errorStatusCodes} onChange={(value) => updateLimit('error', 'StatusCodes', value)} placeholder="403, 404" full />
      )}
    </>
  );
}

function SiteModal({ site, certificates, onClose, onSave }) {
  const [submitting, setSubmitting] = useState(false);
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
    proxyHsts: String(site?.proxy?.hsts ?? false),
    proxyHstsMaxAge: String(site?.proxy?.hstsMaxAge ?? defaultSite.proxyHstsMaxAge),
    proxyGzip: String(site?.proxy?.gzip ?? true),
    proxyBrotli: String(site?.proxy?.brotli ?? false),
    proxyResetXff: String(site?.proxy?.resetXff ?? true),
    proxyModifyHostHeader: String(site?.proxy?.modifyHostHeader ?? true),
    proxyForwardedHeaders: String(site?.proxy?.forwardedHeaders ?? true),
    proxyHostHeader: site?.proxy?.hostHeader || defaultSite.proxyHostHeader,
    proxyXForwardedProto: site?.proxy?.xForwardedProto || defaultSite.proxyXForwardedProto,
    proxyXForwardedHost: site?.proxy?.xForwardedHost || defaultSite.proxyXForwardedHost,
    proxySslServerName: String(site?.proxy?.proxySslServerName ?? true),
    modSecurityEnabled: String(site?.modSecurity?.enabled ?? true),
    modSecurityMode: site?.modSecurity?.mode || defaultSite.modSecurityMode,
    modSecurityRuleset: site?.modSecurity?.ruleset || defaultSite.modSecurityRuleset,
    modSecurityRequestBodyLimit: String(site?.modSecurity?.requestBodyLimit ?? defaultSite.modSecurityRequestBodyLimit),
    aclEnabled: String(site?.acl?.enabled ?? true),
    aclRateLimitMode: site?.acl?.rateLimitMode || defaultSite.aclRateLimitMode,
    aclWaitingRoom: String(site?.acl?.waitingRoom ?? false),
    aclAccessEnabled: String(site?.acl?.accessLimit?.enabled ?? true),
    aclAccessPeriod: String(site?.acl?.accessLimit?.period ?? defaultSite.aclAccessPeriod),
    aclAccessCount: String(site?.acl?.accessLimit?.count ?? defaultSite.aclAccessCount),
    aclAccessAction: site?.acl?.accessLimit?.action || defaultSite.aclAccessAction,
    aclAccessBlockMin: String(site?.acl?.accessLimit?.blockMin ?? defaultSite.aclAccessBlockMin),
    aclAttackEnabled: String(site?.acl?.attackLimit?.enabled ?? true),
    aclAttackPeriod: String(site?.acl?.attackLimit?.period ?? defaultSite.aclAttackPeriod),
    aclAttackCount: String(site?.acl?.attackLimit?.count ?? defaultSite.aclAttackCount),
    aclAttackAction: site?.acl?.attackLimit?.action || defaultSite.aclAttackAction,
    aclAttackBlockMin: String(site?.acl?.attackLimit?.blockMin ?? defaultSite.aclAttackBlockMin),
    aclErrorEnabled: String(site?.acl?.errorLimit?.enabled ?? true),
    aclErrorPeriod: String(site?.acl?.errorLimit?.period ?? defaultSite.aclErrorPeriod),
    aclErrorCount: String(site?.acl?.errorLimit?.count ?? defaultSite.aclErrorCount),
    aclErrorAction: site?.acl?.errorLimit?.action || defaultSite.aclErrorAction,
    aclErrorBlockMin: String(site?.acl?.errorLimit?.blockMin ?? defaultSite.aclErrorBlockMin),
    aclErrorStatusCodes: textFromList(site?.acl?.errorLimit?.statusCodes || defaultSite.aclErrorStatusCodes).replace(/\n/g, ', '),
    featureHttpFlood: String(site?.features?.httpFlood ?? true),
    featureBotProtection: String(site?.features?.botProtection ?? true),
    featureGeoBlock: String(site?.features?.geoBlock ?? false),
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

  async function submit(event) {
    event.preventDefault();
    if (submitting) return;
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
    setSubmitting(true);
    try {
      await onSave({
        ...form,
        tlsEnabled: String(hasHttpsPort || boolValue(form.tlsEnabled)),
        redirectHttp: String(hasHttpsPort && form.listeningPorts.some((row) => row.protocol === 'http') && boolValue(form.proxyForceHttps)),
        hostnames: hostnames.join('\n'),
        upstreams: form.upstreams,
        listeningPorts: form.listeningPorts
      });
    } finally {
      setSubmitting(false);
    }
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
            <>
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
            </>
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
          <button type="button" className="tool-button" onClick={onClose} disabled={submitting}>Cancel</button>
          <button className="tool-button primary" disabled={submitting}>
            {submitting && <Loader2 size={17} className="spin" />}
            {submitting ? 'Saving...' : 'Submit'}
          </button>
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

function ApplicationOption({ label, checked, onChange }) {
  return (
    <div className="application-option">
      <span>{label}</span>
      <Switch checked={checked} onChange={onChange} />
    </div>
  );
}

function CertificateModal({ certificate, onClose, onSave }) {
  const [submitting, setSubmitting] = useState(false);
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

  async function submit(event) {
    event.preventDefault();
    if (submitting) return;
    const domains = listFromText(form.domains, /[\s,]+/);
    if (!domains.length) {
      window.alert('Enter at least one certificate domain.');
      return;
    }
    if (form.source === 'upload' && Boolean(form.certificate.trim()) !== Boolean(form.privateKey.trim())) {
      window.alert('Paste both certificate and private key PEM.');
      return;
    }
    setSubmitting(true);
    try {
      await onSave({
        ...form,
        name: form.name || domains[0],
        domains: domains.join('\n')
      });
    } finally {
      setSubmitting(false);
    }
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
          <button type="button" className="tool-button cert-cancel" onClick={onClose} disabled={submitting}>Cancel</button>
          <button className="tool-button primary cert-submit" disabled={submitting}>
            {submitting && <Loader2 size={17} className="spin" />}
            {submitting ? (form.source === 'certbot' ? 'Issuing...' : 'Saving...') : 'Submit'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function IpGroupModal({ group, onClose, onSave }) {
  const fileInputRef = useRef(null);
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

  async function importTextFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    setForm((current) => ({
      ...current,
      items: [current.items, text].filter(Boolean).join(current.items ? '\n' : '')
    }));
    event.target.value = '';
  }

  return (
    <Modal title={group ? 'Edit IP Group' : 'Add IP Group'} onClose={onClose}>
      <form onSubmit={(event) => { event.preventDefault(); onSave(form); }}>
        <div className="form-grid">
          <TextField label="Name" value={form.name} onChange={(value) => update('name', value)} full required />
          <TextField label="Reference" value={form.referenceUrl} onChange={(value) => update('referenceUrl', value)} placeholder="http://example.com/ip-list.txt" full />
          <div className="ip-import-actions full">
            <button type="button" className="outline-action" onClick={() => fileInputRef.current?.click()}>
              <Upload size={16} /> Import .txt
            </button>
            <span className="form-note">Supports IP/CIDR lists with spaces, commas, semicolons, and # comments.</span>
            <input ref={fileInputRef} className="hidden-file-input" type="file" accept=".txt,text/plain" onChange={importTextFile} />
          </div>
          <TextAreaField label="Content" value={form.items} onChange={(value) => update('items', value)} placeholder="192.0.2.10/32" />
          <SelectField label="Enabled" value={form.enabled} onChange={(value) => update('enabled', value)} options={['true', 'false']} />
          <TextAreaField label="Description" value={form.description} onChange={(value) => update('description', value)} />
          {form.itemsExternal && !String(form.items || '').trim() && (
            <p className="form-note full">This large IP group is stored on disk. Leave Content empty to keep the current file, or import/paste new content to replace it.</p>
          )}
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

function TextAreaField({ label, value, onChange, placeholder = '', full = false }) {
  return (
    <label className={`field ${full ? 'full' : ''}`}>
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

function formatBucketRange(point) {
  const start = new Date(Number(point?.at || 0));
  const end = new Date(Number(point?.endAt || Number(point?.at || 0) + 5 * 60 * 1000));
  const date = start.toLocaleDateString([], { year: 'numeric', month: 'short', day: '2-digit' });
  const startTime = start.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const endTime = end.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  return `${date} ${startTime} - ${endTime}`;
}

function formatPreciseBucketRange(point) {
  if (!point?.at || String(point.at).startsWith('empty-')) return 'Waiting for data';
  const start = new Date(Number(point.at));
  const end = new Date(Number(point.endAt || Number(point.at) + 10 * 1000));
  const startTime = start.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const endTime = end.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  return `${startTime} - ${endTime}`;
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

function ipGroupItemCount(group) {
  return Number(group?.itemCount ?? group?.items?.length ?? 0);
}

function ipGroupPreviewItems(group) {
  const preview = Array.isArray(group?.itemsPreview) && group.itemsPreview.length ? group.itemsPreview : group?.items || [];
  return preview.slice(0, 8);
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

function httpFloodFormFromSite(site, settings) {
  const acl = site?.acl || {};
  const access = acl.accessLimit || {};
  const attack = acl.attackLimit || {};
  const error = acl.errorLimit || {};
  const global = globalRateLimit(settings);
  return {
    rateLimitMode: acl.rateLimitMode || 'custom',
    waitingRoom: String(acl.waitingRoom ?? false),
    accessEnabled: String(access.enabled ?? true),
    accessPeriod: String(access.period ?? global.period),
    accessCount: String(access.count ?? global.count),
    accessAction: access.action || 'challenge_v1',
    accessBlockMin: String(access.blockMin ?? 60),
    attackEnabled: String(attack.enabled ?? true),
    attackPeriod: String(attack.period ?? 60),
    attackCount: String(attack.count ?? 10),
    attackAction: attack.action || 'block',
    attackBlockMin: String(attack.blockMin ?? 30),
    errorEnabled: String(error.enabled ?? true),
    errorPeriod: String(error.period ?? 10),
    errorCount: String(error.count ?? 10),
    errorAction: error.action || 'block',
    errorBlockMin: String(error.blockMin ?? 30),
    errorStatusCodes: textFromList(error.statusCodes || ['403', '404']).replace(/\n/g, ', ')
  };
}

function httpFloodPayload(form) {
  return {
    rateLimitMode: form.rateLimitMode === 'global' ? 'global' : 'custom',
    waitingRoom: boolValue(form.waitingRoom),
    accessLimit: floodLimitPayload(form, 'access'),
    attackLimit: floodLimitPayload(form, 'attack'),
    errorLimit: {
      ...floodLimitPayload(form, 'error'),
      statusCodes: listFromText(form.errorStatusCodes, /[\s,]+/)
    }
  };
}

function floodLimitPayload(form, prefix) {
  return {
    enabled: boolValue(form[`${prefix}Enabled`]),
    period: positiveInt(form[`${prefix}Period`], prefix === 'attack' ? 60 : 10),
    count: positiveInt(form[`${prefix}Count`], prefix === 'access' ? 200 : 10),
    action: form[`${prefix}Action`] || (prefix === 'access' ? 'challenge_v1' : 'block'),
    blockMin: positiveInt(form[`${prefix}BlockMin`], prefix === 'access' ? 60 : 30)
  };
}

function globalRateLimit(settings) {
  const rate = settings?.rateLimit || {};
  return {
    enabled: rate.enabled !== false,
    count: positiveInt(rate.max, 120),
    period: Math.max(1, Math.round(positiveInt(rate.windowMs, 60000) / 1000))
  };
}

function positiveInt(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? Math.round(number) : fallback;
}

function accessLimitSummary(form, settings) {
  if (!boolValue(form.accessEnabled)) return 'Disabled.';
  if (form.rateLimitMode === 'global') {
    const global = globalRateLimit(settings);
    return `An IP follows the global policy: ${global.count} requests within ${global.period} seconds.`;
  }
  return `An IP that makes ${positiveInt(form.accessCount, 200)} requests within ${positiveInt(form.accessPeriod, 10)} seconds will ${floodActionPhrase(form.accessAction, form.accessBlockMin)}.`;
}

function attackLimitSummary(form) {
  if (!boolValue(form.attackEnabled)) return 'Disabled.';
  return `An IP that triggers attack blocking ${positiveInt(form.attackCount, 10)} times within ${positiveInt(form.attackPeriod, 60)} seconds will ${floodActionPhrase(form.attackAction, form.attackBlockMin)}.`;
}

function errorLimitSummary(form) {
  if (!boolValue(form.errorEnabled)) return 'Disabled.';
  const codes = listFromText(form.errorStatusCodes, /[\s,]+/).join(', ') || '403, 404';
  return `An IP that triggers ${codes} errors ${positiveInt(form.errorCount, 10)} times within ${positiveInt(form.errorPeriod, 10)} seconds will ${floodActionPhrase(form.errorAction, form.errorBlockMin)}.`;
}

function applicationDefaultsFormFromSettings(applicationDefaults) {
  const proxy = applicationDefaults?.proxy || {};
  const modSecurity = applicationDefaults?.modSecurity || {};
  return {
    ...defaultApplicationDefaults,
    proxyForceHttps: String(proxy.forceHttps ?? false),
    proxyHsts: String(proxy.hsts ?? false),
    proxyHstsMaxAge: String(proxy.hstsMaxAge ?? 15768000),
    proxyGzip: String(proxy.gzip ?? true),
    proxyBrotli: String(proxy.brotli ?? false),
    proxyHttp2: String(proxy.http2 ?? true),
    proxyResetXff: String(proxy.resetXff ?? true),
    proxyModifyHostHeader: String(proxy.modifyHostHeader ?? true),
    proxyForwardedHeaders: String(proxy.forwardedHeaders ?? true),
    proxyHostHeader: proxy.hostHeader || '$http_host',
    proxyXForwardedHost: proxy.xForwardedHost || '$http_host',
    proxyXForwardedProto: proxy.xForwardedProto || '$scheme',
    proxySslServerName: String(proxy.proxySslServerName ?? true),
    modSecurityEnabled: String(modSecurity.enabled ?? true),
    modSecurityMode: modSecurity.mode === 'detection_only' ? 'detection_only' : 'on',
    modSecurityRuleset: modSecurity.ruleset === 'owasp' ? 'owasp' : 'comodo',
    modSecurityRequestBodyLimit: String(modSecurity.requestBodyLimit ?? 13107200)
  };
}

function applicationDefaultsPayload(form) {
  return {
    proxy: {
      forceHttps: boolValue(form.proxyForceHttps),
      hsts: boolValue(form.proxyHsts),
      hstsMaxAge: positiveInt(form.proxyHstsMaxAge, 15768000),
      gzip: boolValue(form.proxyGzip),
      brotli: boolValue(form.proxyBrotli),
      http2: boolValue(form.proxyHttp2),
      resetXff: boolValue(form.proxyResetXff),
      modifyHostHeader: boolValue(form.proxyModifyHostHeader),
      forwardedHeaders: boolValue(form.proxyForwardedHeaders),
      hostHeader: form.proxyHostHeader || '$http_host',
      xForwardedHost: form.proxyXForwardedHost || '$http_host',
      xForwardedProto: form.proxyXForwardedProto || '$scheme',
      proxySslServerName: boolValue(form.proxySslServerName)
    },
    modSecurity: {
      enabled: boolValue(form.modSecurityEnabled),
      mode: form.modSecurityMode === 'detection_only' ? 'detection_only' : 'on',
      ruleset: form.modSecurityRuleset === 'owasp' ? 'owasp' : 'comodo',
      requestBodyLimit: positiveInt(form.modSecurityRequestBodyLimit, 13107200)
    }
  };
}

function challengePageFormFromSettings(challengePage) {
  return {
    ...defaultChallengePage,
    ...(challengePage || {}),
    tokenTtlMinutes: String(challengePage?.tokenTtlMinutes ?? defaultChallengePage.tokenTtlMinutes),
    waitSeconds: String(challengePage?.waitSeconds ?? defaultChallengePage.waitSeconds)
  };
}

function challengePagePayload(form) {
  return {
    brandName: form.brandName,
    title: form.title,
    message: form.message,
    logoUrl: form.logoUrl,
    supportUrl: form.supportUrl,
    primaryColor: form.primaryColor,
    backgroundColor: form.backgroundColor,
    textColor: form.textColor,
    tokenTtlMinutes: positiveInt(form.tokenTtlMinutes, 30),
    waitSeconds: challengeWaitSeconds(form.waitSeconds)
  };
}

function challengeWaitSeconds(value) {
  const seconds = positiveInt(value, 5);
  return [3, 5, 10].includes(seconds) ? seconds : 5;
}

function floodActionPhrase(action, blockMin) {
  const minutes = positiveInt(blockMin, 30);
  if (action === 'challenge_v1') return `require Anti-Bot challenge when accessing again within the next ${minutes} minutes`;
  if (action === 'monitor') return 'be monitored without blocking';
  return `be automatically blocked ${minutes} minutes`;
}

function botProtectFormFromSite(site) {
  const config = botProtectPayloadFromConfig(site?.botProtection, site?.features?.botProtection !== false);
  return {
    antiBotChallenge: String(config.antiBotChallenge),
    loginChallenge: String(config.loginChallenge.enabled),
    loginPathPatterns: textFromList(config.loginChallenge.pathPatterns),
    rateChallenge: String(config.rateChallenge.enabled),
    rateWindowSeconds: String(config.rateChallenge.windowSeconds),
    rateChallengeCount: String(config.rateChallenge.challengeCount),
    rateBlockCount: String(config.rateChallenge.blockCount),
    dynamicHtml: String(config.dynamicProtection.html),
    dynamicJs: String(config.dynamicProtection.js),
    dynamicWatermark: String(config.dynamicProtection.watermark),
    antiReplay: String(config.antiReplay.enabled)
  };
}

function botProtectPayload(form) {
  const antiBotChallenge = boolValue(form.antiBotChallenge);
  const loginChallenge = antiBotChallenge && boolValue(form.loginChallenge);
  const rateChallenge = antiBotChallenge && boolValue(form.rateChallenge);
  const dynamicHtml = boolValue(form.dynamicHtml);
  const dynamicJs = boolValue(form.dynamicJs);
  const dynamicWatermark = boolValue(form.dynamicWatermark);
  const antiReplay = boolValue(form.antiReplay);
  const dynamicEnabled = dynamicHtml || dynamicJs || dynamicWatermark;
  const challengeCount = positiveInt(form.rateChallengeCount, defaultBotRateChallenge.challengeCount);
  const blockCount = Math.max(challengeCount + 1, positiveInt(form.rateBlockCount, defaultBotRateChallenge.blockCount));
  return {
    enabled: antiBotChallenge || dynamicEnabled || antiReplay,
    antiBotChallenge,
    loginChallenge: {
      enabled: loginChallenge,
      pathPatterns: listFromText(form.loginPathPatterns, /\n+/)
    },
    rateChallenge: {
      enabled: rateChallenge,
      windowSeconds: positiveInt(form.rateWindowSeconds, defaultBotRateChallenge.windowSeconds),
      challengeCount,
      blockCount
    },
    dynamicProtection: {
      enabled: dynamicEnabled,
      html: dynamicHtml,
      js: dynamicJs,
      watermark: dynamicWatermark
    },
    antiReplay: {
      enabled: antiReplay
    }
  };
}

function botProtectPayloadFromConfig(config, enabledFallback = true) {
  const source = config || {};
  const dynamic = source.dynamicProtection || {};
  const replay = source.antiReplay || {};
  const login = source.loginChallenge || {};
  const rate = source.rateChallenge || {};
  const antiBotChallenge = source.antiBotChallenge ?? enabledFallback;
  const loginPatterns = Array.isArray(login.pathPatterns) ? login.pathPatterns : defaultBotLoginPathPatterns;
  const loginEnabled = Boolean(antiBotChallenge) && Boolean(login.enabled ?? true) && loginPatterns.length > 0;
  const challengeCount = positiveInt(rate.challengeCount, defaultBotRateChallenge.challengeCount);
  const blockCount = Math.max(challengeCount + 1, positiveInt(rate.blockCount, defaultBotRateChallenge.blockCount));
  const rateChallenge = {
    enabled: Boolean(antiBotChallenge) && Boolean(rate.enabled ?? true),
    windowSeconds: positiveInt(rate.windowSeconds, defaultBotRateChallenge.windowSeconds),
    challengeCount,
    blockCount
  };
  const html = Boolean(dynamic.html);
  const js = Boolean(dynamic.js);
  const watermark = Boolean(dynamic.watermark);
  const antiReplay = Boolean(replay.enabled);
  const dynamicEnabled = Boolean(dynamic.enabled) && (html || js || watermark);
  const enabled = source.enabled ?? (enabledFallback && (antiBotChallenge || dynamicEnabled || antiReplay));
  return {
    enabled: Boolean(enabled),
    antiBotChallenge: Boolean(antiBotChallenge),
    loginChallenge: {
      enabled: loginEnabled,
      pathPatterns: loginPatterns
    },
    rateChallenge,
    dynamicProtection: {
      enabled: dynamicEnabled,
      html,
      js,
      watermark
    },
    antiReplay: {
      enabled: antiReplay
    }
  };
}

function geoBlockFormFromSite(site) {
  const config = geoBlockPayloadFromConfig(site?.geoBlock, site?.features?.geoBlock === true);
  return {
    enabled: String(config.enabled),
    countries: config.countries.join(', '),
    action: config.action
  };
}

function geoBlockPayload(form) {
  const countries = normalizeCountryCodes(form.countries);
  return {
    enabled: boolValue(form.enabled) && countries.length > 0,
    countries,
    action: form.action === 'monitor' ? 'monitor' : 'block'
  };
}

function geoBlockPayloadFromConfig(config, enabledFallback = false) {
  const countries = normalizeCountryCodes(config?.countries || []);
  return {
    enabled: Boolean(config?.enabled ?? enabledFallback) && countries.length > 0,
    countries,
    action: config?.action === 'monitor' ? 'monitor' : 'block'
  };
}

function normalizeCountryCodes(value) {
  return Array.from(new Set(listFromText(value, /[\s,]+/)
    .map((item) => item.toUpperCase())
    .filter((item) => /^[A-Z]{2}$/.test(item))));
}

function normalizedSiteFeatures(site) {
  const features = site?.features || {};
  return {
    httpFlood: features.httpFlood !== false,
    botProtection: features.botProtection !== false,
    geoBlock: features.geoBlock === true,
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

function formatCompact(value) {
  const number = Number(value || 0);
  if (number >= 1000000) return `${(number / 1000000).toFixed(1)}m`;
  if (number >= 1000) return `${(number / 1000).toFixed(1)}k`;
  return String(number);
}

function formatQps(value) {
  const number = Number(value || 0);
  if (number >= 1000) return formatCompact(number);
  if (number >= 10 || Number.isInteger(number)) return String(Math.round(number));
  return number.toFixed(1);
}

function countryDisplayName(country) {
  const code = String(country?.code || '').toUpperCase();
  if (code === 'ZZ') return 'Unknown';
  if (code === 'LO') return 'Local Network';
  if (code.length === 2 && typeof Intl !== 'undefined' && Intl.DisplayNames) {
    try {
      const display = new Intl.DisplayNames(['en'], { type: 'region' }).of(code);
      if (display) return display;
    } catch {
      // Fall back to the backend label below.
    }
  }
  return country?.name || code || 'Unknown';
}

function countryLogLabel(country) {
  const name = countryDisplayName(country);
  const code = String(country?.code || '').toUpperCase();
  return code && !['ZZ', 'LO'].includes(code) ? `${name} (${code})` : name;
}
