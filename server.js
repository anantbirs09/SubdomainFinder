const express = require('express');
const dns = require('dns').promises;
const http = require('http');
const https = require('https');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// List of common subdomains for dictionary brute-forcing
const COMMON_SUBDOMAINS = [
  'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp',
  'secure', 'vpn', 'api', 'dev', 'stage', 'staging', 'status', 'admin', 'portal',
  'm', 'support', 'shop', 'test', 'demo', 'direct', 'dns', 'mx', 'cloud', 'app',
  'git', 'gitlab', 'jenkins', 'jira', 'wiki', 'docs', 'cpanel', 'whm', 'web',
  'email', 'stats', 'ads', 'localhost', 'autodiscover', 'sip', 'imap', 'pop',
  'assets', 'static', 'media', 'images', 'cdn', 'register', 'signup', 'login',
  'signin', 'oauth', 'auth', 'payment', 'billing', 'invoice', 'dashboard',
  'internal', 'corp', 'intranet', 'careers', 'jobs', 'help', 'helpdesk', 'prod',
  'sandbox', 'test-api', 'beta', 'client', 'manage', 'partner', 'db', 'database'
];

// Helper to fetch with timeout
async function fetchWithTimeout(url, options = {}, timeout = 6000) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    throw error;
  }
}

// 1. Passive scan: crt.sh (Certificate Transparency Logs)
async function scanCrtSh(domain) {
  const subdomains = new Set();
  try {
    const response = await fetchWithTimeout(`https://crt.sh/?q=%.${domain}&output=json`, {}, 8000);
    if (response.ok) {
      const data = await response.json();
      if (Array.isArray(data)) {
        data.forEach(item => {
          // crt.sh names can be wildcard (*.domain.com) or have multiple names separated by newlines
          const nameValue = item.name_value || '';
          nameValue.split('\n').forEach(val => {
            const cleanVal = val.replace(/^\*\./, '').trim().toLowerCase();
            if (cleanVal.endsWith(`.${domain}`) && cleanVal !== domain) {
              subdomains.add(cleanVal);
            }
          });
        });
      }
    }
  } catch (err) {
    console.error(`crt.sh scan error: ${err.message}`);
  }
  return Array.from(subdomains);
}

// 2. Passive scan: AlienVault OTX
async function scanAlienVault(domain) {
  const subdomains = new Set();
  try {
    const response = await fetchWithTimeout(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`, {}, 6000);
    if (response.ok) {
      const data = await response.json();
      if (data && Array.isArray(data.passive_dns)) {
        data.passive_dns.forEach(item => {
          const hostname = (item.hostname || '').trim().toLowerCase();
          if (hostname.endsWith(`.${domain}`) && hostname !== domain) {
            subdomains.add(hostname);
          }
        });
      }
    }
  } catch (err) {
    console.error(`AlienVault scan error: ${err.message}`);
  }
  return Array.from(subdomains);
}

// 3. Passive scan: HackerTarget
async function scanHackerTarget(domain) {
  const subdomains = new Set();
  try {
    const response = await fetchWithTimeout(`https://api.hackertarget.com/hostsearch/?q=${domain}`, {}, 6000);
    if (response.ok) {
      const text = await response.text();
      if (text && !text.includes('API count exceeded')) {
        text.split('\n').forEach(line => {
          const parts = line.split(',');
          if (parts[0]) {
            const host = parts[0].trim().toLowerCase();
            if (host.endsWith(`.${domain}`) && host !== domain) {
              subdomains.add(host);
            }
          }
        });
      }
    }
  } catch (err) {
    console.error(`HackerTarget scan error: ${err.message}`);
  }
  return Array.from(subdomains);
}

// Active verification helper: Resolve DNS
async function resolveDNS(subdomain) {
  try {
    const ips = await dns.resolve4(subdomain);
    return ips[0] || null;
  } catch (err) {
    try {
      // Fallback to dns.lookup if resolve4 fails (e.g. CNAME only)
      const lookupResult = await dns.lookup(subdomain);
      return lookupResult.address || null;
    } catch {
      return null;
    }
  }
}

// Active verification helper: Check HTTP/HTTPS response
function checkWebLive(subdomain, timeoutMs = 4000) {
  return new Promise((resolve) => {
    let resolved = false;

    const done = (result) => {
      if (resolved) return;
      resolved = true;
      resolve(result);
    };

    // Try HTTPS first (preferred), fallback to HTTP if fails
    const tryProtocol = (protocol) => {
      const lib = protocol === 'https:' ? https : http;
      const url = `${protocol}//${subdomain}`;
      
      const req = lib.get(url, {
        timeout: timeoutMs,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) SubdomainFinder/1.0'
        }
      }, (res) => {
        let body = '';
        res.on('data', (chunk) => {
          if (body.length < 2000) body += chunk; // only grab first 2kb for title parsing
        });

        res.on('end', () => {
          let title = '';
          const match = body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
          if (match && match[1]) {
            title = match[1].trim()
              .replace(/\s+/g, ' ')
              .substring(0, 80); // limit title length
          }

          done({
            live: true,
            protocol: protocol.replace(':', ''),
            status: res.statusCode,
            title: title || 'N/A',
            server: res.headers['server'] || 'N/A'
          });
        });
      });

      req.on('error', () => {
        // If HTTPS fails, try HTTP (only if HTTPS was the one that failed)
        if (protocol === 'https:') {
          tryProtocol('http:');
        } else {
          done({ live: false });
        }
      });

      req.on('timeout', () => {
        req.destroy();
        if (protocol === 'https:') {
          tryProtocol('http:');
        } else {
          done({ live: false });
        }
      });
    };

    tryProtocol('https:');
  });
}

// SSE Scan Endpoint
app.get('/api/scan', async (req, res) => {
  const domainInput = req.query.domain;
  if (!domainInput) {
    return res.status(400).json({ error: 'Domain parameter is required' });
  }

  const domain = domainInput.trim().toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '');

  // Setup Server-Sent Events headers
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });

  const sendEvent = (event, data) => {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  };

  sendEvent('info', { message: `Initializing search for domain: ${domain}` });

  // Map to store discovered subdomains and the sources they were found in
  const discoveredMap = new Map();

  const addDiscovered = (list, sourceName) => {
    list.forEach(sub => {
      if (!discoveredMap.has(sub)) {
        discoveredMap.set(sub, new Set());
      }
      discoveredMap.get(sub).add(sourceName);
    });
  };

  try {
    // 1. Fetch Passive Data from APIs
    sendEvent('info', { message: 'Fetching Certificate Transparency logs (crt.sh)...' });
    const crtSubdomains = await scanCrtSh(domain);
    addDiscovered(crtSubdomains, 'crt.sh');
    sendEvent('source_found', { source: 'crt.sh', count: crtSubdomains.length });

    sendEvent('info', { message: 'Fetching AlienVault passive DNS data...' });
    const avSubdomains = await scanAlienVault(domain);
    addDiscovered(avSubdomains, 'AlienVault OTX');
    sendEvent('source_found', { source: 'AlienVault OTX', count: avSubdomains.length });

    sendEvent('info', { message: 'Fetching HackerTarget host search records...' });
    const htSubdomains = await scanHackerTarget(domain);
    addDiscovered(htSubdomains, 'HackerTarget');
    sendEvent('source_found', { source: 'HackerTarget', count: htSubdomains.length });

    // 2. Active Dictionary Brute-Forcing (Checking standard list)
    sendEvent('info', { message: 'Running DNS dictionary brute-force for common names...' });
    const bruteList = COMMON_SUBDOMAINS.map(sub => `${sub}.${domain}`);
    
    // Resolve bruteList DNS records in parallel batches to find active subdomains
    const bruteBatchSize = 20;
    const activeBruteFound = [];
    for (let i = 0; i < bruteList.length; i += bruteBatchSize) {
      const batch = bruteList.slice(i, i + bruteBatchSize);
      const results = await Promise.all(batch.map(async (sub) => {
        const ip = await resolveDNS(sub);
        return ip ? { subdomain: sub, ip } : null;
      }));
      
      results.forEach(res => {
        if (res) {
          activeBruteFound.push(res.subdomain);
        }
      });
    }
    
    addDiscovered(activeBruteFound, 'DNS Brute-force');
    sendEvent('source_found', { source: 'DNS Brute-force', count: activeBruteFound.length });

    // Deduplicate and prepare verification list
    const allUniqueSubdomains = Array.from(discoveredMap.keys());
    sendEvent('info', { 
      message: `Discovered ${allUniqueSubdomains.length} unique potential subdomains. Starting DNS & HTTP verification...` 
    });

    sendEvent('start_verification', { total: allUniqueSubdomains.length });

    // 3. Verification phase: DNS Resolution + Web Check (in parallel batches)
    const verificationBatchSize = 10;
    let completedCount = 0;

    for (let i = 0; i < allUniqueSubdomains.length; i += verificationBatchSize) {
      const batch = allUniqueSubdomains.slice(i, i + verificationBatchSize);
      
      await Promise.all(batch.map(async (subdomain) => {
        const ip = await resolveDNS(subdomain);
        const sources = Array.from(discoveredMap.get(subdomain));

        if (ip) {
          // If DNS resolves, check if web server is live
          const webCheck = await checkWebLive(subdomain);
          
          sendEvent('result', {
            subdomain,
            ip,
            sources,
            live: webCheck.live,
            web: webCheck.live ? {
              protocol: webCheck.protocol,
              status: webCheck.status,
              title: webCheck.title,
              server: webCheck.server
            } : null
          });
        } else {
          // Resolved offline/invalid DNS
          sendEvent('result', {
            subdomain,
            ip: null,
            sources,
            live: false,
            web: null
          });
        }

        completedCount++;
        sendEvent('progress', { current: completedCount, total: allUniqueSubdomains.length });
      }));
    }

    sendEvent('done', { message: 'Scan completed successfully!' });
  } catch (error) {
    console.error(`Scanning error: ${error.message}`);
    sendEvent('error', { message: `A scanning error occurred: ${error.message}` });
  } finally {
    res.end();
  }
});

// Start listening
app.listen(PORT, () => {
  console.log(`Subdomain Finder running at http://localhost:${PORT}`);
});
