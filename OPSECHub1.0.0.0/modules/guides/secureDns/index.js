// 🌍 Guide 2: Secure DNS (DoH) Guide
function initDnsGuide() {
    const btnOpenChrome = document.getElementById('btn-open-chrome-dns');
    if (btnOpenChrome) {
        btnOpenChrome.addEventListener('click', () => {
            brw.tabs.create({ url: 'chrome://settings/security' }).catch(() => {});
        });
    }

    const btnOpenFirefox = document.getElementById('btn-open-firefox-dns');
    if (btnOpenFirefox) {
        btnOpenFirefox.addEventListener('click', () => {
            brw.tabs.create({ url: 'about:preferences#privacy' }).catch(() => {});
        });
    }

    const btnOpenEdge = document.getElementById('btn-open-edge-dns');
    if (btnOpenEdge) {
        btnOpenEdge.addEventListener('click', () => {
            brw.tabs.create({ url: 'edge://settings/privacy' }).catch(() => {});
        });
    }

    const btnOpenOpera = document.getElementById('btn-open-opera-dns');
    if (btnOpenOpera) {
        btnOpenOpera.addEventListener('click', () => {
            brw.tabs.create({ url: 'opera://settings/system' }).catch(() => {});
        });
    }

    const providers = [
        { name: 'Cloudflare (Default)', tag: 'Fast & Private', desc: 'Fastest worldwide, privacy-first, zero logging.', url: 'https://chrome.cloudflare-dns.com/dns-query' },
        { name: 'Cloudflare (Security Filter)', tag: 'Malware Block', desc: 'Blocks malicious domains, phishing, and malware.', url: 'https://security.cloudflare-dns.com/dns-query' },
        { name: 'Cloudflare (Family Shield)', tag: 'Adult + Malware', desc: 'Blocks malware and explicit adult content.', url: 'https://family.cloudflare-dns.com/dns-query' },
        { name: 'Quad9 (Swiss High-Security)', tag: 'Malware Block', desc: 'Swiss-based non-profit with real-time threat intelligence.', url: 'https://dns.quad9.net/dns-query' },
        { name: 'AdGuard (Ad & Tracker Block)', tag: 'Ads & Trackers', desc: 'Blocks advertisements, tracking scripts, and phishing.', url: 'https://dns.adguard-dns.com/dns-query' },
        { name: 'AdGuard (Family Protection)', tag: 'Family Shield', desc: 'Blocks ads, trackers, malware, and adult domains.', url: 'https://family.adguard-dns.com/dns-query' },
        { name: 'Control D (Ad & Tracker Block)', tag: 'Ads & Trackers', desc: 'Customizable DNS with zero-logging privacy guarantees.', url: 'https://freedns.controld.com/p2' },
        { name: 'Control D (Unfiltered)', tag: 'Pure Speed', desc: 'High-performance unfiltered DNS without blocking.', url: 'https://freedns.controld.com/uncensored' },
        { name: 'Mullvad (Ad & Tracker Block)', tag: 'Swedish Privacy', desc: 'Privacy-focused no-logs DNS operated by Mullvad VPN.', url: 'https://adblock.doh.mullvad.net/dns-query' },
        { name: 'Mullvad (Pure No-Logs)', tag: 'Swedish Privacy', desc: 'Unfiltered encrypted DNS with absolute no-logs policy.', url: 'https://doh.mullvad.net/dns-query' },
        { name: 'NextDNS (Public Default)', tag: 'Smart Filtering', desc: 'Next-gen DNS with artificial intelligence tracking protection.', url: 'https://dns.nextdns.io' },
        { name: 'CleanBrowsing (Security Filter)', tag: 'Security Filter', desc: 'Filters out malicious domains, phishing, and rogue IPs.', url: 'https://doh.cleanbrowsing.org/doh/security-filter/' },
        { name: 'Google Public DNS', tag: 'Global Speed', desc: 'Reliable worldwide infrastructure by Google.', url: 'https://dns.google/dns-query' },
        { name: 'DNS.SB (European No-Logs)', tag: 'EU Privacy', desc: 'European privacy-first encrypted DNS with zero logging.', url: 'https://doh.dns.sb/dns-query' }
    ];

    const grid = document.getElementById('dns-providers-grid');
    if (!grid) return;
    grid.innerHTML = '';

    providers.forEach(p => {
        const card = document.createElement('div');
        card.className = 'test-card';
        card.style.cssText = 'flex-direction: column; align-items: stretch; gap: 8px; padding: 14px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.07); border-radius: 8px;';

        card.innerHTML = `
            <div style="display: flex; justify-content: space-between; width: 100%; align-items: center;">
                <h4 style="margin: 0; font-size: 14px; font-weight: 700; color: #ffffff;">${p.name}</h4>
                <span style="font-size: 10.5px; font-weight: 600; color: #00e5ff; background: rgba(0, 229, 255, 0.1); padding: 2px 8px; border-radius: 10px; border: 1px solid rgba(0, 229, 255, 0.2);">${p.tag}</span>
            </div>
            <p style="margin: 0; font-size: 12px; color: #b0bec5; line-height: 1.4;">${p.desc}</p>
            <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 4px;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 11px; color: #78909c; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;">DoH Server Endpoint:</span>
                    <button class="copy-btn" data-url="${p.url}" style="background: rgba(0, 229, 255, 0.12); border: 1px solid rgba(0, 229, 255, 0.3); color: #00e5ff; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 11.5px; font-weight: 600; display: flex; align-items: center; gap: 4px; transition: all 0.2s ease;">
                        📋 Copy URL
                    </button>
                </div>
                <div style="background: rgba(0,0,0,0.45); border: 1px solid rgba(0, 229, 255, 0.2); border-radius: 6px; padding: 8px 12px; word-break: break-all; font-family: monospace; font-size: 11.5px; color: #00e5ff; user-select: all; line-height: 1.4;">
                    ${p.url}
                </div>
            </div>
        `;
        
        const btn = card.querySelector('.copy-btn');
        btn.addEventListener('click', async () => {
            try {
                await navigator.clipboard.writeText(p.url);
                const originalText = btn.innerHTML;
                btn.innerHTML = '✓ Copied!';
                btn.style.background = 'rgba(76, 175, 80, 0.2)';
                btn.style.borderColor = '#4CAF50';
                btn.style.color = '#4CAF50';
                setTimeout(() => {
                    btn.innerHTML = originalText;
                    btn.style.background = 'rgba(0, 229, 255, 0.12)';
                    btn.style.borderColor = 'rgba(0, 229, 255, 0.3)';
                    btn.style.color = '#00e5ff';
                }, 2000);
            } catch (err) {
                console.error('Failed to copy: ', err);
            }
        });

        grid.appendChild(card);
    });
}
