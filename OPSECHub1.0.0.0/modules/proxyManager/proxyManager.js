/**
 * OPSECHub - Proxy Manager Module
 * Handles setting and clearing proxy settings for both Google Chrome (declarative)
 * and Mozilla Firefox (event-driven listener).
 */

const brw = typeof browser !== 'undefined' ? browser : chrome;
const isFirefox = typeof navigator !== 'undefined' && navigator.userAgent.includes("Firefox");
let firefoxProxyListener = null;

export const proxyManagerModule = {
    PROXY_LIST_URL: 'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.json',
    CACHE_DURATION: 24 * 60 * 60 * 1000, // 24 hours

    /**
     * Enables automatic proxy using the remote list.
     */
    enableAutoProxy: async function() {
        try {
            const data = await brw.storage.local.get(['cachedProxies', 'proxiesTimestamp']);
            let proxies = data.cachedProxies;
            const now = Date.now();

            if (!proxies || !data.proxiesTimestamp || (now - data.proxiesTimestamp) > this.CACHE_DURATION) {
                console.log('[OPSECHub] Fetching fresh proxies...');
                try {
                    const response = await fetch(this.PROXY_LIST_URL);
                    if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                    const json = await response.json();
                    
                    proxies = json.map(p => ({
                        type: p.protocol || 'socks5',
                        host: p.ip,
                        port: p.port,
                        country: (p.geolocation && p.geolocation.country) ? p.geolocation.country : 'Unknown'
                    }));
                    
                    await brw.storage.local.set({
                        cachedProxies: proxies,
                        proxiesTimestamp: now
                    });
                } catch (fetchErr) {
                    console.error('[OPSECHub] Failed to fetch proxies:', fetchErr);
                    if (!proxies || proxies.length === 0) {
                        console.warn('[OPSECHub] No cached proxies available to fallback to.');
                        throw fetchErr;
                    } else {
                        console.log('[OPSECHub] Using expired cached proxies as fallback.');
                    }
                }
            } else {
                console.log('[OPSECHub] Using cached proxies.');
            }

            if (proxies && proxies.length > 0) {
                // Pick a random proxy
                const randomProxy = proxies[Math.floor(Math.random() * proxies.length)];
                this.setProxy(randomProxy);
            } else {
                console.warn('[OPSECHub] No proxies found in list.');
            }
        } catch (error) {
            console.error('[OPSECHub] Error enabling auto proxy:', error);
        }
    },

    /**
     * Applies a proxy configuration.
     * @param {Object} config - { type: "http"|"socks5", host: "127.0.0.1", port: 8080 }
     */
    setProxy: function(config) {
        if (!config || !config.host || !config.port) {
            this.clearProxy();
            return;
        }

        // Security: Validate proxy config schema to reject malformed/poisoned data
        if (typeof config.host !== 'string' || !/^[a-zA-Z0-9.\-:]+$/.test(config.host)) {
            console.warn('[OPSECHub] Proxy host rejected (invalid characters):', config.host);
            return;
        }
        const portNum = parseInt(config.port, 10);
        if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
            console.warn('[OPSECHub] Proxy port rejected (out of range):', config.port);
            return;
        }

        if (isFirefox) {
            // Firefox event-driven Proxy implementation
            try {
                this.clearProxy(); // Clear any existing listener first
                
                const scheme = config.type === 'socks5' ? 'socks' : 'http'; // Firefox expects 'socks'
                
                firefoxProxyListener = (requestInfo) => {
                    return {
                        type: scheme,
                        host: config.host,
                        port: parseInt(config.port, 10),
                        proxyDNS: config.type === 'socks5' // Prevents DNS leaks for SOCKS5 by proxying DNS
                    };
                };
                
                brw.proxy.onRequest.addListener(firefoxProxyListener, { urls: ["<all_urls>"] });
                console.log(`[OPSECHub] Firefox Proxy activated: ${scheme}://${config.host}:${config.port}`);
            } catch (err) {
                console.error('[OPSECHub] Firefox Proxy Error:', err);
            }
        } else {
            // Chrome settings-based Proxy implementation
            const scheme = config.type === 'socks5' ? 'socks5' : 'http';
            
            const proxyConfig = {
                mode: "fixed_servers",
                rules: {
                    singleProxy: {
                        scheme: scheme,
                        host: config.host,
                        port: parseInt(config.port, 10)
                    },
                    bypassList: ["localhost", "127.0.0.1", "::1"]
                }
            };

            brw.proxy.settings.set(
                { value: proxyConfig, scope: 'regular' },
                function() {
                    if (brw.runtime.lastError) {
                        console.error('[OPSECHub] Proxy Error:', brw.runtime.lastError.message);
                    } else {
                        console.log(`[OPSECHub] Proxy activated: ${scheme}://${config.host}:${config.port}`);
                    }
                }
            );
        }
    },

    /**
     * Clears any applied proxy, returning to system default.
     */
    clearProxy: function() {
        if (isFirefox) {
            if (firefoxProxyListener) {
                brw.proxy.onRequest.removeListener(firefoxProxyListener);
                firefoxProxyListener = null;
                console.log('[OPSECHub] Firefox Proxy cleared. Using system default.');
            }
        } else {
            brw.proxy.settings.clear(
                { scope: 'regular' },
                function() {
                    if (brw.runtime.lastError) {
                        console.error('[OPSECHub] Proxy Error on clear:', brw.runtime.lastError.message);
                    } else {
                        console.log('[OPSECHub] Proxy cleared. Using system default.');
                    }
                }
            );
        }
    }
};
