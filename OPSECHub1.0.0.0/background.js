const brw = typeof browser !== 'undefined' ? browser : chrome;

import webrtcModule from './modules/webrtc/index.js';
import mediaBlockModule from './modules/mediaBlock/index.js';
import locationBlockModule from './modules/locationBlock/index.js';
import userAgentSpoofModule from './modules/userAgentSpoof/index.js';
import googleTelemetryModule from './modules/googleTelemetry/index.js';
import privacyHeadersModule from './modules/privacyHeaders/index.js';
import searchReferrerBlockModule from './modules/searchReferrerBlock/index.js';
import urlSanitizerModule from './modules/urlSanitizer/index.js';
import antiFingerprintModule from './modules/antiFingerprint/index.js';
import cookieGuardModule from './modules/cookieGuard/index.js';
import forceHttpsModule from './modules/forceHttps/index.js';
import { proxyManagerModule } from './modules/proxyManager/proxyManager.js';
import decoyTrafficModule from './modules/decoyTraffic/index.js';
import hardwareMaskModule from './modules/hardwareMask/index.js';
import clickjackXssModule from './modules/clickjackXss/index.js';
import referrerControlModule from './modules/referrerControl/index.js';
import networkExportModule from './modules/networkExport/index.js';
import clipboardGuardModule from './modules/clipboardGuard/index.js';

let globalMasterSwitch = true;
let globalExcludedDomains = [];

async function initializeModulesSafely() {
    // Helper to send logs to our diagnostic server
    const logDiag = (msg, data = null) => {
        console.log(`[OPSECHub:Diag] ${msg}`, data || '');
    };

    try {
        logDiag('initializeModulesSafely started');

        const sessionRules = await brw.declarativeNetRequest.getSessionRules();
        const isSessionInitialized = sessionRules.some(r => r.id === 999000);

        logDiag('Session initialization check', { isSessionInitialized, sessionRules: sessionRules.map(r => r.id) });

        if (isSessionInitialized) {
            logDiag('Session already initialized, skipping initialization.');
            return;
        }

        const d = await brw.storage.local.get({ masterSwitch: true, excludedDomains: [], threatFeeds: {}, moduleStates: {} });

        globalMasterSwitch = d.masterSwitch;
        globalExcludedDomains = d.excludedDomains;

        updateExclusionRules(globalExcludedDomains);

        if (d.masterSwitch) {
            const states = d.moduleStates || {};
            logDiag('First-time session initialization. Module states:', states);

            for (const [mod, enabled] of Object.entries(states)) {
                if (enabled && mod !== 'threatIntel' && mod !== 'adBlocker') {
                    logDiag(`Initializing module on startup: ${mod}`);
                    await handleModuleToggle(mod, true);
                }
            }

            // Re-sync core static rulesets
            await syncCoreRuleset().catch(err => {
                logDiag('Sync core ruleset failed', err.toString());
            });

            // Re-register threat feeds only if they are missing
            const isIntelEnabled = d.masterSwitch && d.moduleStates.threatIntel !== false;
            if (isIntelEnabled) {
                const feeds = d.threatFeeds || {};
                try {
                    const res = await fetch(brw.runtime.getURL('rules/Malware_Phishing_Threat_Intelligence/Threat_list.json'));
                    if (res.ok) {
                        const listData = await res.json();
                        for (const entry of listData.entries) {
                            if (feeds[entry.id]) {
                                await toggleDynamicRuleset(entry.id, entry.url, true);
                            }
                        }
                    }
                } catch (e) {
                    logDiag('Failed to restore threat feeds', e.toString());
                }
            }
        }

        // Register the session marker rule to mark session as initialized
        const markerRule = {
            id: 999000,
            priority: 1,
            action: {
                type: "modifyHeaders",
                requestHeaders: [
                    { header: "X-OPSECHub-Session", operation: "set", value: "active" }
                ]
            },
            condition: {
                urlFilter: "https://opsechub.local/*",
                resourceTypes: ["xmlhttprequest"]
            }
        };

        await brw.declarativeNetRequest.updateSessionRules({
            addRules: [markerRule]
        });
        logDiag('Session marker rule registered. Session is now initialized.');

    } catch (e) {
        logDiag('Error in initializeModulesSafely', e.toString());
    }
}

// Call safe initialization
initializeModulesSafely();

async function clearAllDynamicRules() {
    try {
        const rules = await brw.declarativeNetRequest.getDynamicRules();
        const legacyRuleIds = rules.map(r => r.id).filter(id => id !== 999999);
        if (legacyRuleIds.length > 0) {
            console.log(`[OPSECHub] Wiping ${legacyRuleIds.length} dynamic rules...`);
            await brw.declarativeNetRequest.updateDynamicRules({
                removeRuleIds: legacyRuleIds
            });
        }
    } catch (err) {
        console.error('[OPSECHub] Failed to wipe dynamic rules:', err);
    }
}

async function updateExclusionRules(domains) {
    const oldRuleIds = [999999];
    if (!domains || domains.length === 0) {
        return brw.declarativeNetRequest.updateDynamicRules({ removeRuleIds: oldRuleIds }).catch(() => { });
    }
    const rule = {
        id: 999999,
        priority: 9999,
        action: { type: 'allowAllRequests' },
        condition: {
            requestDomains: domains,
            resourceTypes: ["main_frame", "sub_frame"]
        }
    };
    return brw.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: oldRuleIds,
        addRules: [rule]
    }).catch(() => { });
}

async function syncCoreRuleset() {
    const d = await brw.storage.local.get({ masterSwitch: true, coreShieldMode: 'disabled' });
    const { masterSwitch, coreShieldMode } = d;
    const adblockEnabled = masterSwitch && coreShieldMode !== 'disabled' && coreShieldMode !== 'custom';

    const enabledIds = await brw.declarativeNetRequest.getEnabledRulesets();
    const manifest = brw.runtime.getManifest();
    const allDeclaredIds = (manifest.declarative_net_request?.rule_resources || []).map(r => r.id);
    const allCoreIds = allDeclaredIds.filter(id => id.startsWith('Core_'));

    let enableIds = [];
    let disableIds = [];

    if (adblockEnabled) {
        enableIds = allCoreIds.filter(id => id.startsWith(coreShieldMode + '_') && !enabledIds.includes(id));
        disableIds = allCoreIds.filter(id => !id.startsWith(coreShieldMode + '_') && enabledIds.includes(id));
    } else {
        disableIds = allCoreIds.filter(id => enabledIds.includes(id));
    }

    console.log(`[OPSECHub] Syncing core rulesets. Mode: ${coreShieldMode}, Master: ${masterSwitch}`);
    console.log(`[OPSECHub]   To enable: ${enableIds.join(', ') || 'none'}`);
    console.log(`[OPSECHub]   To disable: ${disableIds.join(', ') || 'none'}`);

    if (enableIds.length > 0 || disableIds.length > 0) {
        try {
            await brw.declarativeNetRequest.updateEnabledRulesets({
                disableRulesetIds: disableIds,
                enableRulesetIds: enableIds
            });
            console.log(`[OPSECHub] Core rulesets updated successfully.`);
        } catch (err) {
            console.error(`[OPSECHub] Error updating static rulesets (e.g., rules count limit exceeded):`, err);
        }
    }

    // Diagnostics: log currently active rulesets in Chrome
    const activeIds = await brw.declarativeNetRequest.getEnabledRulesets();
    console.log('[OPSECHub] Currently Active Rulesets in Chrome:', activeIds);
}

// ═══════════════════════════════════════════════════════════════════
// STATE INITIALIZATION
// ═══════════════════════════════════════════════════════════════════
brw.runtime.onInstalled.addListener((details) => {
    console.log('[OPSECHub] Extension Installed/Updated. Reason:', details?.reason);

    // Wipe all dynamic rules first to guarantee legacy builds are cleared
    clearAllDynamicRules();

    if (details && details.reason === 'install') {
        brw.tabs.create({ url: brw.runtime.getURL('welcome.html') });
    }

    brw.storage.local.get({ moduleStates: {} }).then(data => {
        if (Object.keys(data.moduleStates).length === 0) {
            brw.storage.local.set({ moduleStates: {} });
        } else {
            // Re-sync all enabled dynamic scripts on update/reload
            const states = data.moduleStates || {};
            for (const [mod, enabled] of Object.entries(states)) {
                if (enabled && mod !== 'threatIntel' && mod !== 'adBlocker') {
                    console.log(`[OPSECHub] Re-syncing script for module on update/reload: ${mod}`);
                    handleModuleToggle(mod, true).catch(err => {
                        console.error(`[OPSECHub] Failed to re-sync module ${mod}:`, err);
                    });
                }
            }
        }
        syncCoreRuleset().catch(err => console.error('[OPSECHub] onInstalled sync failed:', err));
    });
});

// ═══════════════════════════════════════════════════════════════════
// MESSAGE HANDLER
// ═══════════════════════════════════════════════════════════════════
brw.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'resetStats') {
        brw.storage.local.set({ opsecStats: { adsBlocked: 0, threatsBlocked: 0 } }, () => {
            sendResponse({ success: true });
        });
        return true;
    }

    if (message.action === 'trace_redirects_background') {
        const targetUrl = message.url;
        const hops = [targetUrl];

        const redirectListener = (details) => {
            if (details.redirectUrl) {
                if (!hops.includes(details.redirectUrl)) {
                    hops.push(details.redirectUrl);
                }
            }
        };

        brw.webRequest.onBeforeRedirect.addListener(
            redirectListener,
            { urls: ["<all_urls>"] }
        );

        fetch(targetUrl, {
            method: 'GET',
            mode: 'no-cors',
            redirect: 'follow',
            cache: 'no-store',
            credentials: 'omit'
        })
            .then(res => {
                brw.webRequest.onBeforeRedirect.removeListener(redirectListener);
                if (res.url && !hops.includes(res.url)) {
                    hops.push(res.url);
                }
                sendResponse({ success: true, hops: hops });
            })
            .catch(err => {
                brw.webRequest.onBeforeRedirect.removeListener(redirectListener);
                // Fallback: If even no-cors fails, return the captured hops so far
                if (hops.length > 0) {
                    sendResponse({ success: true, hops: hops });
                } else {
                    sendResponse({ success: false, error: err.message, hops: hops });
                }
            });

        return true; // Keep channel open
    }

    if (message.action === 'executeQuickAction') {
        console.log(`[OPSECHub] Executing quick action: ${message.type}`);

        try {
            if (message.type === 'qa-clear-history') {
                brw.browsingData.remove({ since: Date.now() - 3600000 }, { history: true });
            } else if (message.type === 'qa-clear-cache') {
                brw.browsingData.remove({}, { cache: true, appcache: true, cacheStorage: true });
            } else if (message.type === 'qa-clear-cookies') {
                brw.browsingData.remove({}, { cookies: true });
            } else if (message.type === 'qa-clear-site') {
                brw.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    if (tabs[0] && tabs[0].url) {
                        try {
                            const origin = new URL(tabs[0].url).origin;
                            brw.browsingData.remove({ origins: [origin] }, { cache: true, cookies: true, localStorage: true });
                            console.log(`[OPSECHub] Cleared data for ${origin}`);
                        } catch (e) { }
                    }
                });
            }
            sendResponse({ success: true });
        } catch (e) {
            console.error(`[OPSECHub] Quick Action Error:`, e);
            sendResponse({ success: false, error: e.toString() });
        }
        return true;
    }

    if (message.action === 'registerBlock') {
        const { module } = message;
        brw.storage.local.get({ opsecStats: { adsBlocked: 0, threatsBlocked: 0 }, alertLog: [] }).then(data => {
            const stats = data.opsecStats;
            stats.threatsBlocked = (stats.threatsBlocked || 0) + 1;
            // Persist alert to history log (capped at 50)
            const log = data.alertLog || [];
            log.unshift({
                module: module,
                action: message.detail || '',
                url: (sender && sender.tab) ? sender.tab.url : '',
                time: Date.now()
            });
            if (log.length > 50) log.length = 50;
            brw.storage.local.set({ opsecStats: stats, alertLog: log });
        });

        if (sender && sender.tab && sender.tab.id) {
            const tabId = sender.tab.id;
            brw.action.getBadgeText({ tabId: tabId }).then(text => {
                let currentCount = parseInt(text) || 0;
                currentCount += 1;
                brw.action.setBadgeText({ text: String(currentCount), tabId: tabId }).catch(() => { });
                brw.action.setBadgeBackgroundColor({ color: '#00e5ff', tabId: tabId }).catch(() => { });
            }).catch(() => {
                brw.action.setBadgeText({ text: '1', tabId: tabId }).catch(() => { });
                brw.action.setBadgeBackgroundColor({ color: '#00e5ff', tabId: tabId }).catch(() => { });
            });
        }
        sendResponse({ success: true });
        return true;
    }

    if (message.action === 'toggleModule') {
        const { module, enabled } = message;
        handleModuleToggle(module, enabled);
        sendResponse({ success: true });
        return true;
    }

    if (message.action === 'toggleMaster') {
        const { enabled } = message;
        globalMasterSwitch = enabled;
        console.log('[OPSECHub] Master Switch toggled:', enabled);

        brw.tabs.query({}, tabs => {
            tabs.forEach(tab => brw.tabs.sendMessage(tab.id, { action: 'masterToggle', enabled }).catch(() => { }));
        });

        brw.storage.local.get('moduleStates').then(data => {
            const states = data.moduleStates || {};
            for (const [mod, modEnabled] of Object.entries(states)) {
                if (modEnabled) {
                    handleModuleToggle(mod, enabled);
                }
            }
        });

        syncCoreRuleset().then(() => sendResponse({ success: true }));
        return true;
    }

    if (message.action === 'toggleExclusion') {
        const { domain, exclude } = message;
        brw.storage.local.get({ excludedDomains: [] }).then(data => {
            let domains = data.excludedDomains || [];
            if (exclude && !domains.includes(domain)) {
                domains.push(domain);
            } else if (!exclude) {
                domains = domains.filter(d => d !== domain);
            }
            globalExcludedDomains = domains;
            brw.storage.local.set({ excludedDomains: domains }).then(() => {
                updateExclusionRules(domains);
                sendResponse({ success: true, domains });
            });
        });
        return true;
    }

    if (message.action === 'toggleDynamicList') {
        const { listId, url, enabled } = message;
        brw.storage.local.get({ moduleStates: {}, masterSwitch: true }).then(d => {
            const isMasterIntelEnabled = d.masterSwitch && d.moduleStates.threatIntel !== false;
            const dnrEnabled = isMasterIntelEnabled && enabled;

            toggleDynamicRuleset(listId, url, dnrEnabled)
                .then(res => {
                    if (res.success) {
                        brw.storage.local.get({ threatFeeds: {}, threatCounts: {} }).then(storeData => {
                            const feeds = storeData.threatFeeds || {};
                            const counts = storeData.threatCounts || {};
                            feeds[listId] = enabled; // Checked status is stored as requested

                            if (dnrEnabled) {
                                counts[listId] = res.count;
                            } else {
                                delete counts[listId];
                            }
                            brw.storage.local.set({ threatFeeds: feeds, threatCounts: counts }).then(() => {
                                sendResponse({ success: true, count: dnrEnabled ? res.count : 0 });
                            });
                        });
                    } else {
                        sendResponse(res);
                    }
                })
                .catch(err => sendResponse({ success: false, error: err.message }));
        });
        return true;
    }

    if (message.action === 'fetchSecurityHeaders') {
        const targetUrl = message.targetUrl;
        fetch(targetUrl, { method: 'GET', redirect: 'follow', cache: 'no-store' })
            .then(res => {
                const headersObj = {};
                res.headers.forEach((val, key) => {
                    headersObj[key.toLowerCase()] = val;
                });
                sendResponse({ success: true, status: res.status, headers: headersObj });
            })
            .catch(err => {
                fetch(targetUrl, { method: 'HEAD', redirect: 'follow', cache: 'no-store' })
                    .then(res => {
                        const headersObj = {};
                        res.headers.forEach((val, key) => {
                            headersObj[key.toLowerCase()] = val;
                        });
                        sendResponse({ success: true, status: res.status, headers: headersObj });
                    })
                    .catch(err2 => sendResponse({ success: false, error: err2.message || 'Fetch failed' }));
            });
        return true;
    }

    if (message.action === 'probeDohEndpoint') {
        const { targetUrl } = message;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4500);

        fetch(targetUrl, {
            method: 'GET',
            headers: { 'Accept': 'application/dns-message, application/dns-json, application/json' },
            cache: 'no-store',
            signal: controller.signal
        })
            .then(async (res) => {
                clearTimeout(timeoutId);
                let isDnssec = false;
                if (res.ok) {
                    const data = await res.json().catch(() => ({}));
                    isDnssec = !!(data.AD || data.AuthenticData);
                }
                sendResponse({ success: true, status: res.status, isDnssec });
            })
            .catch(err => {
                clearTimeout(timeoutId);
                sendResponse({ success: false, error: err.message || 'Probing failed' });
            });
        return true;
    }

    if (message.action === 'clearData') {
        console.log('[OPSECHub] Wiping browsing data (Quick Action)...');
        brw.browsingData.remove({}, {
            "appcache": true,
            "cache": true,
            "cacheStorage": true,
            "cookies": true,
            "downloads": true,
            "fileSystems": true,
            "formData": true,
            "history": true,
            "indexedDB": true,
            "localStorage": true,
            "passwords": false,
            "serviceWorkers": true,
            "webSQL": true
        }, () => {
            console.log('[OPSECHub] Browsing data wiped successfully.');
            sendResponse({ success: true });
        });
        return true;
    }

    if (message.action === 'switchCoreRuleset') {
        const { activeRuleset } = message;
        const enabled = activeRuleset !== 'disabled';
        brw.storage.local.get({ moduleStates: {} }).then(data => {
            const states = data.moduleStates || {};
            states.adBlocker = enabled;
            brw.storage.local.set({ coreShieldMode: activeRuleset, moduleStates: states })
                .then(() => syncCoreRuleset())
                .then(() => sendResponse({ success: true }))
                .catch(err => {
                    console.error('[OPSECHub] switchCoreRuleset failed:', err);
                    sendResponse({ success: false, error: err.message });
                });
        });
        return true;
    }

    if (message.action === 'toggleStaticRuleset') {
        const { rulesetId, enabled } = message;
        brw.declarativeNetRequest.getEnabledRulesets().then(enabledIds => {
            let enableIds = [];
            let disableIds = [];
            if (enabled && !enabledIds.includes(rulesetId)) enableIds.push(rulesetId);
            if (!enabled && enabledIds.includes(rulesetId)) disableIds.push(rulesetId);

            brw.declarativeNetRequest.updateEnabledRulesets({
                enableRulesetIds: enableIds,
                disableRulesetIds: disableIds
            }).then(() => sendResponse({ success: true }))
                .catch(err => {
                    console.error('[OPSECHub] Failed to toggle static ruleset:', err);
                    sendResponse({ success: false, error: err.message });
                });
        });
        return true;
    }

    if (message.action === 'setProxy') {
        const { config } = message;
        if (config) {
            // Security: Validate proxy config schema to prevent injection from untrusted CDN data
            if (typeof config.host !== 'string' || typeof config.port === 'undefined' ||
                !/^[a-zA-Z0-9.\-:]+$/.test(config.host) ||
                isNaN(parseInt(config.port, 10)) ||
                parseInt(config.port, 10) < 1 || parseInt(config.port, 10) > 65535) {
                console.warn('[OPSECHub] Invalid proxy config rejected:', config);
                sendResponse({ success: false, error: 'Invalid proxy configuration' });
                return true;
            }
            proxyManagerModule.setProxy(config);
        } else {
            proxyManagerModule.enableAutoProxy();
        }
        sendResponse({ success: true });
        return true;
    }

    if (message.action === 'refreshRules') {
        brw.storage.local.get({ threatFeeds: {} }).then(async (data) => {
            const feeds = data.threatFeeds || {};
            const promises = [];

            // Re-sync core rulesets
            promises.push(syncCoreRuleset());

            // Load and re-fetch enabled threat lists
            try {
                const res = await fetch(brw.runtime.getURL('rules/Malware_Phishing_Threat_Intelligence/Threat_list.json'));
                if (res.ok) {
                    const listData = await res.json();
                    for (const entry of listData.entries) {
                        if (feeds[entry.id]) {
                            promises.push(toggleDynamicRuleset(entry.id, entry.url, true));
                        }
                    }
                }
            } catch (err) {
                console.warn('[OPSECHub] Failed to read Threat_list.json during refresh:', err);
            }

            Promise.all(promises)
                .then(() => sendResponse({ success: true }))
                .catch(err => {
                    console.error('[OPSECHub] Refresh Rules Failed:', err);
                    sendResponse({ success: false, error: err.message });
                });
        });
        return true;
    }
});

async function handleModuleToggle(module, enabled) {
    switch (module) {
        case 'adBlocker':
            {
                const activeRuleset = enabled ? 'Core_Normal' : 'disabled';
                try {
                    const data = await brw.storage.local.get({ moduleStates: {} });
                    const states = data.moduleStates || {};
                    await brw.storage.local.set({ coreShieldMode: activeRuleset, moduleStates: states });
                    await syncCoreRuleset();
                } catch (e) { }
            }
            break;
        case 'proxyManager':
            if (!enabled) {
                proxyManagerModule.clearProxy();
            } else {
                try {
                    const data = await brw.storage.local.get('activeProxy');
                    if (data.activeProxy) {
                        proxyManagerModule.setProxy(data.activeProxy);
                    } else {
                        proxyManagerModule.enableAutoProxy();
                    }
                } catch (e) { }
            }
            break;
        case 'webrtcBlock':
            await webrtcModule.toggle(enabled);
            break;
        case 'mediaBlock':
            await mediaBlockModule.toggle(enabled);
            break;
        case 'locationBlock':
            await locationBlockModule.toggle(enabled);
            break;
        case 'clipboardGuard':
            await clipboardGuardModule.toggle(enabled);
            break;
        case 'userAgentSpoof':
            try {
                const data = await brw.storage.local.get({ uaProfile: 'win_chrome' });
                await userAgentSpoofModule.toggle(enabled, data.uaProfile);
            } catch (e) { }
            break;
        case 'googleTelemetry':
            await googleTelemetryModule.toggle(enabled);
            break;
        case 'privacyHeaders':
            await privacyHeadersModule.toggle(enabled);
            break;
        case 'searchReferrerBlock':
            await searchReferrerBlockModule.toggle(enabled);
            break;
        case 'urlSanitizer':
            await urlSanitizerModule.toggle(enabled);
            break;
        case 'antiFingerprint':
            try {
                const data = await brw.storage.local.get({ antiFingerprintMode: 'blend-in' });
                console.log('[OPSECHub] Toggling antiFingerprint:', enabled, 'mode:', data.antiFingerprintMode);
                await antiFingerprintModule.toggle(enabled, data.antiFingerprintMode);
            } catch (e) { }
            break;
        case 'hardwareMask':
            await hardwareMaskModule.toggle(enabled);
            break;
        case 'threatIntel':
            if (!enabled) {
                for (const listId in DYNAMIC_LIST_BASE_IDS) {
                    await toggleDynamicRuleset(listId, '', false);
                }
                await brw.storage.local.set({ threatCounts: {} });
            } else {
                try {
                    const d = await brw.storage.local.get({ threatFeeds: {}, threatCounts: {} });
                    const feeds = d.threatFeeds || {};
                    const counts = d.threatCounts || {};
                    const res = await fetch(brw.runtime.getURL('rules/Malware_Phishing_Threat_Intelligence/Threat_list.json'));
                    if (res.ok) {
                        const listData = await res.json();
                        for (const entry of listData.entries) {
                            if (feeds[entry.id]) {
                                const toggleRes = await toggleDynamicRuleset(entry.id, entry.url, true);
                                if (toggleRes && toggleRes.success) {
                                    counts[entry.id] = toggleRes.count;
                                }
                            }
                        }
                        await brw.storage.local.set({ threatCounts: counts });
                    }
                } catch (e) {
                    console.warn('[OPSECHub] Failed to restore threat lists:', e);
                }
            }
            break;
        case 'cookieGuard':
            await cookieGuardModule.toggle(enabled);
            break;
        case 'forceHttps':
            await forceHttpsModule.toggle(enabled);
            break;
        case 'decoyTraffic':
            await decoyTrafficModule.toggle(enabled);
            break;
        case 'clickjackXss':
            await clickjackXssModule.toggle(enabled);
            break;
        case 'referrerControl':
            await referrerControlModule.toggle(enabled);
            break;
        case 'networkExport':
            await networkExportModule.toggle(enabled);
            break;
        default:
            try {
                const tabs = await brw.tabs.query({});
                for (const tab of tabs) {
                    if (tab.url && !tab.url.startsWith('chrome://')) {
                        await brw.tabs.sendMessage(tab.id, {
                            action: 'toggleModule',
                            module: module,
                            enabled: enabled
                        }).catch(() => { });
                    }
                }
            } catch (e) { }
    }
}

// ═══════════════════════════════════════════════════════════════════
// DYNAMIC THREAT RULES ENGINE
// ═══════════════════════════════════════════════════════════════════
const DYNAMIC_LIST_BASE_IDS = {
    'live_fake': 100000,
    'live_shortener': 200000,
    'live_dyndns': 300000,
    'live_badware': 400000
};

async function toggleDynamicRuleset(listId, url, enabled) {
    const baseId = DYNAMIC_LIST_BASE_IDS[listId];
    if (!baseId) return { success: false, error: 'Unknown dynamic list ID' };

    try {
        const existingRules = await brw.declarativeNetRequest.getDynamicRules();
        const removeRuleIds = existingRules
            .map(r => r.id)
            .filter(id => id >= baseId && id < baseId + 99999);

        let addRules = [];

        if (enabled) {
            console.log(`[OPSECHub] Fetching dynamic rules for ${listId} from ${url}...`);
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const text = await response.text();

            const lines = text.split('\n');
            let ruleId = baseId;

            for (let line of lines) {
                line = line.trim();
                // Skip empty lines, comments, and element hiding rules
                if (!line || line.startsWith('!') || line.startsWith('[') || line.includes('##') || line.includes('#@#')) {
                    continue;
                }

                let isException = false;
                if (line.startsWith('@@')) {
                    // Security: Strip ALL exception/allow rules from external feeds.
                    // A compromised feed could inject '@@' rules to whitelist malicious domains.
                    console.warn(`[OPSECHub] Stripped exception rule from external feed ${listId}: ${line}`);
                    continue;
                }

                let urlFilter = line;
                let condition = {
                    resourceTypes: ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "websocket", "other"]
                };

                // Parse modifiers if present
                if (urlFilter.includes('$')) {
                    const parts = urlFilter.split('$');
                    urlFilter = parts[0];
                    const modifiers = parts[1].split(',');

                    let specificResourceTypes = [];
                    let hasResourceTypeMod = false;

                    for (const mod of modifiers) {
                        if (mod === 'third-party') {
                            condition.domainType = "thirdParty";
                        } else if (mod === '~third-party') {
                            condition.domainType = "firstParty";
                        } else if (mod.startsWith('domain=')) {
                            const domains = mod.substring(7).split('|');
                            const initiatorDomains = [];
                            const excludedInitiatorDomains = [];
                            domains.forEach(d => {
                                if (d.startsWith('~')) {
                                    excludedInitiatorDomains.push(d.substring(1));
                                } else {
                                    initiatorDomains.push(d);
                                }
                            });
                            if (initiatorDomains.length > 0) condition.initiatorDomains = initiatorDomains;
                            if (excludedInitiatorDomains.length > 0) condition.excludedInitiatorDomains = excludedInitiatorDomains;
                        } else {
                            // Check for resource type modifiers
                            const typeMap = {
                                'script': 'script',
                                'image': 'image',
                                'stylesheet': 'stylesheet',
                                'xmlhttprequest': 'xmlhttprequest',
                                'subdocument': 'sub_frame',
                                'ping': 'ping',
                                'media': 'media',
                                'font': 'font',
                                'object': 'object',
                                'websocket': 'websocket',
                                'other': 'other'
                            };
                            const cleanMod = mod.startsWith('~') ? mod.substring(1) : mod;
                            if (typeMap[cleanMod]) {
                                hasResourceTypeMod = true;
                                if (!mod.startsWith('~')) {
                                    specificResourceTypes.push(typeMap[cleanMod]);
                                }
                            }
                        }
                    }

                    if (hasResourceTypeMod && specificResourceTypes.length > 0) {
                        condition.resourceTypes = specificResourceTypes;
                    }
                }

                // Parse hosts format (0.0.0.0 domain or 127.0.0.1 domain)
                if (/^(0\.0\.0\.0|127\.0\.0\.1)\s+/.test(urlFilter)) {
                    urlFilter = urlFilter.replace(/^(0\.0\.0\.0|127\.0\.0\.1)\s+/, '').trim();
                }

                // Format bare domain names into valid DNR AdBlock domain syntax
                if (!urlFilter.startsWith('||') && !urlFilter.startsWith('*') && !urlFilter.startsWith('/') && /^[a-zA-Z0-9\.\-]+$/.test(urlFilter)) {
                    urlFilter = `||${urlFilter}^`;
                }

                // If urlFilter is empty, contains spaces or non-ASCII characters, skip (DNR requires clean ASCII)
                if (!urlFilter || /[^\x00-\x7F]/.test(urlFilter) || urlFilter.includes(' ')) continue;

                condition.urlFilter = urlFilter;

                addRules.push({
                    "id": ruleId++,
                    "priority": 100,
                    "action": { "type": "block" },
                    "condition": condition
                });

                if (addRules.length >= 30000) break;
            }

            console.log(`[OPSECHub] Parsed ${addRules.length} dynamic rules for ${listId}`);

            // Randomize a test domain from the blocklist
            if (addRules.length > 0) {
                const blockRules = addRules.filter(r => r.action && r.action.type === 'block' && r.condition && r.condition.urlFilter);
                if (blockRules.length > 0) {
                    const cleanDomainRegex = /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/i;
                    let chosenDomain = '';
                    const shuffled = [...blockRules].sort(() => 0.5 - Math.random());
                    for (const rule of shuffled) {
                        let dom = rule.condition.urlFilter.replace(/^\|\|/, '').replace(/^\*/, '');
                        dom = dom.split('^')[0].split('*')[0].split('/')[0];
                        if (cleanDomainRegex.test(dom)) {
                            chosenDomain = dom;
                            break;
                        }
                    }
                    if (chosenDomain) {
                        console.log(`[OPSECHub] Selected dynamic test domain for ${listId}: ${chosenDomain}`);
                        const d = await brw.storage.local.get({ threatTestDomains: {} });
                        const testDomains = d.threatTestDomains || {};
                        testDomains[listId] = chosenDomain;
                        await brw.storage.local.set({ threatTestDomains: testDomains });
                    }
                }
            }
        }

        await brw.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: removeRuleIds,
            addRules: addRules
        });

        console.log(`[OPSECHub] Dynamic ruleset ${listId} ${enabled ? 'ENABLED' : 'DISABLED'}`);
        return { success: true, count: addRules.length };
    } catch (err) {
        console.error(`[OPSECHub] Dynamic Ruleset Error (${listId}):`, err);
        return { success: false, error: err.message };
    }
}

// ═══════════════════════════════════════════════════════════════════
// DYNAMIC SCRIPT INJECTION (Bypass CSP & Race Conditions)
// ═══════════════════════════════════════════════════════════════════
async function toggleDynamicScript(id, path, enabled) {
    try {
        const existing = await brw.scripting.getRegisteredContentScripts({ ids: [id] });
        if (enabled) {
            if (existing.length === 0) {
                await brw.scripting.registerContentScripts([{
                    id: id,
                    matches: ["<all_urls>"],
                    js: [path],
                    runAt: "document_start",
                    world: "MAIN",
                    allFrames: true
                }]);
                console.log(`[OPSECHub] Registered dynamic script: ${id}`);
            }
        } else {
            if (existing.length > 0) {
                await brw.scripting.unregisterContentScripts({ ids: [id] });
                console.log(`[OPSECHub] Unregistered dynamic script: ${id}`);
            }
        }
    } catch (e) {
        console.warn(`[OPSECHub] Error toggling dynamic script ${id}:`, e);
    }
}

// ═══════════════════════════════════════════════════════════════════
// TAB EVENT LISTENERS (For dynamic injections)
// ═══════════════════════════════════════════════════════════════════
brw.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading') {
        brw.action.setBadgeText({ text: '', tabId: tabId }).catch(() => { });
    }
});

if (brw.declarativeNetRequest && brw.declarativeNetRequest.onRuleMatchedDebug) {
    brw.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
        console.log(`[OPSECHub:DNR] Rule ID ${info.rule.ruleId} matched for ${info.request.url}`);

        brw.storage.local.get({ opsecStats: { adsBlocked: 0, threatsBlocked: 0 } }).then(data => {
            const stats = data.opsecStats;
            const ruleId = info.rule.ruleId;

            if (ruleId === 999999) {
                // Exclusion domain - ignored
                return;
            }

            if (ruleId === 900005 || ruleId === 900002 || ruleId === 900003 || ruleId === 999000 || ruleId === 999001) {
                // Header modifications & URL sanitizer & session markers - ignore for main counters
                return;
            }

            if (ruleId >= 100000 && ruleId < 500000) {
                stats.threatsBlocked = (stats.threatsBlocked || 0) + 1;
            } else {
                stats.adsBlocked = (stats.adsBlocked || 0) + 1;
            }

            brw.storage.local.set({ opsecStats: stats });
        });
    });
}


