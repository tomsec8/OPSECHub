const brw = typeof browser !== 'undefined' ? browser : chrome;

import webrtcModule from './modules/webrtc/index.js';
import mediaBlockModule from './modules/mediaBlock/index.js';
import locationBlockModule from './modules/locationBlock/index.js';
import googleTelemetryModule from './modules/googleTelemetry/index.js';
import privacyHeadersModule from './modules/privacyHeaders/index.js';
import cookieGuardModule from './modules/cookieGuard/index.js';
import forceHttpsModule from './modules/forceHttps/index.js';
import { proxyManagerModule } from './modules/proxyManager/proxyManager.js';
import clipboardGuardModule from './modules/clipboardGuard/index.js';
import { syncContentScripts, handleScriptingMessage } from './scripting-manager.js';
import {
    refreshRemoteCatalog,
    refreshEnabledRemoteLists,
    repairIncompleteRemoteLists,
    needsRemoteListRestore,
    ensureRemoteListsAlarm,
    getCatalogForUi,
    setRemoteListEnabled,
    loadRegexRulesForLists,
    getDnrBudgetSnapshot,
    DEFAULT_CDN_BASE
} from './js/remote-lists.js';
import {
    hasModuleOptionalPermissions,
    modulesNeedingPermission,
    MODULE_OPTIONAL_PERMISSIONS
} from './js/optional-permissions.mjs';

void DEFAULT_CDN_BASE;
void getDnrBudgetSnapshot;

let globalMasterSwitch = true;
let globalExcludedDomains = [];

async function sanitizeOptionalModuleStates() {
    const data = await brw.storage.local.get({ moduleStates: {} });
    const states = { ...(data.moduleStates || {}) };
    let changed = false;
    for (const id of Object.keys(MODULE_OPTIONAL_PERMISSIONS)) {
        if (!states[id]) continue;
        const ok = await hasModuleOptionalPermissions(id);
        if (!ok) {
            states[id] = false;
            changed = true;
            try { await handleModuleToggle(id, false); } catch { /* ignore */ }
        }
    }
    if (changed) {
        await brw.storage.local.set({ moduleStates: states });
        console.log('[OPSECHub] Cleared modules missing optional permissions');
    }
}

async function initializeModulesSafely() {
    const logDiag = (msg, data = null) => {
        console.log(`[OPSECHub] ${msg}`, data || '');
    };

    try {
        logDiag('initializeModulesSafely started');

        const sessionRules = await brw.declarativeNetRequest.getSessionRules();
        const isSessionInitialized = sessionRules.some(r => r.id === 999000);

        logDiag('Session initialization check', { isSessionInitialized, sessionRules: sessionRules.map(r => r.id) });

        await sanitizeOptionalModuleStates();

        if (isSessionInitialized) {
            // Session-scoped DNR rules outlive the service worker, so the
            // expensive setup below is already done. Listeners held in module
            // memory do not: a worker restart drops them, and the module still
            // reads as enabled, so it goes quietly dead until toggled by hand.
            logDiag('Session already initialized, re-binding in-memory listeners.');
            await rebindInMemoryModules();
            // Session rules die with the browser session — re-apply pause gate.
            await applyNetworkFilteringGate().catch(() => { });
            // Still finish any list load that was cut off mid-flight.
            await repairIncompleteRemoteLists().catch((err) => {
                logDiag('Incomplete list repair failed', err?.toString?.() || err);
            });
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

            // Re-sync cosmetics / regex / clear leftover static
            await syncCoreRuleset().catch(err => {
                logDiag('Sync core ruleset failed', err.toString());
            });

            // Network filter lists are remote dynamic DNR only
            await applyNetworkFilteringGate().catch(() => { });
            await repairIncompleteRemoteLists().catch((err) => {
                logDiag('Incomplete list repair failed', err?.toString?.() || err);
            });
            if (d.masterSwitch !== false && d.moduleStates.adBlocker !== false) {
                await restoreRemoteListsIfEnabled();
                refreshRemoteCatalog({ force: false }).catch(() => { });
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

// Instant pause for AdBlocker / master-off: keep list DNR installed, override
// with a higher-priority session allow (other blockers pause similarly).
const NETWORK_PAUSE_RULE_ID = 998000;
const NETWORK_PAUSE_RESOURCE_TYPES = [
    'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font',
    'object', 'xmlhttprequest', 'ping', 'websocket', 'media', 'other'
];

async function setNetworkFilteringPaused(paused) {
    try {
        if (paused) {
            await brw.declarativeNetRequest.updateSessionRules({
                removeRuleIds: [NETWORK_PAUSE_RULE_ID],
                addRules: [{
                    id: NETWORK_PAUSE_RULE_ID,
                    priority: 2000000,
                    action: { type: 'allow' },
                    condition: { resourceTypes: [...NETWORK_PAUSE_RESOURCE_TYPES] }
                }]
            });
        } else {
            await brw.declarativeNetRequest.updateSessionRules({
                removeRuleIds: [NETWORK_PAUSE_RULE_ID]
            });
        }
    } catch (err) {
        console.warn('[OPSECHub] Network pause gate failed:', err?.message || err);
    }
}

/** Pause network filtering when master is off OR AdBlocker module is off. */
async function applyNetworkFilteringGate() {
    const d = await brw.storage.local.get({ masterSwitch: true, moduleStates: {} });
    const active = d.masterSwitch !== false && d.moduleStates?.adBlocker !== false;
    await setNetworkFilteringPaused(!active);
    return { active };
}

// Defaults match lists_config.json `enabled: true`. Network rules load as
// remote dynamic DNR from Git — the extension no longer ships static rulesets.
function defaultFilterLists() {
    return [
        'easylist',
        'easyprivacy',
        'peter_lowe',
        'ublock_filters',
        'adguard_ubo',
        'ublock_badware',
        'malicious_url',
    ];
}

// Keep at most one list per exclusiveGroup (e.g. HaGeZi Multi tiers).
let exclusiveGroupCache = null;
async function loadExclusiveGroups() {
    if (exclusiveGroupCache) return exclusiveGroupCache;
    try {
        const res = await fetch(brw.runtime.getURL('rules/lists_config.json'));
        const config = await res.json();
        const groups = new Map();
        for (const cat of Object.values(config.categories || {})) {
            for (const [id, info] of Object.entries(cat.lists || {})) {
                if (!info.exclusiveGroup) continue;
                if (!groups.has(info.exclusiveGroup)) groups.set(info.exclusiveGroup, []);
                groups.get(info.exclusiveGroup).push(id);
            }
        }
        exclusiveGroupCache = groups;
    } catch (_) {
        exclusiveGroupCache = new Map();
    }
    return exclusiveGroupCache;
}

async function sanitizeExclusiveFilterLists(lists) {
    const groups = await loadExclusiveGroups();
    if (groups.size === 0) return lists;
    const selected = new Set(lists);
    let changed = false;
    for (const ids of groups.values()) {
        const enabled = ids.filter(id => selected.has(id));
        if (enabled.length <= 1) continue;
        const keep = [...lists].reverse().find(id => ids.includes(id));
        for (const id of enabled) {
            if (id !== keep) {
                selected.delete(id);
                changed = true;
            }
        }
    }
    if (!changed) return lists;
    const cleaned = lists.filter(id => selected.has(id));
    await brw.storage.local.set({ enabledFilterLists: cleaned });
    return cleaned;
}

// storage.onChanged fires once per changed key and several message handlers
// call sync directly, so runs overlap. Two overlapping runs each snapshot the
// dynamic rules before the other has written, then both claim rule id 700000.
let syncQueue = Promise.resolve();

function syncCoreRuleset() {
    const run = syncQueue.then(syncCoreRulesetNow, syncCoreRulesetNow);
    syncQueue = run.catch(() => { });
    return run;
}

// Modules whose entire effect is a listener registered inside enable(), rather
// than a DNR rule or a registered content script. Those two survive a service
// worker restart on their own; these do not. Re-running toggle(true) is safe,
// each of these guards on its own isEnabled flag.
const IN_MEMORY_LISTENER_MODULES = [
    'cookieGuard',
    // Chrome's proxy.settings persist, but Firefox's proxy.onRequest listener
    // lives in worker memory.
    'proxyManager',
];

async function rebindInMemoryModules() {
    const { moduleStates, masterSwitch } = await brw.storage.local.get({
        moduleStates: {},
        masterSwitch: true,
    });
    if (masterSwitch === false) { return; }
    for (const mod of IN_MEMORY_LISTENER_MODULES) {
        if (moduleStates[mod] !== true) { continue; }
        await handleModuleToggle(mod, true).catch(err =>
            console.error(`[OPSECHub] Failed to re-bind module ${mod}:`, err)
        );
    }
}

async function syncCoreRulesetNow() {
    const d = await brw.storage.local.get({
        masterSwitch: true,
        moduleStates: {},
        enabledFilterLists: defaultFilterLists(),
        excludedDomains: [],
    });
    const masterSwitch = d.masterSwitch && (d.moduleStates.adBlocker !== false);
    let enabledFilterLists = await sanitizeExclusiveFilterLists(d.enabledFilterLists || []);

    // Older installs may still have static rulesets enabled — turn them all off.
    try {
        const leftover = await brw.declarativeNetRequest.getEnabledRulesets();
        if (leftover.length > 0) {
            await brw.declarativeNetRequest.updateEnabledRulesets({
                disableRulesetIds: leftover,
                enableRulesetIds: []
            });
            console.log(`[OPSECHub] Disabled ${leftover.length} leftover static ruleset(s)`);
        }
    } catch (err) {
        console.warn('[OPSECHub] Could not clear leftover static rulesets:', err.message || err);
    }

    const scriptingIds = masterSwitch ? enabledFilterLists : [];
    console.log(`[OPSECHub] Syncing dynamic lists. Master: ${masterSwitch}, lists: ${scriptingIds.length}`);

    // Bundled regex companions (dynamic ids 700000+) for enabled lists.
    await syncRegexRules(scriptingIds);

    // Cosmetics / scriptlets follow the same enabled lists.
    await syncContentScripts(scriptingIds, {
        enabled: masterSwitch,
        excludedDomains: d.excludedDomains || [],
        generic: d.moduleStates.cosmeticGeneric !== false,
    });
}

// Regex companions: prefer remote cache (Git), fall back to bundled rules/regex/.
// Installed as dynamic rules (ids 700000+) after isRegexSupported checks.
const REGEX_RULE_ID_BASE = 700000;
const MAX_REGEX_RULES = 1000;

const regexSupportCache = new Map();

async function isRegexUsable(rule) {
    const { regexFilter, isUrlFilterCaseSensitive } = rule.condition;
    const key = `${isUrlFilterCaseSensitive === true ? 'cs' : 'ci'}\n${regexFilter}`;
    if (regexSupportCache.has(key)) { return regexSupportCache.get(key); }
    const result = await brw.declarativeNetRequest.isRegexSupported({
        regex: regexFilter,
        isCaseSensitive: isUrlFilterCaseSensitive === true,
        requireCapturing: rule.action?.redirect?.regexSubstitution !== undefined
    }).catch(() => ({ isSupported: false }));
    regexSupportCache.set(key, result.isSupported === true);
    return result.isSupported === true;
}

async function syncRegexRules(enabledRulesetIds) {
    const candidates = await loadRegexRulesForLists(enabledRulesetIds);

    const usable = await Promise.all(candidates.map(isRegexUsable));
    const addRules = [];
    for (let i = 0; i < candidates.length; i += 1) {
        if (usable[i] !== true) { continue; }
        if (addRules.length >= MAX_REGEX_RULES) {
            console.warn('[OPSECHub] Regex rule budget reached, dropping the remainder.');
            break;
        }
        const rule = { ...candidates[i], condition: { ...(candidates[i].condition || {}) } };
        rule.id = REGEX_RULE_ID_BASE + addRules.length;
        addRules.push(rule);
    }

    const existing = await brw.declarativeNetRequest.getDynamicRules();
    const removeRuleIds = existing
        .filter(r => r.id >= REGEX_RULE_ID_BASE && r.id < REGEX_RULE_ID_BASE + MAX_REGEX_RULES)
        .map(r => r.id);

    if (removeRuleIds.length === 0 && addRules.length === 0) { return; }
    try {
        await brw.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules });
        console.log(`[OPSECHub] Regex rules active: ${addRules.length} of ${candidates.length}`);
    } catch (err) {
        console.error('[OPSECHub] Failed to install regex rules:', err);
    }
}

// ═══════════════════════════════════════════════════════════════════
// REAL-TIME STORAGE & RULE MATCH LISTENERS
// ═══════════════════════════════════════════════════════════════════
brw.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local') {
        // excludedDomains matters here too: it becomes excludeMatches on the
        // registered cosmetic content scripts, not just a DNR allow rule.
        if (changes.masterSwitch || changes.enabledFilterLists || changes.moduleStates || changes.excludedDomains) {
            console.log('[OPSECHub] Storage change detected, triggering syncCoreRuleset...');
            if (changes.masterSwitch || changes.moduleStates) {
                applyNetworkFilteringGate().catch(() => { });
            }
            syncCoreRuleset().catch(err => console.error('[OPSECHub] Sync failed on storage change:', err));
        }
        if (changes.masterSwitch) {
            const isNowOn = changes.masterSwitch.newValue;
            if (isNowOn) {
                brw.action.setBadgeText({ text: '' });
                brw.action.setBadgeBackgroundColor({ color: '#4CAF50' });
            } else {
                brw.action.setBadgeText({ text: 'OFF' });
                brw.action.setBadgeBackgroundColor({ color: '#F44336' });
            }
        }
        if (changes.excludedDomains) {
            updateExclusionRules(changes.excludedDomains.newValue);
        }
    }
});

async function restoreRemoteListsIfEnabled({ force = false } = {}) {
    try {
        await refreshEnabledRemoteLists({ force });
    } catch (err) {
        console.warn('[OPSECHub] Restore remote lists skipped:', err.message || err);
    }
}

async function repairListsAfterWake() {
    try {
        await repairIncompleteRemoteLists();
    } catch (err) {
        console.warn('[OPSECHub] List repair skipped:', err?.message || err);
    }
}

// ═══════════════════════════════════════════════════════════════════
// STATE INITIALIZATION
// ═══════════════════════════════════════════════════════════════════
async function openWelcomeSetupTab() {
    const url = brw.runtime.getURL('welcome.html');
    try {
        const existing = await brw.tabs.query({ url: [
            brw.runtime.getURL('welcome.html'),
            brw.runtime.getURL('welcome.html*')
        ] });
        if (existing && existing[0]?.id != null) {
            await brw.tabs.update(existing[0].id, { active: true });
            if (existing[0].windowId != null) {
                await brw.windows?.update?.(existing[0].windowId, { focused: true });
            }
            return;
        }
    } catch { /* ignore query quirks */ }
    await brw.tabs.create({ url });
}

brw.runtime.onInstalled.addListener(async (details) => {
    console.log('[OPSECHub] Extension Installed/Updated. Reason:', details?.reason);
    const reason = details?.reason;

    // Open first-run UI early (don't wait on DNR wipe — that made welcome feel "missing").
    try {
        const setup = await brw.storage.local.get({
            setupCompleted: null,
            enabledFilterLists: null
        });

        if (reason === 'install') {
            await brw.storage.local.set({
                enabledFilterLists: [],
                setupCompleted: false,
                moduleStates: { adBlocker: false }
            });
            await openWelcomeSetupTab();
        } else if (setup.setupCompleted === false) {
            // Reload / update while setup was never finished.
            await openWelcomeSetupTab();
        } else if (setup.setupCompleted == null) {
            const lists = setup.enabledFilterLists;
            if (Array.isArray(lists) && lists.length > 0) {
                // Existing users who already had lists before this onboarding flow.
                await brw.storage.local.set({ setupCompleted: true });
            } else {
                // Fresh profile / empty lists after code update — run setup.
                await brw.storage.local.set({
                    enabledFilterLists: [],
                    setupCompleted: false
                });
                await openWelcomeSetupTab();
            }
        }
    } catch (err) {
        console.error('[OPSECHub] Failed to open welcome setup:', err);
    }

    // Must finish before syncCoreRuleset runs, otherwise it wipes the regex
    // rules that sync has just installed.
    await clearAllDynamicRules();
    // Drop legacy URL Sanitizer session rule if present from older installs.
    try {
        await brw.declarativeNetRequest.updateSessionRules({ removeRuleIds: [900005] });
    } catch { /* ignore */ }

    brw.storage.local.get({ moduleStates: {} }).then(async (data) => {
        if (Object.keys(data.moduleStates).length === 0) {
            await brw.storage.local.set({ moduleStates: {} });
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
        ensureRemoteListsAlarm();
        try {
            await refreshRemoteCatalog({ force: true });
            // Dynamic rules were wiped above — force reinstall (don't skip by revision).
            await restoreRemoteListsIfEnabled({ force: true });
        } catch (err) {
            console.warn('[OPSECHub] Remote list bootstrap failed:', err.message || err);
        }
        syncCoreRuleset().catch(err => console.error('[OPSECHub] onInstalled sync failed:', err));
    });
});

brw.runtime.onStartup?.addListener?.(() => {
    ensureRemoteListsAlarm();
    applyNetworkFilteringGate()
        .then(() => repairListsAfterWake())
        .then(() => refreshRemoteCatalog({ force: false }))
        .then(() => restoreRemoteListsIfEnabled())
        .catch(() => { });
});

// ═══════════════════════════════════════════════════════════════════
// MESSAGE HANDLER
// ═══════════════════════════════════════════════════════════════════
// css-specific.js caches its per-hostname selector lookups in session storage,
// and content scripts count as an untrusted context.
brw.storage.session?.setAccessLevel?.({
    accessLevel: 'TRUSTED_AND_UNTRUSTED_CONTEXTS',
}).catch(() => { });

brw.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if ( handleScriptingMessage(message, sender, sendResponse) ) { return true; }

    if (message.action === 'refreshRules') {
        syncCoreRuleset().then(() => {
            sendResponse({ success: true });
        }).catch(err => {
            sendResponse({ success: false, error: err.toString() });
        });
        return true;
    }

    if (message.action === 'syncFilterLists') {
        syncCoreRuleset()
            .then(() => sendResponse({ success: true }))
            .catch(err => sendResponse({ success: false, error: err.toString() }));
        return true;
    }

    if (message.action === 'toggleExclusion') {
        const { domain, exclude } = message;
        brw.storage.local.get({ excludedDomains: [] }).then(data => {
            let list = data.excludedDomains || [];
            if (exclude && !list.includes(domain)) {
                list.push(domain);
            } else if (!exclude) {
                list = list.filter(d => d !== domain);
            }
            brw.storage.local.set({ excludedDomains: list }).then(() => {
                updateExclusionRules(list);
                sendResponse({ success: true, excludedDomains: list });
            });
        });
        return true;
    }

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
        handleModuleToggle(module, enabled).then(
            (res) => sendResponse(res && typeof res === 'object'
                ? { success: res.success !== false, ...res }
                : { success: true }),
            err => sendResponse({ success: false, error: err?.message || String(err) })
        );
        return true;
    }

    if (message.action === 'toggleMaster') {
        const enabled = !!message.enabled;
        globalMasterSwitch = enabled;
        console.log('[OPSECHub] Master Switch toggled:', enabled);

        (async () => {
            try {
                await brw.storage.local.set({ masterSwitch: enabled });
                // Instant network mute/unmute (keeps list rules installed).
                await applyNetworkFilteringGate();

                brw.tabs.query({}, (tabs) => {
                    tabs.forEach((tab) => brw.tabs.sendMessage(tab.id, {
                        action: 'masterToggle',
                        enabled
                    }).catch(() => { }));
                });

                // Apply module side-effects without wiping saved preferences.
                const data = await brw.storage.local.get({ moduleStates: {} });
                const states = data.moduleStates || {};
                for (const [mod, modEnabled] of Object.entries(states)) {
                    if (!modEnabled) continue;
                    // Network/cosmetics gated by pause + syncCore; legacy threatIntel
                    // shares DNR id space with remote lists — never wipe via master.
                    if (mod === 'adBlocker' || mod === 'threatIntel') continue;
                    try {
                        await handleModuleToggle(mod, enabled);
                    } catch (err) {
                        console.warn(`[OPSECHub] Master ${enabled ? 'enable' : 'disable'} failed for ${mod}:`, err);
                    }
                }

                await syncCoreRuleset().catch(() => { });
                sendResponse({ success: true, enabled });
            } catch (err) {
                console.error('[OPSECHub] toggleMaster failed:', err);
                sendResponse({ success: false, error: err?.message || String(err) });
            }
        })();
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

    if (message.action === 'getDnrBudget') {
        getDnrBudgetSnapshot()
            .then(budget => sendResponse({ success: true, budget }))
            .catch(err => sendResponse({ success: false, error: err.message || String(err) }));
        return true;
    }

    if (message.action === 'getFilterCatalog') {
        getCatalogForUi()
            .then(data => sendResponse({ success: true, ...data }))
            .catch(err => sendResponse({ success: false, error: err.message || String(err) }));
        return true;
    }

    if (message.action === 'refreshRemoteCatalog') {
        refreshRemoteCatalog({ force: true })
            .then(res => sendResponse({ success: res.ok || !!res.catalog, ...res }))
            .catch(err => sendResponse({ success: false, error: err.message || String(err) }));
        return true;
    }

    if (message.action === 'toggleDynamicList') {
        const { listId, enabled } = message;
        setRemoteListEnabled(listId, !!enabled)
            .then(async (res) => {
                // Reply first so the UI can clear its busy spinner; cosmetics
                // sync can take longer and used to look like a hang.
                sendResponse(res);
                if (res?.success) {
                    syncCoreRuleset().catch(() => { });
                }
            })
            .catch(err => sendResponse({ success: false, error: err.message || String(err) }));
        return true;
    }

    if (message.action === 'refreshLiveLists' || message.action === 'refreshRemoteLists') {
        refreshEnabledRemoteLists()
            .then(async (res) => {
                try { await syncCoreRuleset(); } catch { /* ignore */ }
                sendResponse({
                    success: true,
                    refreshed: res.refreshed || 0,
                    skipped: res.skipped || 0,
                    failed: res.failed || 0,
                    unchanged: !!res.unchanged,
                    catalogOk: res.catalogOk,
                    builtAt: res.builtAt,
                    meta: res.meta
                });
            })
            .catch(err => sendResponse({ success: false, error: err.message || String(err) }));
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
    // Optional API perms must already be granted by the UI (user gesture).
    if (enabled) {
        const ok = await hasModuleOptionalPermissions(module);
        if (!ok) {
            console.warn(`[OPSECHub] Refusing to enable ${module}: optional permission missing`);
            return { success: false, error: 'permission_required', code: 'permission_required' };
        }
    }

    switch (module) {
        case 'adBlocker':
            {
                try {
                    const data = await brw.storage.local.get({
                        moduleStates: {},
                        enabledFilterLists: [],
                        threatFeeds: {}
                    });
                    const states = data.moduleStates || {};

                    if (enabled) {
                        const hasLists = (data.enabledFilterLists || []).length > 0
                            || Object.values(data.threatFeeds || {}).some(Boolean);
                        if (!hasLists) {
                            states.adBlocker = false;
                            await brw.storage.local.set({ moduleStates: states });
                            return {
                                success: false,
                                code: 'needs_lists',
                                error: 'Select at least one filter list before turning AdBlocker on.'
                            };
                        }
                    }

                    states.adBlocker = enabled;
                    await brw.storage.local.set({ moduleStates: states });

                    if (!enabled) {
                        // Instant pause: keep installed list rules + cache; override
                        // with a high-priority session allow (like other blockers).
                        // Cosmetics/regex: storage.onChanged → syncCoreRuleset (don't block UI).
                        await applyNetworkFilteringGate();
                        return { success: true, paused: true };
                    }

                    // Unpause network immediately. Only block the UI on a real restore
                    // (first enable / lists chosen while AdBlocker was off).
                    await applyNetworkFilteringGate();
                    const needsRestore = await needsRemoteListRestore();
                    if (!needsRestore) {
                        return { success: true, resumed: true, refreshed: 0, skipped: 0, failed: 0, total: 0 };
                    }

                    const restored = await refreshEnabledRemoteLists({ force: true });
                    // New lists may need cosmetics/regex — kick sync, don't make toggle wait.
                    syncCoreRuleset().catch(() => { });
                    return {
                        success: true,
                        refreshed: restored?.refreshed || 0,
                        skipped: restored?.skipped || 0,
                        failed: restored?.failed || 0,
                        total: (restored?.refreshed || 0)
                            + (restored?.skipped || 0)
                            + (restored?.failed || 0)
                    };
                } catch (e) {
                    console.error('[OPSECHub] adBlocker toggle failed:', e);
                    return { success: false, error: e?.message || String(e) };
                }
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
        case 'googleTelemetry':
            await googleTelemetryModule.toggle(enabled);
            break;
        case 'privacyHeaders':
            await privacyHeadersModule.toggle(enabled);
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

// Pack many domains into few DNR rules (same idea as static HaGeZi compression).
const DYNAMIC_DOMAIN_CHUNK = 4000;
const DYNAMIC_RESOURCE_TYPES = [
    'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font',
    'object', 'xmlhttprequest', 'ping', 'websocket', 'media', 'other'
];
const RE_BARE_DOMAIN = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

function extractSimpleDomain(line) {
    let s = line.trim();
    if (!s || s.startsWith('!') || s.startsWith('[') || s.includes('##') || s.includes('#@#')) {
        return null;
    }
    if (s.startsWith('@@')) return null; // exceptions stripped for security
    if (/^(0\.0\.0\.0|127\.0\.0\.1)\s+/.test(s)) {
        s = s.replace(/^(0\.0\.0\.0|127\.0\.0\.1)\s+/, '').trim().split(/\s+/)[0];
    }
    // ||domain^ or ||domain^$all — still a simple domain block
    let m = s.match(/^\|\|([a-z0-9.-]+)\^(\$[^,]*)?$/i);
    if (m && RE_BARE_DOMAIN.test(m[1])) return m[1].toLowerCase();
    if (s.includes('$') || s.includes('*') || s.includes('/') || s.includes('|')) return null;
    if (RE_BARE_DOMAIN.test(s)) return s.toLowerCase();
    return null;
}

async function toggleDynamicRuleset(listId, url, enabled) {
    const baseId = DYNAMIC_LIST_BASE_IDS[listId];
    if (!baseId) return { success: false, error: 'Unknown dynamic list ID' };

    try {
        const existingRules = await brw.declarativeNetRequest.getDynamicRules();
        const removeRuleIds = existingRules
            .map(r => r.id)
            .filter(id => id >= baseId && id < baseId + 99999);

        let addRules = [];
        let domainCount = 0;

        if (enabled) {
            console.log(`[OPSECHub] Fetching dynamic rules for ${listId} from ${url}...`);
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const text = await response.text();

            const domains = new Set();
            const complexLines = [];

            for (let line of text.split('\n')) {
                line = line.trim();
                if (!line || line.startsWith('!') || line.startsWith('[')) continue;
                if (line.startsWith('@@')) {
                    console.warn(`[OPSECHub] Stripped exception rule from external feed ${listId}: ${line}`);
                    continue;
                }
                if (line.includes('##') || line.includes('#@#')) continue;

                const domain = extractSimpleDomain(line);
                if (domain) {
                    domains.add(domain);
                    continue;
                }

                // Fallback: keep non-trivial filters as individual urlFilter rules
                let urlFilter = line;
                const condition = { resourceTypes: [...DYNAMIC_RESOURCE_TYPES] };
                if (urlFilter.includes('$')) {
                    const parts = urlFilter.split('$');
                    urlFilter = parts[0];
                    // ignore exotic modifiers for live domain feeds — most HaGeZi lines are simple
                }
                if (/^(0\.0\.0\.0|127\.0\.0\.1)\s+/.test(urlFilter)) {
                    urlFilter = urlFilter.replace(/^(0\.0\.0\.0|127\.0\.0\.1)\s+/, '').trim();
                }
                if (!urlFilter.startsWith('||') && !urlFilter.startsWith('*') && !urlFilter.startsWith('/') && /^[a-zA-Z0-9.-]+$/.test(urlFilter)) {
                    urlFilter = `||${urlFilter}^`;
                }
                if (!urlFilter || /[^\x00-\x7F]/.test(urlFilter) || urlFilter.includes(' ')) continue;
                condition.urlFilter = urlFilter;
                complexLines.push(condition);
            }

            domainCount = domains.size;
            const domainList = Array.from(domains);
            let ruleId = baseId;

            for (let i = 0; i < domainList.length; i += DYNAMIC_DOMAIN_CHUNK) {
                const chunk = domainList.slice(i, i + DYNAMIC_DOMAIN_CHUNK);
                addRules.push({
                    id: ruleId++,
                    priority: 100,
                    action: { type: 'block' },
                    condition: {
                        requestDomains: chunk,
                        resourceTypes: [...DYNAMIC_RESOURCE_TYPES]
                    }
                });
            }

            for (const condition of complexLines) {
                if (addRules.length >= 500) break; // hard cap for leftover complex rules
                addRules.push({
                    id: ruleId++,
                    priority: 100,
                    action: { type: 'block' },
                    condition
                });
            }

            console.log(
                `[OPSECHub] Compressed ${listId}: ${domainCount} domains + ${complexLines.length} complex` +
                ` → ${addRules.length} DNR rules`
            );

            if (domainList.length > 0) {
                const pick = domainList[Math.floor(Math.random() * domainList.length)];
                const d = await brw.storage.local.get({ threatTestDomains: {} });
                const testDomains = d.threatTestDomains || {};
                testDomains[listId] = pick;
                await brw.storage.local.set({ threatTestDomains: testDomains });
            }
        }

        await brw.declarativeNetRequest.updateDynamicRules({
            removeRuleIds,
            addRules
        });

        const meta = await brw.storage.local.get({ liveListMeta: {} });
        const liveListMeta = meta.liveListMeta || {};
        if (enabled) {
            liveListMeta[listId] = {
                updatedAt: new Date().toISOString(),
                domains: domainCount,
                rules: addRules.length,
                url
            };
        } else {
            delete liveListMeta[listId];
        }
        await brw.storage.local.set({ liveListMeta });

        console.log(`[OPSECHub] Dynamic ruleset ${listId} ${enabled ? 'ENABLED' : 'DISABLED'}`);
        return {
            success: true,
            count: addRules.length,
            domains: domainCount,
            updatedAt: enabled ? new Date().toISOString() : null
        };
    } catch (err) {
        console.error(`[OPSECHub] Dynamic Ruleset Error (${listId}):`, err);
        return { success: false, error: err.message };
    }
}

async function refreshEnabledLiveLists() {
    const d = await brw.storage.local.get({
        masterSwitch: true,
        moduleStates: {},
        threatFeeds: {},
        threatCounts: {},
    });
    if (d.masterSwitch === false || d.moduleStates.adBlocker === false) {
        return { success: true, refreshed: 0 };
    }
    const feeds = d.threatFeeds || {};
    const counts = d.threatCounts || {};
    let refreshed = 0;
    try {
        const res = await fetch(brw.runtime.getURL('rules/Malware_Phishing_Threat_Intelligence/Threat_list.json'));
        if (!res.ok) return { success: false, error: 'catalog missing' };
        const listData = await res.json();
        for (const entry of listData.entries) {
            if (!feeds[entry.id]) continue;
            const toggleRes = await toggleDynamicRuleset(entry.id, entry.url, true);
            if (toggleRes?.success) {
                counts[entry.id] = toggleRes.count;
                refreshed += 1;
            }
        }
        await brw.storage.local.set({
            threatCounts: counts,
            liveListsLastSync: new Date().toISOString()
        });
        return { success: true, refreshed };
    } catch (e) {
        console.warn('[OPSECHub] Live list refresh failed:', e);
        return { success: false, error: e.message };
    }
}

function ensureLiveListsAlarm() {
    ensureRemoteListsAlarm();
}

if (brw.alarms?.onAlarm) {
    brw.alarms.onAlarm.addListener((alarm) => {
        if (alarm.name === 'refreshLiveLists' || alarm.name === 'refreshRemoteLists') {
            refreshEnabledRemoteLists()
                .then(async () => {
                    try { await syncCoreRuleset(); } catch { /* ignore */ }
                })
                .catch(err =>
                    console.warn('[OPSECHub] Scheduled remote refresh failed:', err)
                );
        }
    });
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

// Stats only (declarativeNetRequestFeedback). Never log request URLs.
if (brw.declarativeNetRequest && brw.declarativeNetRequest.onRuleMatchedDebug) {
    brw.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
        const ruleId = info.rule?.ruleId;
        if (ruleId == null) return;

        // Exclusion, pause gate, header mods, session marker — not block counters.
        if (
            ruleId === 999999
            || ruleId === 998000
            || ruleId === 900002
            || ruleId === 900003
            || ruleId === 999000
        ) {
            return;
        }

        brw.storage.local.get({ opsecStats: { adsBlocked: 0, threatsBlocked: 0 } }).then((data) => {
            const stats = data.opsecStats || { adsBlocked: 0, threatsBlocked: 0 };

            // Legacy live-threat id bands (100k–500k). Remote filter lists share
            // this space too — both count toward protection metrics.
            if (ruleId >= 100000 && ruleId < 500000) {
                stats.threatsBlocked = (stats.threatsBlocked || 0) + 1;
            } else {
                stats.adsBlocked = (stats.adsBlocked || 0) + 1;
            }

            brw.storage.local.set({ opsecStats: stats });
        });
    });
}

// If the user revokes an optional permission in chrome://extensions, turn those tools off
// (toggles stay available so they can re-enable and grant again).
if (brw.permissions?.onRemoved) {
    brw.permissions.onRemoved.addListener(async (removed) => {
        const affected = new Set();
        for (const p of removed.permissions || []) {
            for (const id of modulesNeedingPermission(p)) affected.add(id);
        }
        if (affected.size === 0) return;
        const data = await brw.storage.local.get({ moduleStates: {} });
        const states = { ...(data.moduleStates || {}) };
        let changed = false;
        for (const id of affected) {
            if (states[id]) {
                states[id] = false;
                changed = true;
                try { await handleModuleToggle(id, false); } catch { /* ignore */ }
            }
        }
        if (changed) {
            await brw.storage.local.set({ moduleStates: states });
            console.log('[OPSECHub] Disabled modules after permission revoke:', [...affected]);
        }
    });
}


