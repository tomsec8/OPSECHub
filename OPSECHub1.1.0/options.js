/**
 * OPSECHub – Extra Tools Controller
 */

const brw = typeof browser !== 'undefined' ? browser : chrome;

// Defaults match lists_config.json `enabled: true`. Network rules are remote dynamic only.
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

// The ad blocker and threat intel ship on, so an absent entry means enabled.
// Every other module is opt-in. background.js applies the same rule, and both
// the popup and the options page must agree with it or their toggles drift apart.
function isModuleEnabled(states, module) {
    if (module === 'adBlocker' || module === 'threatIntel') {
        return (states || {})[module] !== false;
    }
    return !!(states || {})[module];
}

// Counts what is live right now: the lists the user has enabled, using the
// figures tools/build-rules.mjs recorded for each of them.
async function activeRulesetStats() {
    const d = await brw.storage.local.get({
        masterSwitch: true,
        moduleStates: {},
        enabledFilterLists: defaultFilterLists(),
        threatCounts: {},
        threatFeeds: {},
        remoteManagedLists: {},
    });

    const res = await fetch(brw.runtime.getURL('rules/lists_config.json'));
    const config = await res.json();
    const builtAt = config.builtAt || null;

    if (d.masterSwitch === false || isModuleEnabled(d.moduleStates, 'adBlocker') === false) {
        return { enabled: false, rules: 0, lists: 0, cosmetic: 0, live: 0, builtAt };
    }

    const active = new Set(d.enabledFilterLists || []);
    const counts = d.threatCounts || {};
    const feeds = d.threatFeeds || {};

    let rules = 0, dynamic = 0, lists = 0, cosmetic = 0;
    for (const cat of Object.values(config.categories || {})) {
        for (const [id, info] of Object.entries(cat.lists || {})) {
            if (active.has(id) === false) continue;
            const s = info.stats || {};
            lists += 1;
            if ((s.css?.specific || 0) !== 0 || (s.css?.generic || 0) !== 0) cosmetic += 1;
            dynamic += counts[id] || s.compressed || 0;
        }
    }

    for (const id of Object.keys(feeds)) {
        if (!feeds[id]) continue;
        if (active.has(id)) continue;
        dynamic += counts[id] || 0;
        lists += 1;
    }

    return { enabled: true, rules, lists, cosmetic, live: dynamic, builtAt };
}

function formatBuiltAt(iso) {
    if (!iso) return null;
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return null;
    return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
}

async function updateShieldMetaInfo(elementId) {
    const infoEl = document.getElementById(elementId);
    if (!infoEl) return;
    try {
        const stats = await activeRulesetStats();
        const when = formatBuiltAt(stats.builtAt);
        const updatedLine = when
            ? `<div style="margin-top:4px;opacity:0.85;">Updated ${when}</div>`
            : '';
        if (stats.enabled === false) {
            infoEl.innerHTML =
                '🛡️ AdBlocker is currently <strong>disabled</strong>.' + updatedLine;
            return;
        }
        infoEl.innerHTML =
            `🛡️ <strong>${(stats.live || 0).toLocaleString()}</strong> dynamic rules` +
            ` across <strong>${stats.lists}</strong> lists` +
            (stats.cosmetic !== 0 ? `, plus cosmetic filters on ${stats.cosmetic} of them` : '') +
            updatedLine;
    } catch (_) {
        infoEl.textContent = '';
    }
}

function escapeHtml(str) {
    if (!str) return '';
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

document.addEventListener('DOMContentLoaded', () => {
    initSidebar();
    initSettings();
    initDnsGuide();
    initThreatIntel();
    initThreatDiagnostics();
    initExtraTools();
});

function initThreatIntel() {
    // Live threat feeds are checkboxes under AdBlocker filter lists.
}

function initSidebar() {
    const topTabs = document.querySelectorAll('.top-tab');
    const sidebarTabs = document.querySelectorAll('.sidebar-tab');
    const panels = document.querySelectorAll('.opt-panel');

    // Handle Top Tab Clicks
    topTabs.forEach(topTab => {
        topTab.addEventListener('click', () => {
            const topCat = topTab.dataset.topcat; // e.g., 'security'
            brw.storage.local.set({ activeOptionsTopTab: topCat }); // Save state

            // 1. Set active Top Tab
            topTabs.forEach(t => t.classList.remove('active'));
            topTab.classList.add('active');

            // 2. Filter Sidebar Tabs
            let firstVisibleSidebarTab = null;
            sidebarTabs.forEach(sideTab => {
                if (sideTab.dataset.category === topCat) {
                    sideTab.classList.add('show');
                    if (!firstVisibleSidebarTab && sideTab.dataset.tab) firstVisibleSidebarTab = sideTab;
                } else {
                    sideTab.classList.remove('show');
                }
            });

            // 3. Auto-click the first visible sidebar tab
            if (firstVisibleSidebarTab) {
                firstVisibleSidebarTab.click();
            }
        });
    });

    // Handle Sidebar Tab Clicks
    sidebarTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.tab;
            if (target) brw.storage.local.set({ activeOptionsSidebarTab: target }); // Save state

            sidebarTabs.forEach(t => t.classList.remove('active'));
            panels.forEach(p => p.classList.remove('active'));

            tab.classList.add('active');
            const panel = document.getElementById(`tab-${target}`);
            if (panel) {
                panel.classList.add('active');
            } else {
                console.error('[OPSECHub] Panel not found:', `tab-${target}`);
            }
        });
    });

    // Deep-link from popup: ?cat=tools&tool=opt-tool-...
    const params = new URLSearchParams(window.location.search);
    const deepCat = params.get('cat');
    const deepTool = params.get('tool');
    if (params.get('setup') === 'true') {
        const guideTopTab = document.querySelector('.top-tab[data-topcat="guides"]');
        if (guideTopTab) {
            guideTopTab.click();
            const guideSidebarTab = document.querySelector('.sidebar-tab[data-tab="opt-guide-setup"]');
            if (guideSidebarTab) guideSidebarTab.click();
        }
    } else if (deepCat) {
        const deepTopTab = document.querySelector(`.top-tab[data-topcat="${deepCat}"]`);
        if (deepTopTab) {
            deepTopTab.click();
            if (deepTool) {
                setTimeout(() => {
                    const deepSidebarTab = document.querySelector(`.sidebar-tab[data-tab="${deepTool}"]`);
                    if (deepSidebarTab) deepSidebarTab.click();
                }, 50);
            }
        }
    } else {
        // Load saved state
        brw.storage.local.get(['activeOptionsTopTab', 'activeOptionsSidebarTab'], (res) => {
            if (res.activeOptionsTopTab) {
                const savedTopTab = document.querySelector(`.top-tab[data-topcat="${res.activeOptionsTopTab}"]`);
                if (savedTopTab) {
                    savedTopTab.click(); // This will auto-click the first sidebar tab of that category

                    // Override with specific saved sidebar tab if it matches the category
                    if (res.activeOptionsSidebarTab) {
                        setTimeout(() => {
                            const savedSidebarTab = document.querySelector(`.sidebar-tab[data-tab="${res.activeOptionsSidebarTab}"]`);
                            if (savedSidebarTab && savedSidebarTab.dataset.category === res.activeOptionsTopTab) {
                                savedSidebarTab.click();
                            }
                        }, 50); // slight delay to let topTab click finish updating DOM
                    }
                    return;
                }
            }
            // Fallback: Click first top tab if no state is saved
            if (topTabs.length > 0 && !document.querySelector('.top-tab.active')) {
                topTabs[0].click();
            }
        });
    }
}


function initSettings() {
    brw.storage.local.get({ excludedDomains: [], moduleStates: {}, activeProxy: null, customProxies: [] }).then(data => {

        async function runRemoteListsRefresh({ triggerBtn = null } = {}) {
            const { showFilterBusy, updateFilterBusy, hideFilterBusy, bindFilterBusyProgress } = await import(
                brw.runtime.getURL('js/filter-busy-ui.mjs')
            );
            const refreshLiveOpt = document.getElementById('btn-refresh-live-lists-opt');
            const labelEl = refreshLiveOpt?.querySelector('.filter-refresh-label');
            const listsEl = document.getElementById('advanced-filter-lists-container-opt');
            const originalGlobal = triggerBtn ? triggerBtn.innerHTML : null;
            let unbindProgress = () => { };

            if (triggerBtn) {
                triggerBtn.disabled = true;
                triggerBtn.innerHTML = '⏳ Refreshing…';
            }
            if (refreshLiveOpt) {
                refreshLiveOpt.disabled = true;
                refreshLiveOpt.classList.add('is-refreshing');
                if (labelEl) labelEl.textContent = 'Refreshing…';
            }
            if (listsEl) {
                listsEl.style.opacity = '0.55';
                listsEl.style.pointerEvents = 'none';
            }
            showFilterBusy(
                'Refreshing from Git…',
                'Checking the catalog and updating enabled lists if needed.'
            );
            unbindProgress = bindFilterBusyProgress();

            try {
                const res = await brw.runtime.sendMessage({ action: 'refreshRemoteLists' });
                const info = document.getElementById('live-lists-sync-info-opt');
                if (info) {
                    info.textContent = res && res.success
                        ? ('Catalog synced' +
                            (res.builtAt ? ' · ' + new Date(res.builtAt).toLocaleString() : '') +
                            (res.unchanged
                                ? ' · up to date (no list re-download)'
                                : (' · updated ' + (res.refreshed || 0) +
                                    (res.skipped ? (', skipped ' + res.skipped) : ''))))
                        : ('Refresh failed: ' + ((res && res.error) || 'unknown'));
                }
                updateFilterBusy(
                    res && res.success ? (res.unchanged ? 'Up to date' : 'Done') : 'Refresh failed',
                    res && res.success
                        ? (res.unchanged ? 'Nothing new to download.' : 'Reloading list UI…')
                        : ((res && res.error) || 'Check the console / network.')
                );
                if (filtersContainerOpt) await initAdvancedFiltersOpt(filtersContainerOpt);
                if (triggerBtn && res && res.success) {
                    triggerBtn.innerHTML = '✓ Synchronized!';
                }
                return res;
            } catch (err) {
                console.error(err);
                updateFilterBusy('Refresh failed', 'Check the console / network.');
                return { success: false, error: String(err) };
            } finally {
                unbindProgress();
                if (refreshLiveOpt) {
                    refreshLiveOpt.disabled = false;
                    refreshLiveOpt.classList.remove('is-refreshing');
                    if (labelEl) labelEl.textContent = 'Refresh';
                }
                if (listsEl) {
                    listsEl.style.opacity = '';
                    listsEl.style.pointerEvents = '';
                }
                hideFilterBusy(700);
                if (triggerBtn) {
                    setTimeout(() => {
                        triggerBtn.disabled = false;
                        if (originalGlobal) triggerBtn.innerHTML = originalGlobal;
                    }, 700);
                }
            }
        }

        // Init toggles
        document.querySelectorAll('.opt-module-toggle').forEach(toggle => {
            const module = toggle.getAttribute('data-module');
            toggle.checked = isModuleEnabled(data.moduleStates, module);

            toggle.addEventListener('change', async (e) => {
                const enabled = e.target.checked;

                if (module === 'adBlocker') {
                    if (enabled) {
                        const sel = await brw.storage.local.get({
                            enabledFilterLists: [],
                            threatFeeds: {}
                        });
                        const hasLists = (sel.enabledFilterLists || []).length > 0
                            || Object.values(sel.threatFeeds || {}).some(Boolean);
                        if (!hasLists) {
                            e.target.checked = false;
                            alert('Select at least one filter list before turning AdBlocker on.');
                            return;
                        }
                        toggle.disabled = true;
                        let unbindProgress = () => { };
                        let hideBusy = null;
                        try {
                            const responsePromise = brw.runtime.sendMessage({
                                action: 'toggleModule',
                                module: 'adBlocker',
                                enabled: true
                            });
                            // Modal only if restore/download actually takes time.
                            const slowTimer = setTimeout(() => {
                                import(brw.runtime.getURL('js/filter-busy-ui.mjs')).then((ui) => {
                                    ui.showFilterBusy(
                                        'Turning AdBlocker on…',
                                        'Downloading / restoring filter lists…'
                                    );
                                    unbindProgress = ui.bindFilterBusyProgress();
                                    hideBusy = ui.hideFilterBusy;
                                }).catch(() => { });
                            }, 180);

                            const response = await responsePromise;
                            clearTimeout(slowTimer);

                            if (!response || response.success === false) {
                                e.target.checked = false;
                                if (hideBusy) {
                                    const { updateFilterBusy } = await import(
                                        brw.runtime.getURL('js/filter-busy-ui.mjs')
                                    );
                                    updateFilterBusy(
                                        'Could not enable AdBlocker',
                                        response?.error || 'Try again.'
                                    );
                                    hideBusy(1200);
                                } else {
                                    alert(response?.error || 'Could not enable AdBlocker');
                                }
                            } else {
                                if (hideBusy && !response.resumed) {
                                    const { updateFilterBusy } = await import(
                                        brw.runtime.getURL('js/filter-busy-ui.mjs')
                                    );
                                    const loaded = (response.refreshed || 0) + (response.skipped || 0);
                                    const total = response.total || loaded;
                                    updateFilterBusy(
                                        'AdBlocker is on',
                                        total
                                            ? `Loaded ${loaded} / ${total} list(s).`
                                            : 'Selected lists are active.'
                                    );
                                    hideBusy(600);
                                } else if (hideBusy) {
                                    hideBusy(0);
                                }
                                if (filtersContainerOpt) await initAdvancedFiltersOpt(filtersContainerOpt);
                            }
                        } catch (err) {
                            console.error(err);
                            e.target.checked = false;
                        } finally {
                            unbindProgress();
                            toggle.disabled = false;
                            updateShieldMetaInfo('opt-shield-mode-info');
                        }
                        return;
                    }

                    // Instant pause — keep list rules installed.
                    toggle.disabled = true;
                    try {
                        await brw.runtime.sendMessage({
                            action: 'toggleModule',
                            module: 'adBlocker',
                            enabled: false
                        });
                    } finally {
                        toggle.disabled = false;
                        updateShieldMetaInfo('opt-shield-mode-info');
                    }
                    return;
                }

                if (enabled && module !== 'threatIntel') {
                    try {
                        const { ensureModulePermissions, showPermToast } = await import(
                            brw.runtime.getURL('js/optional-permissions.mjs')
                        );
                        const result = await ensureModulePermissions(module);
                        if (!result.granted) {
                            e.target.checked = false;
                            showPermToast(
                                result.cancelled
                                    ? 'Permission not granted — tool stays off. You can try again anytime.'
                                    : 'Chrome permission declined — tool stays off. Toggle it on again to retry.',
                                { isError: true }
                            );
                            return;
                        }
                    } catch (err) {
                        console.error(err);
                        e.target.checked = false;
                        return;
                    }
                }
                const st = await brw.storage.local.get({ moduleStates: {} });
                const states = st.moduleStates || {};
                states[module] = enabled;
                await brw.storage.local.set({ moduleStates: states });
                brw.runtime.sendMessage({ action: 'toggleModule', module, enabled });
            });
        });

        updateShieldMetaInfo('opt-shield-mode-info');

        const filtersContainerOpt = document.getElementById('advanced-filter-lists-container-opt');
        if (filtersContainerOpt) {
            initAdvancedFiltersOpt(filtersContainerOpt);
        }

        const refreshLiveOpt = document.getElementById('btn-refresh-live-lists-opt');
        if (refreshLiveOpt) {
            refreshLiveOpt.addEventListener('click', () => runRemoteListsRefresh());
        }

        const btnGlobalRefreshEarly = document.getElementById('btn-global-refresh');
        if (btnGlobalRefreshEarly) {
            btnGlobalRefreshEarly.addEventListener('click', () => {
                runRemoteListsRefresh({ triggerBtn: btnGlobalRefreshEarly });
            });
        }

        async function initAdvancedFiltersOpt(container) {
            try {
                const catRes = await brw.runtime.sendMessage({ action: 'getFilterCatalog' });
                let config;
                let enabledRulesets = [];
                let threatFeeds = {};
                let threatCounts = {};
                let liveListMeta = {};

                const remoteManaged = (catRes && catRes.remoteManagedLists) || {};
                const maxDynamic = (catRes && catRes.maxDynamicRules) || 30000;
                const maxRegex = (catRes && catRes.maxRegexRules) || 1000;
                const budgetLive = (catRes && catRes.budget) || null;

                if (catRes && catRes.success && catRes.catalog) {
                    const catalog = catRes.catalog;
                    enabledRulesets = catRes.enabledFilterLists || [];
                    threatFeeds = catRes.threatFeeds || {};
                    threatCounts = catRes.threatCounts || {};
                    liveListMeta = catRes.liveListMeta || {};
                    config = { builtAt: catalog.builtAt, categories: {} };
                    for (const list of catalog.lists || []) {
                        // Domain/live feeds are rendered in the dedicated section below.
                        if (list.type === 'domain') continue;
                        const catKey = list.category || 'other';
                        if (!config.categories[catKey]) {
                            config.categories[catKey] = {
                                label: (catalog.categories && catalog.categories[catKey]?.label) || catKey,
                                lists: {}
                            };
                        }
                        config.categories[catKey].lists[list.id] = {
                            name: list.name,
                            stats: list.stats || null,
                            exclusiveGroup: list.exclusiveGroup || null,
                            enabled: list.enabledByDefault,
                            bundledStatic: list.bundledStatic === true
                        };
                    }
                    const syncInfo = document.getElementById('live-lists-sync-info-opt');
                    if (syncInfo) {
                        const meta = catRes.meta || {};
                        syncInfo.textContent = catRes.lastSync
                            ? ('Last sync: ' + new Date(catRes.lastSync).toLocaleString() +
                                (meta.ok === false ? ' · using cache' : ''))
                            : ('Catalog source: ' + (meta.source || 'local'));
                    }
                } else {
                    const res = await fetch(brw.runtime.getURL('rules/lists_config.json'));
                    config = await res.json();
                    const storageData = await brw.storage.local.get({ enabledFilterLists: defaultFilterLists() });
                    enabledRulesets = storageData.enabledFilterLists;
                }

                container.innerHTML = '';

                const legend = document.createElement('div');
                legend.className = 'filter-legend-opt';
                legend.innerHTML =
                    '<strong>What the numbers mean</strong><br>' +
                    '<strong>Catalog</strong> — list names &amp; categories from Git (refresh / every ~24h).<br>' +
                    '<strong>Enable a list</strong> — downloads its dynamic DNR rules (+ cosmetics for full lists).<br>' +
                    '<strong>AdBlocker off</strong> — checkmarks still save your selection, but rules are not installed until AdBlocker is on.<br>' +
                    '<strong>Refresh / 24h</strong> — catalog check; re-downloads enabled lists only if their version changed.<br>' +
                    '<strong>Budget</strong> — Chrome dynamic DNR ~30k shared across all enabled lists.';
                container.appendChild(legend);

                const listControls = new Map();
                const MAX_DYNAMIC = maxDynamic;
                const MAX_REGEX = maxRegex;
                const FILTER_BUDGET = Math.max(0, MAX_DYNAMIC - 64);

                const statusDiv = document.createElement('div');
                statusDiv.className = 'filter-status-bar-opt';

                const busyOverlay = document.createElement('div');
                busyOverlay.className = 'filter-busy-opt';
                busyOverlay.setAttribute('aria-live', 'polite');
                busyOverlay.innerHTML =
                    '<div class="filter-busy-modal">' +
                    '<div class="filter-busy-card">' +
                    '<div class="filter-busy-inner">' +
                    '<span class="filter-spinner" aria-hidden="true"></span>' +
                    '<span class="filter-busy-text">Applying filter lists…</span>' +
                    '<span class="filter-busy-sub">Please wait — large lists can take a moment.</span>' +
                    '</div></div></div>';

                const setBusyMessage = (msg, sub) => {
                    const textEl = busyOverlay.querySelector('.filter-busy-text');
                    const subEl = busyOverlay.querySelector('.filter-busy-sub');
                    if (textEl) textEl.textContent = msg;
                    if (subEl && sub != null) subEl.textContent = sub;
                };

                const setListsBusy = (busy) => {
                    busyOverlay.style.display = busy ? 'block' : 'none';
                    // Keep modal on document.body so it centers the viewport.
                    if (busy && busyOverlay.parentElement !== document.body) {
                        document.body.appendChild(busyOverlay);
                    }
                    for (const ctrl of listControls.values()) {
                        ctrl.checkbox.disabled = busy;
                        ctrl.checkbox.style.cursor = busy ? 'wait' : 'pointer';
                    }
                    container.style.opacity = busy ? '0.55' : '1';
                    container.style.pointerEvents = busy ? 'none' : '';
                };

                const withTimeout = (promise, ms, label) => Promise.race([
                    promise,
                    new Promise((_, reject) => {
                        setTimeout(() => reject(new Error(`${label} timed out after ${Math.round(ms / 1000)}s`)), ms);
                    })
                ]);

                const updateStatusUI = () => {
                    let dynamic = 0, regex = 0, lists = 0;
                    for (const ctrl of listControls.values()) {
                        if (!ctrl.checkbox.checked) continue;
                        lists += 1;
                        dynamic += ctrl.ruleCount || 0;
                        regex += ctrl.regexCount || 0;
                    }
                    const dynFree = Math.max(0, FILTER_BUDGET - dynamic);
                    const rxFree = Math.max(0, MAX_REGEX - regex);
                    const pct = Math.min(100, (dynamic / Math.max(1, FILTER_BUDGET)) * 100);
                    const over = dynamic > FILTER_BUDGET || regex > MAX_REGEX;
                    statusDiv.innerHTML =
                        `Dynamic: <strong>${dynamic.toLocaleString()}</strong> / ${FILTER_BUDGET.toLocaleString()}` +
                        ` <span style="opacity:0.85;">(${pct.toFixed(1)}% · ${dynFree.toLocaleString()} free)</span>` +
                        `<div style="margin-top:3px;opacity:0.9;">` +
                        `Regex: <strong>${regex.toLocaleString()}</strong> / ${MAX_REGEX.toLocaleString()}` +
                        ` <span style="opacity:0.85;">(${rxFree.toLocaleString()} free)</span> · ${lists} lists` +
                        (budgetLive ? ` · Chrome live: ${budgetLive.filterListRules}/${budgetLive.regex} rx` : '') +
                        `</div>`;
                    statusDiv.style.color = over ? '#ff5252'
                        : (dynamic > FILTER_BUDGET * 0.9 || regex > MAX_REGEX * 0.9 ? '#ff9800' : '#00e5ff');
                };

                const wouldExceedLocal = (listId, addRules, addRegex) => {
                    let dynamic = 0, regex = 0;
                    for (const [id, ctrl] of listControls) {
                        if (id === listId) continue;
                        if (!ctrl.checkbox.checked) continue;
                        dynamic += ctrl.ruleCount || 0;
                        regex += ctrl.regexCount || 0;
                    }
                    if (dynamic + addRules > FILTER_BUDGET) {
                        return `Dynamic DNR budget exceeded (${(dynamic + addRules).toLocaleString()} / ${FILTER_BUDGET.toLocaleString()}). Disable other lists first.`;
                    }
                    if (regex + addRegex > MAX_REGEX) {
                        return `Regex budget exceeded (${(regex + addRegex).toLocaleString()} / ${MAX_REGEX.toLocaleString()}). Disable other regex-heavy lists.`;
                    }
                    return null;
                };

                const formatListStats = (stats, extra = '') => {
                    if (!stats && !extra) return '';
                    if (!stats) {
                        return ` <span style="color:#78909c; font-size:11px; margin-left:6px;">(${extra})</span>`;
                    }
                    const cosmetic = (stats.css?.specific || 0) + (stats.css?.generic || 0);
                    const scriptlets = stats.scriptlets || 0;
                    return ` <span style="color:#78909c; font-size:11px; margin-left:6px;">` +
                        `(Original: ${Number(stats.original || 0).toLocaleString()}, ` +
                        `Compressed: ${Number(stats.compressed || 0).toLocaleString()}, ` +
                        `Cosmetic: ${cosmetic.toLocaleString()}` +
                        (scriptlets ? `, Scriptlets: ${scriptlets.toLocaleString()}` : '') +
                        (extra ? `, ${extra}` : '') +
                        `)</span>`;
                };

                const makeCategory = (label, openByDefault = false) => {
                    const catEl = document.createElement('div');
                    catEl.className = 'filter-cat-opt' + (openByDefault ? ' open' : '');
                    const header = document.createElement('button');
                    header.type = 'button';
                    header.className = 'filter-cat-header-opt';
                    header.innerHTML = `<span>${label}</span><span class="filter-cat-chevron-opt">▾</span>`;
                    header.addEventListener('click', () => catEl.classList.toggle('open'));
                    const body = document.createElement('div');
                    body.className = 'filter-cat-body-opt';
                    catEl.appendChild(header);
                    catEl.appendChild(body);
                    return { catEl, body };
                };

                const catKeys = Object.keys(config.categories);
                catKeys.forEach((catKey, idx) => {
                    const catData = config.categories[catKey];
                    const { catEl, body } = makeCategory(catData.label, idx === 0);

                    for (const listId of Object.keys(catData.lists)) {
                        const listInfo = catData.lists[listId];
                        if (listInfo.live || listInfo.type === 'domain') continue;
                        const isEnabled = enabledRulesets.includes(listId);
                        const stats = listInfo.stats || {};
                        const isRemote = !!remoteManaged[listId];
                        const ruleCount = isRemote
                            ? (threatCounts[listId] || stats.compressed || 0)
                            : (stats.compressed || 0);
                        const originalCount = stats.original || 0;
                        const cosmeticCount = (stats.css?.specific || 0) + (stats.css?.generic || 0);
                        const regexCount = Number(stats.regex) || 0;

                        const row = document.createElement('label');
                        row.className = 'filter-row-opt';

                        const cb = document.createElement('input');
                        cb.type = 'checkbox';
                        cb.checked = isEnabled;
                        listControls.set(listId, {
                            checkbox: cb,
                            ruleCount,
                            regexCount,
                            originalCount,
                            cosmeticCount,
                            exclusiveGroup: listInfo.exclusiveGroup || null,
                            live: false,
                            remote: isRemote
                        });

                        cb.addEventListener('change', async (e) => {
                            const checked = e.target.checked;
                            if (checked) {
                                const blockMsg = wouldExceedLocal(listId, ruleCount, regexCount);
                                if (blockMsg) {
                                    e.target.checked = false;
                                    alert(blockMsg);
                                    updateStatusUI();
                                    return;
                                }
                            }
                            const group = listInfo.exclusiveGroup || null;
                            const displaced = [];
                            const prevChecked = new Map();
                            for (const [id, ctrl] of listControls) {
                                prevChecked.set(id, id === listId ? !checked : ctrl.checkbox.checked);
                            }

                            if (checked && group) {
                                for (const [otherId, ctrl] of listControls) {
                                    if (otherId === listId || ctrl.live) continue;
                                    if (ctrl.exclusiveGroup !== group) continue;
                                    if (!ctrl.checkbox.checked) continue;
                                    ctrl.checkbox.checked = false;
                                    displaced.push(otherId);
                                }
                            }

                            updateStatusUI();
                            const adState = await brw.storage.local.get({ moduleStates: {}, masterSwitch: true });
                            const adOn = adState.masterSwitch !== false && adState.moduleStates?.adBlocker !== false;

                            setListsBusy(true);
                            if (!adOn && checked) {
                                setBusyMessage(
                                    `Selected ${listInfo.name}`,
                                    'AdBlocker is off — this list will download when you turn AdBlocker on.'
                                );
                            } else {
                                setBusyMessage(
                                    checked ? `Adding ${listInfo.name}…` : `Removing ${listInfo.name}…`,
                                    checked
                                        ? 'Downloading and installing rules from Git / cache.'
                                        : 'Clearing dynamic rules from the browser. This can take a moment.'
                                );
                            }
                            try {
                                for (const otherId of displaced) {
                                    setBusyMessage(
                                        `Removing ${otherId}…`,
                                        'Switching exclusive list tier — clearing the previous one first.'
                                    );
                                    await withTimeout(
                                        brw.runtime.sendMessage({
                                            action: 'toggleDynamicList',
                                            listId: otherId,
                                            enabled: false
                                        }),
                                        120000,
                                        `Clear ${otherId}`
                                    );
                                    const octrl = listControls.get(otherId);
                                    if (octrl) {
                                        octrl.remote = false;
                                        octrl.ruleCount = (catData.lists[otherId]?.stats?.compressed) || octrl.ruleCount;
                                    }
                                    delete remoteManaged[otherId];
                                }
                                if (adOn || !checked) {
                                    setBusyMessage(
                                        checked ? `Adding ${listInfo.name}…` : `Removing ${listInfo.name}…`,
                                        checked
                                            ? 'Installing network rules (+ cosmetics when available).'
                                            : 'Removing rules — please keep this tab open.'
                                    );
                                }
                                const response = await withTimeout(
                                    brw.runtime.sendMessage({
                                        action: 'toggleDynamicList',
                                        listId,
                                        enabled: checked
                                    }),
                                    180000,
                                    checked ? `Load ${listId}` : `Clear ${listId}`
                                );
                                if (!response || !response.success) {
                                    for (const [id, ctrl] of listControls) {
                                        ctrl.checkbox.checked = prevChecked.get(id) === true;
                                    }
                                    alert((response && response.error) || 'Failed to apply filter list.');
                                } else {
                                    const ctrl = listControls.get(listId);
                                    if (ctrl) {
                                        ctrl.remote = !!checked;
                                        ctrl.ruleCount = checked
                                            ? (response.count || stats.compressed || 0)
                                            : (stats.compressed || 0);
                                        if (checked) remoteManaged[listId] = true;
                                        else delete remoteManaged[listId];
                                    }
                                    updateShieldMetaInfo('opt-shield-mode-info');
                                }
                            } catch (err) {
                                console.error('Failed to toggle ruleset', listId, err);
                                for (const [id, ctrl] of listControls) {
                                    ctrl.checkbox.checked = prevChecked.get(id) === true;
                                }
                                updateStatusUI();
                                alert(err?.message || 'Failed to apply filter list. Please try again.');
                            } finally {
                                setListsBusy(false);
                                setBusyMessage('Applying filter lists…');
                                updateStatusUI();
                            }
                        });

                        const text = document.createElement('span');
                        text.innerHTML = listInfo.name + formatListStats(
                            listInfo.stats,
                            (listInfo.bundledStatic || catKey === 'backup')
                                ? 'Bundled offline fallback'
                                : ''
                        );
                        row.appendChild(cb);
                        row.appendChild(text);
                        body.appendChild(row);
                    }
                    if (body.childElementCount > 0) {
                        container.appendChild(catEl);
                    }
                });

                // Live Threat Intelligence (from remote catalog when available)
                try {
                    const liveEntries = [];
                    if (catRes && catRes.success && catRes.catalog) {
                        for (const list of catRes.catalog.lists || []) {
                            if (list.type === 'domain') {
                                liveEntries.push({
                                    id: list.id,
                                    name: list.name,
                                    source: list.source || 'Online',
                                    url: list.sourceUrl || null
                                });
                            }
                        }
                    }
                    if (!liveEntries.length) {
                        const threatRes = await fetch(brw.runtime.getURL('rules/Malware_Phishing_Threat_Intelligence/Threat_list.json'));
                        const threatData = threatRes.ok ? await threatRes.json() : { entries: [] };
                        for (const entry of threatData.entries || []) liveEntries.push(entry);
                    }

                    const syncInfo = document.getElementById('live-lists-sync-info-opt');
                    if (syncInfo) {
                        syncInfo.textContent = catRes?.lastSync
                            ? ('Last live sync: ' + new Date(catRes.lastSync).toLocaleString())
                            : 'Live lists sync when enabled (auto every 24h).';
                    }

                    const { catEl: liveCat, body: liveBody } = makeCategory('⚡ Live Threat Intelligence', true);

                    for (const entry of liveEntries) {
                        const meta = liveListMeta[entry.id] || {};
                        const ruleCount = threatCounts[entry.id] || meta.rules || 0;
                        const domains = meta.domains || 0;
                        const isEnabled = !!threatFeeds[entry.id];

                        const row = document.createElement('label');
                        row.className = 'filter-row-opt';
                        const cb = document.createElement('input');
                        cb.type = 'checkbox';
                        cb.checked = isEnabled;

                        const metaEl = document.createElement('div');
                        metaEl.className = 'filter-row-meta-opt';
                        metaEl.textContent = isEnabled
                            ? ('Live · Domains: ' + domains.toLocaleString() + ' · Compressed: ' + ruleCount +
                                ' · Updated: ' + (meta.updatedAt ? new Date(meta.updatedAt).toLocaleString() : 'loaded'))
                            : ('Live feed · ' + (entry.source || 'Online') + ' · enable to fetch & compress');

                        listControls.set(entry.id, {
                            checkbox: cb,
                            ruleCount: ruleCount || 0,
                            regexCount: 0,
                            originalCount: domains,
                            cosmeticCount: 0,
                            exclusiveGroup: null,
                            live: true,
                            metaEl
                        });

                        const textWrap = document.createElement('div');
                        const nameEl = document.createElement('div');
                        nameEl.textContent = entry.name;
                        textWrap.appendChild(nameEl);
                        textWrap.appendChild(metaEl);

                        cb.addEventListener('change', async (e) => {
                            const checked = e.target.checked;
                            if (checked) {
                                const blockMsg = wouldExceedLocal(entry.id, ruleCount || 0, 0);
                                if (blockMsg) {
                                    e.target.checked = false;
                                    alert(blockMsg);
                                    updateStatusUI();
                                    return;
                                }
                            }

                            const adState = await brw.storage.local.get({ moduleStates: {}, masterSwitch: true });
                            const adOn = adState.masterSwitch !== false && adState.moduleStates?.adBlocker !== false;

                            setListsBusy(true);
                            if (!adOn && checked) {
                                setBusyMessage(
                                    `Selected ${entry.name}`,
                                    'AdBlocker is off — this live feed will download when you turn AdBlocker on.'
                                );
                            } else {
                                setBusyMessage(
                                    checked ? `Adding ${entry.name}…` : `Removing ${entry.name}…`,
                                    checked
                                        ? 'Fetching & compressing the live threat feed.'
                                        : 'Clearing live rules from the browser.'
                                );
                            }
                            try {
                                const response = await withTimeout(
                                    brw.runtime.sendMessage({
                                        action: 'toggleDynamicList',
                                        listId: entry.id,
                                        url: entry.url,
                                        enabled: checked
                                    }),
                                    120000,
                                    checked ? `Fetch ${entry.id}` : `Clear ${entry.id}`
                                );
                                if (!response || !response.success) {
                                    e.target.checked = !checked;
                                    alert((response && response.error) || 'Failed to toggle live list');
                                } else {
                                    const ctrl = listControls.get(entry.id);
                                    if (ctrl) {
                                        const deferred = !!response.deferred;
                                        ctrl.ruleCount = (checked && !deferred) ? (response.count || 0) : 0;
                                        ctrl.originalCount = (checked && !deferred) ? (response.domains || 0) : 0;
                                        if (ctrl.metaEl) {
                                            if (!checked) {
                                                ctrl.metaEl.textContent = 'Live feed · ' + (entry.source || 'Online') + ' · enable to fetch & compress';
                                            } else if (deferred) {
                                                ctrl.metaEl.textContent = 'Selected · will fetch when AdBlocker is turned on';
                                            } else {
                                                ctrl.metaEl.textContent = 'Live · Domains: ' + (response.domains || 0).toLocaleString() +
                                                    ' · Compressed: ' + (response.count || 0) +
                                                    ' · Updated: ' + new Date().toLocaleString();
                                            }
                                        }
                                    }
                                    if (syncInfo && !response.deferred) {
                                        syncInfo.textContent = 'Last live sync: ' + new Date().toLocaleString();
                                    }
                                }
                            } catch (err) {
                                e.target.checked = !checked;
                                console.error(err);
                                alert(err?.message || String(err));
                            } finally {
                                setListsBusy(false);
                                setBusyMessage('Applying filter lists…');
                                updateStatusUI();
                            }
                        });

                        row.appendChild(cb);
                        row.appendChild(textWrap);
                        liveBody.appendChild(row);
                    }
                    container.appendChild(liveCat);
                } catch (liveErr) {
                    console.warn('[OPSECHub] Failed to load live threat lists:', liveErr);
                }

                updateStatusUI();
                // Modal is attached to document.body while busy (see setListsBusy).
                if (statusDiv.parentElement !== container.parentElement) {
                    container.parentElement.appendChild(statusDiv);
                }
            } catch (e) {
                console.error('Error loading filter lists', e);
                container.innerHTML = '<div style="color:#ff5252; font-size:12px;">Failed to load lists.</div>';
            }
        }

        const btnAddAllowlist = document.getElementById('btn-add-allowlist');
        const inputAllowlist = document.getElementById('allowlist-input');
        if (btnAddAllowlist && inputAllowlist) {
            const addDomainHandler = () => {
                let domain = inputAllowlist.value.trim().toLowerCase();
                if (!domain) return;

                // Clean up protocol/www prefixes, paths, and ports
                domain = domain.replace(/^(https?:\/\/)?(www\.)?/, '');
                domain = domain.split('/')[0].split(':')[0];

                // Validate domain pattern
                if (!/^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$/.test(domain)) {
                    inputAllowlist.style.borderColor = '#ff453a';
                    setTimeout(() => inputAllowlist.style.borderColor = '', 2000);
                    return;
                }

                brw.runtime.sendMessage({ action: 'toggleExclusion', domain, exclude: true }, (res) => {
                    if (res && res.success) {
                        renderAllowlist(res.domains);
                        inputAllowlist.value = '';
                    } else {
                        console.error(res?.error || 'Failed to add domain to allowlist.');
                    }
                });
            };

            btnAddAllowlist.addEventListener('click', addDomainHandler);
            inputAllowlist.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    addDomainHandler();
                }
            });
        }

        renderAllowlist(data.excludedDomains);
        initProxyManager(data);
    });

    // Listen for state changes from popup or background to keep options in sync
    brw.storage.onChanged.addListener((changes, area) => {
        if (area !== 'local') return;

        if (changes.excludedDomains) {
            renderAllowlist(changes.excludedDomains.newValue);
        }

        if (changes.threatFeeds) {
            const feeds = changes.threatFeeds.newValue || {};
            brw.storage.local.get('threatCounts').then(d => {
                const counts = d.threatCounts || {};
                document.querySelectorAll('.threat-feed-toggle').forEach(input => {
                    const feedId = input.dataset.feedId;
                    const isEnabled = !!feeds[feedId];
                    if (input.checked !== isEnabled) {
                        input.checked = isEnabled;
                    }
                    const itemRow = input.closest('.toggle-switch')?.parentElement;
                    if (itemRow) {
                        const statusEl = itemRow.querySelector('span');
                        if (statusEl) {
                            if (isEnabled) {
                                statusEl.style.background = 'rgba(76, 175, 80, 0.1)';
                                statusEl.style.color = '#4CAF50';
                                const count = counts[feedId];
                                statusEl.textContent = count ? `Active (${count} rules)` : 'Active';
                            } else {
                                statusEl.style.background = 'rgba(255,255,255,0.1)';
                                statusEl.style.color = 'var(--text-muted)';
                                statusEl.textContent = 'Inactive';
                            }
                        }
                    }
                });
            });
        }

        if (changes.moduleStates) {
            const newStates = changes.moduleStates.newValue || {};
            document.querySelectorAll('.opt-module-toggle').forEach(toggle => {
                const module = toggle.getAttribute('data-module');
                const isEnabled = isModuleEnabled(newStates, module);
                if (toggle.checked !== isEnabled) {
                    toggle.checked = isEnabled;
                }
            });
        }

        if (changes.moduleStates || changes.enabledFilterLists || changes.masterSwitch) {
            updateShieldMetaInfo('opt-shield-mode-info');
        }

        if (changes.activeProxy) {
            const val = changes.activeProxy.newValue;
            const select = document.getElementById('opt-proxy-profile-select');
            if (select) {
                if (val) {
                    let matched = 'none';
                    for (let option of select.options) {
                        if (option.value === 'none' || option.value === 'custom') continue;
                        try {
                            const parsed = JSON.parse(option.value);
                            if (parsed.host === val.host && parsed.port === val.port && parsed.type === val.type) {
                                matched = option.value;
                                break;
                            }
                        } catch (e) { }
                    }
                    select.value = matched;
                } else {
                    select.value = 'none';
                }
            }
        }





    });
}

function initProxyManager(data) {
    const proxySelect = document.getElementById('opt-proxy-profile-select');
    const btnAddProxy = document.getElementById('btn-add-custom-proxy');
    const proxyToggle = document.querySelector('.opt-module-toggle[data-module="proxyManager"]');

    if (!proxySelect) return;

    // Fetch free proxies from GitHub (with 24-hour cache)
    const CACHE_KEY = 'cachedProxies';
    const CACHE_TIME_KEY = 'proxiesTimestamp';
    const CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours in ms

    function renderFreeProxies(proxies) {
        const proxySelect = document.getElementById('opt-proxy-profile-select');
        const customGroup = document.getElementById('proxy-group-custom');
        if (!proxySelect || !customGroup) return;

        // Remove existing dynamically added country optgroups
        Array.from(proxySelect.querySelectorAll('optgroup.dynamic-country')).forEach(el => el.remove());

        // Group proxies by country
        const grouped = {};
        proxies.forEach(p => {
            const country = p.country || 'Unknown';
            if (!grouped[country]) grouped[country] = [];
            grouped[country].push(p);
        });

        // Create optgroups for each country and insert them before Custom Proxies
        Object.keys(grouped).sort().forEach(country => {
            const optgroup = document.createElement('optgroup');
            optgroup.className = 'dynamic-country';
            optgroup.label = `🆓 ${country} (${grouped[country].length} Proxies)`;

            grouped[country].forEach(p => {
                const opt = document.createElement('option');
                opt.value = JSON.stringify(p);
                opt.textContent = `${p.host}:${p.port} (${p.type.toUpperCase()})`;
                optgroup.appendChild(opt);
            });
            proxySelect.insertBefore(optgroup, customGroup);
        });

        if (data.activeProxy) {
            let matched = 'none';
            for (let option of proxySelect.options) {
                if (option.value === 'none' || option.value === 'custom') continue;
                try {
                    const parsed = JSON.parse(option.value);
                    if (parsed.host === data.activeProxy.host && parsed.port === data.activeProxy.port && parsed.type === data.activeProxy.type) {
                        matched = option.value;
                        break;
                    }
                } catch (e) { }
            }
            proxySelect.value = matched;
        } else {
            proxySelect.value = 'none';
        }
        if (typeof updateProxyIndicator === 'function') updateProxyIndicator();
    }

    brw.storage.local.get([CACHE_KEY, CACHE_TIME_KEY]).then(cacheData => {
        const now = Date.now();
        if (cacheData[CACHE_KEY] && cacheData[CACHE_TIME_KEY] && (now - cacheData[CACHE_TIME_KEY] < CACHE_DURATION)) {
            console.log('[OPSECHub] Loaded proxies from cache.');
            renderFreeProxies(cacheData[CACHE_KEY]);
        } else {
            fetchProxies();
        }
    });

    function fetchProxies() {
        console.log('[OPSECHub] Fetching fresh proxies from GitHub...');
        const btn = document.getElementById('btn-refresh-proxies');
        if (btn) btn.textContent = '⏳ Refreshing...';

        const primaryUrl = 'https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.json';
        const fallbackUrl = 'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.json';

        const parseData = (data) => {
            const proxies = data.map(p => ({
                type: p.protocol || 'socks5',
                host: p.ip,
                port: p.port,
                country: (p.geolocation && p.geolocation.country) ? p.geolocation.country : 'Unknown'
            }));
            brw.storage.local.set({ [CACHE_KEY]: proxies, [CACHE_TIME_KEY]: Date.now() });
            renderFreeProxies(proxies);
            if (btn) btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16"/></svg> Force Refresh';
        };

        fetch(primaryUrl)
            .then(res => {
                if (!res.ok) throw new Error('Primary fetch failed');
                return res.json();
            })
            .then(parseData)
            .catch(() => {
                // Try fallback URL
                fetch(fallbackUrl)
                    .then(res => res.json())
                    .then(parseData)
                    .catch(err => {
                        console.warn('[OPSECHub] Free proxies update notice:', err.message || err);
                        if (btn) btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16"/></svg> Refresh';
                        brw.storage.local.get(CACHE_KEY).then(d => {
                            if (d[CACHE_KEY]) renderFreeProxies(d[CACHE_KEY]);
                        });
                    });
            });
    }

    const btnRefresh = document.getElementById('btn-refresh-proxies');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', fetchProxies);
    }

    // btn-global-refresh is wired in initSettings → runRemoteListsRefresh

    const btnResetData = document.getElementById('btn-global-reset-data');
    if (btnResetData) {
        btnResetData.addEventListener('click', () => {
            if (confirm("Are you sure you want to reset OPSECHub to factory defaults? All statistics, custom proxies, exclusions, and settings will be deleted.")) {
                btnResetData.innerHTML = '⏳ Resetting...';
                brw.storage.local.clear().then(() => {
                    chrome.runtime.reload();
                });
            }
        });
    }

    // Load custom proxies
    const groupCustom = document.getElementById('proxy-group-custom');
    const customProxies = data.customProxies || [];

    function renderCustomProxies() {
        groupCustom.innerHTML = '';
        customProxies.forEach(p => {
            const opt = document.createElement('option');
            opt.value = JSON.stringify(p);
            const labelName = p.name ? p.name : `${p.host}:${p.port}`;
            opt.textContent = `🔧 Custom: ${labelName} (${p.type.toUpperCase()})`;
            groupCustom.appendChild(opt);
        });
    }

    renderCustomProxies();

    if (data.activeProxy) {
        // We delay setting value slightly to allow async fetch to populate if needed, 
        // but for custom and tools it's immediate.
        proxySelect.value = JSON.stringify(data.activeProxy);
    }

    const btnDeleteProxy = document.getElementById('btn-delete-custom-proxy');
    const proxyIndicator = document.getElementById('active-proxy-indicator');

    function updateDeleteBtnVisibility(val) {
        if (!btnDeleteProxy) return;
        try {
            if (val === 'none') {
                btnDeleteProxy.style.display = 'none';
                return;
            }
            const config = JSON.parse(val);
            const isCustom = customProxies.some(p => p.host === config.host && String(p.port) === String(config.port) && p.type === config.type);
            btnDeleteProxy.style.display = isCustom ? 'flex' : 'none';
        } catch (e) {
            btnDeleteProxy.style.display = 'none';
        }
    }

    function updateProxyIndicator() {
        if (!proxyIndicator || !proxySelect) return;
        const val = proxySelect.value;
        const isModuleOn = proxyToggle && proxyToggle.checked;
        const btnTest = document.getElementById('btn-test-proxy');

        proxyIndicator.style.display = 'block';

        if (val === 'none') {
            proxyIndicator.style.background = 'rgba(255,255,255,0.05)';
            proxyIndicator.style.color = '#8892b0';
            proxyIndicator.innerHTML = isModuleOn
                ? '🟢 <strong>Auto-Routing:</strong> Extension will pick a random proxy (None specified).'
                : '🔴 <strong>Direct Connection:</strong> Proxy module is currently OFF.';
            if (btnTest) btnTest.style.display = 'none';
            return;
        }

        try {
            const config = JSON.parse(val);
            const labelName = config.name ? config.name : `${config.host}:${config.port}`;
            const safeLabelName = escapeHtml(labelName);

            if (isModuleOn) {
                proxyIndicator.style.background = 'rgba(76, 175, 80, 0.15)';
                proxyIndicator.style.color = '#4CAF50';
                proxyIndicator.innerHTML = `🟢 <strong>Currently Routing Through:</strong> ${safeLabelName} (${escapeHtml(config.type.toUpperCase())})`;
                if (btnTest) {
                    btnTest.style.display = 'block';
                    btnTest.textContent = '🔍 Test Active Connection';
                    btnTest.style.color = '#e3f2fd';
                }
            } else {
                proxyIndicator.style.background = 'rgba(255, 152, 0, 0.1)';
                proxyIndicator.style.color = '#FF9800';
                proxyIndicator.innerHTML = `⏸️ <strong>Profile Selected:</strong> ${safeLabelName} (Waiting for Proxy module to be turned ON)`;
                if (btnTest) btnTest.style.display = 'none';
            }
        } catch (e) { }
    }

    updateDeleteBtnVisibility(proxySelect.value);
    updateProxyIndicator();

    if (proxyToggle) {
        proxyToggle.addEventListener('change', () => {
            updateProxyIndicator();
        });
    }

    const btnTest = document.getElementById('btn-test-proxy');
    if (btnTest) {
        btnTest.addEventListener('click', async () => {
            btnTest.textContent = '⏳ Testing...';
            btnTest.style.color = '#FFC107';
            try {
                // To test if the proxy works, we just make a fetch call.
                // Since the proxy is ACTIVE globally for Chrome, this fetch will go through the proxy!
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 8000); // 8s timeout

                const res = await fetch('https://api.ipify.org?format=json', { signal: controller.signal });
                clearTimeout(timeoutId);

                if (res.ok) {
                    const data = await res.json();
                    btnTest.textContent = `✅ Success! IP: ${data.ip}`;
                    btnTest.style.color = '#4CAF50';
                } else {
                    throw new Error('Bad response');
                }
            } catch (err) {
                btnTest.textContent = '❌ Dead Proxy (Failed)';
                btnTest.style.color = '#F44336';
            }
        });
    }

    // Handle Proxy Selection
    proxySelect.addEventListener('change', (e) => {
        const val = e.target.value;
        updateDeleteBtnVisibility(val);
        updateProxyIndicator();

        if (val === 'none') {
            brw.storage.local.set({ activeProxy: null });
            if (proxyToggle && proxyToggle.checked) {
                brw.runtime.sendMessage({ action: 'setProxy', config: null });
            }
        } else {
            try {
                const config = JSON.parse(val);
                brw.storage.local.set({ activeProxy: config });
                if (proxyToggle && proxyToggle.checked) {
                    brw.runtime.sendMessage({ action: 'setProxy', config });
                }
            } catch (err) { }
        }
    });

    if (btnDeleteProxy) {
        btnDeleteProxy.addEventListener('click', () => {
            const val = proxySelect.value;
            if (val === 'none') return;
            try {
                const config = JSON.parse(val);
                const index = customProxies.findIndex(p => p.host === config.host && String(p.port) === String(config.port) && p.type === config.type);
                if (index !== -1) {
                    customProxies.splice(index, 1);
                    brw.storage.local.set({ customProxies });
                    renderCustomProxies();
                    proxySelect.value = 'none';
                    proxySelect.dispatchEvent(new Event('change'));
                }
            } catch (e) { }
        });
    }

    // Handle adding custom proxy
    if (btnAddProxy) {
        btnAddProxy.addEventListener('click', () => {
            const nameEl = document.getElementById('opt-proxy-add-name');
            const name = nameEl ? nameEl.value.trim() : '';
            const type = document.getElementById('opt-proxy-add-type').value;
            const host = document.getElementById('opt-proxy-add-host').value.trim();
            const port = document.getElementById('opt-proxy-add-port').value.trim();

            if (!host || !port) {
                const hostEl = document.getElementById('opt-proxy-add-host');
                if (hostEl) hostEl.style.borderColor = '#ff453a';
                setTimeout(() => { if (hostEl) hostEl.style.borderColor = ''; }, 2000);
                return;
            }

            const newProxy = { name, type, host, port };
            customProxies.push(newProxy);
            brw.storage.local.set({ customProxies });

            renderCustomProxies();

            // Clear inputs
            if (nameEl) nameEl.value = '';
            document.getElementById('opt-proxy-add-host').value = '';
            document.getElementById('opt-proxy-add-port').value = '';

            // Auto-select
            proxySelect.value = JSON.stringify(newProxy);
            proxySelect.dispatchEvent(new Event('change'));
        });
    }
}

function renderAllowlist(domains) {
    const container = document.getElementById('allowlist-container');
    const empty = document.getElementById('allowlist-empty');
    if (!container) return;

    container.innerHTML = '';
    if (!domains || domains.length === 0) {
        if (empty) empty.style.display = 'block';
        return;
    }

    if (empty) empty.style.display = 'none';

    domains.forEach(domain => {
        const li = document.createElement('li');
        li.style.display = 'flex';
        li.style.justifyContent = 'space-between';
        li.style.alignItems = 'center';
        li.style.padding = '8px 12px';
        li.style.background = 'rgba(255,255,255,0.05)';
        li.style.marginBottom = '6px';
        li.style.borderRadius = '4px';

        const text = document.createElement('span');
        text.textContent = domain;
        text.style.color = 'var(--text-primary)';
        text.style.fontSize = '13px';

        const removeBtn = document.createElement('button');
        removeBtn.textContent = 'Remove';
        removeBtn.style.background = 'rgba(244, 67, 54, 0.1)';
        removeBtn.style.color = '#ff5252';
        removeBtn.style.border = 'none';
        removeBtn.style.padding = '4px 8px';
        removeBtn.style.borderRadius = '4px';
        removeBtn.style.cursor = 'pointer';
        removeBtn.style.fontSize = '11px';

        removeBtn.addEventListener('click', () => {
            brw.runtime.sendMessage({ action: 'toggleExclusion', domain, exclude: false }, (res) => {
                if (res && res.success) {
                    renderAllowlist(res.domains);
                }
            });
        });

        li.appendChild(text);
        li.appendChild(removeBtn);
        container.appendChild(li);
    });
}

function initThreatDiagnostics() {
    const btn = document.getElementById('btn-run-threat-diagnostics');
    if (!btn) return;

    // Load randomized test domains from storage if present
    async function loadTestDomains() {
        try {
            const d = await brw.storage.local.get({ threatTestDomains: {} });
            const testDomains = d.threatTestDomains || {};
            const rows = document.querySelectorAll('.diagnostic-row');
            rows.forEach(row => {
                const feedId = row.dataset.feed;
                if (testDomains[feedId]) {
                    row.dataset.url = testDomains[feedId];
                    const codeEl = row.querySelector('code');
                    if (codeEl) {
                        codeEl.textContent = testDomains[feedId];
                    }
                }
            });
        } catch (e) {
            console.error('[OPSECHub] Failed to load randomized test domains:', e);
        }
    }

    loadTestDomains();

    btn.addEventListener('click', async () => {
        // Refresh storage data to get latest feed states and latest test domains
        btn.disabled = true;
        btn.textContent = '⏳ Testing...';

        await loadTestDomains();

        const rows = document.querySelectorAll('.diagnostic-row');
        // Read current module states and dynamic threat feed states
        const d = await brw.storage.local.get({ threatFeeds: {}, moduleStates: {}, masterSwitch: true });
        const feeds = d.threatFeeds || {};
        const isMasterIntelEnabled = d.masterSwitch !== false && d.moduleStates.adBlocker !== false;

        const testPromises = Array.from(rows).map(async row => {
            const feedId = row.dataset.feed;
            const domain = row.dataset.url;
            const statusEl = row.querySelector('.diagnostic-status');
            if (!statusEl) return;

            statusEl.textContent = '⏳ Probing...';
            statusEl.style.color = '#ff9800';

            const isEnabled = isMasterIntelEnabled && !!feeds[feedId];
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 1500);

            try {
                // Use no-cors to bypass CORS block and only test DNS resolution/DNR interception
                await fetch(`https://${domain}/favicon.ico`, {
                    mode: 'no-cors',
                    cache: 'no-store',
                    signal: controller.signal
                });
                clearTimeout(timeoutId);

                // If it resolved, the request succeeded (meaning it was not blocked)
                statusEl.textContent = 'Allowed ⚠️';
                statusEl.style.color = '#ff9800';
            } catch (err) {
                clearTimeout(timeoutId);

                // If it was rejected, check if the feed is checked in settings
                if (isEnabled) {
                    statusEl.textContent = 'Blocked 🛡️ (Protected)';
                    statusEl.style.color = '#4CAF50';
                } else {
                    statusEl.textContent = 'Allowed ⚠️';
                    statusEl.style.color = '#ff9800';
                }
            }
        });

        await Promise.all(testPromises);
        btn.disabled = false;
        btn.textContent = 'Run Probe Test';
    });
}

function initExtraTools() {
    initDocumentTrackerTool();
    initMetadataRemoverTool();
    initPassphraseTool();
    initFileHashTool();
    initDocEncryptorTool();
    initLinkTracerTool();
    initVirusTotalTool();
    initSslCheckerTool();
    initHeaderAnalyzerTool();
    initDohCheckerTool();
}


