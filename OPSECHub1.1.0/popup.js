/**
 * OPSECHub – Main Popup Controller
 * Handles UI state, navigation, toggle sync, and module management.
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
            // All network blocking is remote/dynamic — never count as static.
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

function updateShieldCard(enabled) {
    const valShield = document.getElementById('val-shield');
    const descShield = document.getElementById('desc-shield');
    const shieldCard = document.getElementById('status-shield');
    if (valShield) {
        valShield.textContent = enabled ? 'Active' : 'Disabled';
        valShield.className = 'status-card-value ' + (enabled ? 'status-on' : 'status-off');
    }
    if (descShield) {
        descShield.textContent = enabled
            ? 'Recommended all-round protection.'
            : 'All core protection is off.';
    }
    if (shieldCard) { shieldCard.classList.toggle('active', enabled); }
}

// ═══════════════════════════════════════════════════════════════════
// MODULE REGISTRY
// ═══════════════════════════════════════════════════════════════════
const MODULE_REGISTRY = {

    webrtcBlock: { label: 'WebRTC', icon: '📡', onLabel: 'Blocked', offLabel: 'Leaking' },
    googleTelemetry: { label: 'Google Telemetry', icon: '🚫', onLabel: 'Blocked', offLabel: 'Leaking' },
    privacyHeaders: { label: 'Do Not Track', icon: '🛡️', onLabel: 'Active', offLabel: 'Off' },
    forceHttps: { label: 'HTTPS', icon: '🔒', onLabel: 'Enforced', offLabel: 'Off' },
    cookieGuard: { label: 'Cookies', icon: '🍪', onLabel: 'Guarded', offLabel: 'Off' },
    locationBlock: { label: 'Location Guard', icon: '📍', onLabel: 'Spoofed', offLabel: 'Real' },
    mediaBlock: { label: 'Camera & Mic', icon: '📸', onLabel: 'Blocked', offLabel: 'Exposed' },
    clipboardGuard: { label: 'Clipboard', icon: '📋', onLabel: 'Guarded', offLabel: 'Off' },
    proxyManager: { label: 'Proxy', icon: '🌐', onLabel: 'Connected', offLabel: 'Direct' },
};

// ═══════════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════════
let moduleStates = {};

// ═══════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', async () => {
    // Hydrate shield / master BEFORE first paint so we don't flash "Disabled".
    const boot = await brw.storage.local.get({
        moduleStates: {},
        masterSwitch: true
    });
    moduleStates = boot.moduleStates || {};
    const adOn = isModuleEnabled(moduleStates, 'adBlocker');
    const dashToggle = document.getElementById('toggle-adblocker-dashboard');
    if (dashToggle) dashToggle.checked = adOn;
    updateShieldCard(adOn);
    updateMasterUI(boot.masterSwitch !== false);

    initNavigation();
    initDashboardCustomizer();
    initToggles();
    initQuickActions();
    updateShieldStatus();
    initAlertLog();
    initSetupBanner();

    // Reveal UI after hydrate (boot splash fades out via CSS).
    requestAnimationFrame(() => {
        document.documentElement.classList.remove('popup-booting');
        document.documentElement.classList.add('popup-ready');
        const bootEl = document.getElementById('popup-boot');
        if (bootEl) {
            bootEl.addEventListener('transitionend', () => bootEl.remove(), { once: true });
            // Fallback if transitionend doesn't fire
            setTimeout(() => bootEl.remove(), 400);
        }
    });

    // iOS Inline Settings Toggles (skip deep-link buttons like Lists/Settings)
    const settingsBtns = document.querySelectorAll('.settings-btn');
    settingsBtns.forEach(btn => {
        if (btn.id === 'btn-open-filter-lists') return;
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const moduleId = btn.id.replace('btn-settings-', '');
            const panel = document.getElementById(`settings-panel-${moduleId}`);
            if (panel) {
                const open = panel.classList.toggle('open');
                btn.classList.toggle('is-open', open);
            }
        });
    });

    function openFilterListsSettings() {
        const url = brw.runtime.getURL('options.html?cat=security&tool=opt-adblocker');
        brw.tabs.create({ url });
    }
    const openListsBtn = document.getElementById('btn-open-filter-lists');
    if (openListsBtn) {
        openListsBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            openFilterListsSettings();
        });
    }

    // Sync Proxy Profiles
    const proxySelect = document.getElementById('proxyProfileSelect');
    if (proxySelect) {
        brw.storage.local.get({ customProxies: [], cachedProxies: [], activeProxy: null }, (data) => {
            // Remove existing dynamically added country groups
            Array.from(proxySelect.querySelectorAll('optgroup.dynamic-country-popup')).forEach(el => el.remove());

            const customGroup = document.getElementById('proxy-popup-group-custom');
            if (customGroup) {
                customGroup.innerHTML = '';
                data.customProxies.forEach(p => {
                    const opt = document.createElement('option');
                    const pVal = JSON.stringify(p);
                    opt.value = pVal;
                    opt.textContent = `🔧 Custom: ${p.name || p.host} (${p.type.toUpperCase()})`;
                    customGroup.appendChild(opt);
                });
            }

            // Group free proxies by country
            const grouped = {};
            const cached = data.cachedProxies || [];
            cached.forEach(p => {
                const country = p.country || 'Unknown';
                if (!grouped[country]) grouped[country] = [];
                grouped[country].push(p);
            });

            // Append country groups to select
            Object.keys(grouped).sort().forEach(country => {
                const optgroup = document.createElement('optgroup');
                optgroup.className = 'dynamic-country-popup';
                optgroup.label = `🆓 ${country} (${grouped[country].length} Proxies)`;

                grouped[country].forEach(p => {
                    const opt = document.createElement('option');
                    opt.value = JSON.stringify(p);
                    opt.textContent = `${p.host}:${p.port} (${p.type.toUpperCase()})`;
                    optgroup.appendChild(opt);
                });
                proxySelect.appendChild(optgroup);
            });

            const notice = document.getElementById('proxy-notice');
            if (notice) {
                notice.style.display = (data.customProxies.length === 0 && cached.length === 0) ? 'block' : 'none';
            }

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
        });

        proxySelect.addEventListener('change', (e) => {
            const val = e.target.value;
            if (val === 'none') {
                brw.storage.local.set({ activeProxy: null }, () => {
                    brw.runtime.sendMessage({ action: 'toggleModule', module: 'proxyManager', enabled: true });
                });
            } else {
                try {
                    const config = JSON.parse(val);
                    brw.storage.local.set({ activeProxy: config }, () => {
                        brw.runtime.sendMessage({ action: 'toggleModule', module: 'proxyManager', enabled: true });
                    });
                } catch (err) { }
            }
        });
    }



    // Load Stats
    function updateStatsUI(stats) {
        if (!stats) return;
        const statAds = document.getElementById('stat-ads-blocked');
        const statThreats = document.getElementById('stat-threats-blocked');

        if (statAds) statAds.textContent = stats.adsBlocked || 0;
        if (statThreats) statThreats.textContent = stats.threatsBlocked || 0;
    }

    brw.storage.local.get({ opsecStats: { adsBlocked: 0, threatsBlocked: 0 } }, (data) => {
        updateStatsUI(data.opsecStats);
    });

    const resetStatsBtn = document.getElementById('btn-reset-stats');
    if (resetStatsBtn) {
        resetStatsBtn.addEventListener('click', () => {
            brw.runtime.sendMessage({ action: 'resetStats' }, () => {
                const statAds = document.getElementById('stat-ads-blocked');
                const statThreats = document.getElementById('stat-threats-blocked');

                if (statAds) statAds.textContent = '0';
                if (statThreats) statThreats.textContent = '0';
            });
        });
    }

    // Sync buttons/links to avoid inline CSP violations
    const linkManageAllowlist = document.getElementById('link-manage-allowlist');
    if (linkManageAllowlist) {
        linkManageAllowlist.addEventListener('click', () => {
            window.open('options.html', '_blank');
        });
    }

    const linkConfigureProxies = document.getElementById('link-configure-proxies');
    if (linkConfigureProxies) {
        linkConfigureProxies.addEventListener('click', () => {
            window.open('options.html', '_blank');
        });
    }

    // Listen for state changes to keep popup in sync with options page or background
    brw.storage.onChanged.addListener((changes, area) => {
        if (area !== 'local') return;

        if (changes.opsecStats) {
            updateStatsUI(changes.opsecStats.newValue);
        }

        if (changes.moduleStates) {
            const newStates = changes.moduleStates.newValue || {};
            moduleStates = newStates; // Update the global state!
            document.querySelectorAll('.module-toggle').forEach(toggle => {
                const module = toggle.getAttribute('data-module');
                const isEnabled = isModuleEnabled(newStates, module);
                if (toggle.checked !== isEnabled) {
                    toggle.checked = isEnabled;
                }
                if (module === 'adBlocker') { updateShieldCard(isEnabled); }
            });
            updateDashboardCards();
        }

        if (changes.masterSwitch) {
            const masterCheckbox = document.getElementById('master-toggle');
            if (masterCheckbox && masterCheckbox.checked !== changes.masterSwitch.newValue) {
                masterCheckbox.checked = changes.masterSwitch.newValue;
                updateShieldStatus();
            }
            updateMasterUI(changes.masterSwitch.newValue);
        }

        if (changes.moduleStates || changes.enabledFilterLists || changes.masterSwitch) {
            updateShieldMetaInfo('inline-shield-mode-info');
        }

        if (changes.excludedDomains) {
            brw.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs && tabs[0] && tabs[0].url) {
                    try {
                        const url = new URL(tabs[0].url);
                        const domain = url.hostname;
                        const isExcluded = (changes.excludedDomains.newValue || []).includes(domain);
                        const toggle = document.getElementById('toggle-site-exclusion');
                        if (toggle) {
                            toggle.checked = !isExcluded;
                        }
                    } catch (e) { }
                }
            });
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
                        const statusEl = itemRow.querySelector('.live-status-text');
                        if (statusEl) {
                            statusEl.textContent = isEnabled ? (counts[feedId] ? `Active (${counts[feedId]} rules)` : 'Active') : 'Inactive';
                            statusEl.style.color = isEnabled ? 'var(--primary-color)' : 'var(--text-muted)';
                        }
                    }
                });
            });
        }

        if (changes.activeProxy) {
            const newProxy = changes.activeProxy.newValue;
            const proxySelect = document.getElementById('proxyProfileSelect');
            if (proxySelect) {
                if (newProxy) {
                    let matched = 'none';
                    for (let option of proxySelect.options) {
                        if (option.value === 'none' || option.value === 'custom') continue;
                        try {
                            const parsed = JSON.parse(option.value);
                            if (parsed.host === newProxy.host && parsed.port === newProxy.port && parsed.type === newProxy.type) {
                                matched = option.value;
                                break;
                            }
                        } catch (e) { }
                    }
                    proxySelect.value = matched;
                } else {
                    proxySelect.value = 'none';
                }
            }
        }





        if (changes.opsecStats) {
            updateStatsUI(changes.opsecStats.newValue);
        }
    });
});

// ═══════════════════════════════════════════════════════════════════
// LOAD / SAVE STATE
// ═══════════════════════════════════════════════════════════════════
async function loadModuleStates() {
    const data = await brw.storage.local.get({ moduleStates: {} });
    moduleStates = data.moduleStates || {};
}

function saveModuleStates() {
    brw.storage.local.set({ moduleStates });
}

// ═══════════════════════════════════════════════════════════════════
// NAVIGATION
// ═══════════════════════════════════════════════════════════════════
function initNavigation() {
    const tabs = document.querySelectorAll('.nav-tab');
    const panels = document.querySelectorAll('.tab-panel');

    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.tab;
            brw.storage.local.set({ activePopupTab: target }); // Save state

            tabs.forEach(t => t.classList.remove('active'));
            panels.forEach(p => p.classList.remove('active'));

            tab.classList.add('active');
            const panel = document.getElementById(`tab-${target}`);
            if (panel) panel.classList.add('active');
        });
    });

    // Load saved state
    brw.storage.local.get(['activePopupTab'], (res) => {
        if (res.activePopupTab) {
            const savedTab = document.querySelector(`.nav-tab[data-tab="${res.activePopupTab}"]`);
            if (savedTab) savedTab.click();
        }
    });

    // Settings button opens options page
    const settingsBtn = document.getElementById('btn-settings');
    if (settingsBtn) {
        settingsBtn.addEventListener('click', () => {
            brw.runtime.openOptionsPage();
        });
    }

    // Allowlist button opens options page to Exclusions
    const allowlistBtn = document.getElementById('btn-popup-allowlist');
    if (allowlistBtn) {
        allowlistBtn.addEventListener('click', () => {
            brw.tabs.create({ url: brw.runtime.getURL('options.html') });
        });
    }

    // Extra Tools: open options on the selected tool
    document.querySelectorAll('.tool-launch-card').forEach(card => {
        card.addEventListener('click', () => {
            const tool = card.dataset.tool;
            const url = brw.runtime.getURL(`options.html?cat=tools&tool=${encodeURIComponent(tool)}`);
            brw.tabs.create({ url });
        });
    });

    // Same action as Settings → Refresh Lists (catalog + enabled list bodies).
    const refreshBtn = document.getElementById('btn-refresh-all');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', async () => {
            if (refreshBtn.disabled) return;
            refreshBtn.disabled = true;
            const origHtml = refreshBtn.innerHTML;
            let unbindProgress = () => { };
            try {
                const { showFilterBusy, updateFilterBusy, hideFilterBusy, bindFilterBusyProgress } = await import(
                    brw.runtime.getURL('js/filter-busy-ui.mjs')
                );
                showFilterBusy(
                    'Refreshing from Git…',
                    'Checking the catalog and updating enabled lists if needed.'
                );
                unbindProgress = bindFilterBusyProgress();
                const res = await brw.runtime.sendMessage({ action: 'refreshRemoteLists' });
                if (res && res.success) {
                    updateFilterBusy(
                        res.unchanged ? 'Up to date' : 'Done',
                        res.unchanged
                            ? 'Nothing new to download.'
                            : `Updated ${res.refreshed || 0} list(s)` +
                                (res.skipped ? `, skipped ${res.skipped}` : '')
                    );
                    refreshBtn.innerHTML = '✓';
                    setTimeout(() => { refreshBtn.innerHTML = origHtml; }, 1600);
                } else {
                    updateFilterBusy('Refresh failed', (res && res.error) || 'Unknown error');
                    console.error('[OPSECHub] Remote list refresh failed:', res?.error);
                }
                hideFilterBusy(700);
            } catch (err) {
                console.error('[OPSECHub] Remote list refresh failed:', err);
            } finally {
                unbindProgress();
                refreshBtn.disabled = false;
            }
        });
    }
}

// ═══════════════════════════════════════════════════════════════════
// TOGGLE MANAGEMENT
// ═══════════════════════════════════════════════════════════════════
function updateMasterUI(isOn) {
    const btn = document.getElementById('btn-master-power');
    if (!btn) return;
    if (isOn) {
        document.body.classList.remove('master-off');
        btn.classList.remove('power-off');
        btn.classList.add('power-on');
    } else {
        document.body.classList.add('master-off');
        btn.classList.remove('power-on');
        btn.classList.add('power-off');
    }
}

function initToggles() {
    // We bind change events globally because elements might be created dynamically
    document.body.addEventListener('change', (e) => {
        if (e.target.tagName === 'INPUT' && e.target.type === 'checkbox' && e.target.hasAttribute('data-module')) {
            const moduleName = e.target.dataset.module;
            // adBlocker has its own handler below with DNR error rollback.
            if (moduleName === 'adBlocker') { return; }
            handleModuleToggle(moduleName, e.target.checked);
        }
    });

    // Wire handlers; shield/master visuals were already hydrated on boot.
    brw.storage.local.get({ moduleStates: {}, locationMode: 'block', masterSwitch: true, excludedDomains: [] }).then(data => {
        moduleStates = data.moduleStates || moduleStates;

        brw.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            const banner = document.getElementById('site-exclusion-banner');
            if (tabs && tabs[0] && tabs[0].url && banner) {
                try {
                    const url = new URL(tabs[0].url);
                    const domain = url.hostname;
                    // Ignore chrome://, chrome-extension://, edge://, about:, etc.
                    if (domain && !tabs[0].url.startsWith('chrome') && !tabs[0].url.startsWith('edge') && !tabs[0].url.startsWith('about')) {
                        banner.style.display = 'flex';
                        document.getElementById('current-site-domain').textContent = domain;
                        const isExcluded = data.excludedDomains.includes(domain);
                        const toggle = document.getElementById('toggle-site-exclusion');
                        toggle.checked = !isExcluded; // Checked = protected

                        toggle.addEventListener('change', (e) => {
                            const exclude = !e.target.checked;
                            brw.runtime.sendMessage({ action: 'toggleExclusion', domain, exclude });
                        });
                    } else {
                        banner.style.display = 'none';
                    }
                } catch (e) {
                    banner.style.display = 'none';
                }
            } else if (banner) {
                banner.style.display = 'none';
            }
        });

        const btnMaster = document.getElementById('btn-master-power');
        if (btnMaster && !btnMaster.dataset.bound) {
            btnMaster.dataset.bound = '1';
            btnMaster.addEventListener('click', () => {
                const isNowOn = document.body.classList.contains('master-off'); // toggling ON if currently OFF

                btnMaster.disabled = true;
                btnMaster.style.opacity = '0.4';
                btnMaster.style.cursor = 'wait';

                brw.storage.local.set({ masterSwitch: isNowOn }).then(() => {
                    updateMasterUI(isNowOn);
                    brw.runtime.sendMessage({ action: 'toggleMaster', enabled: isNowOn }).catch(() => {});
                    btnMaster.disabled = false;
                    btnMaster.style.opacity = '';
                    btnMaster.style.cursor = '';
                });
            });
        }
        document.querySelectorAll('.module-toggle').forEach(toggle => {
            const module = toggle.getAttribute('data-module');
            if (module === 'adBlocker') {
                const adOn = isModuleEnabled(data.moduleStates, 'adBlocker');
                toggle.checked = adOn;
                updateShieldCard(adOn);
                updateShieldMetaInfo('inline-shield-mode-info');
                if (toggle.dataset.bound) return;
                toggle.dataset.bound = '1';
                toggle.addEventListener('change', async (e) => {
                    const enabled = e.target.checked;
                    toggle.disabled = true;

                    if (enabled) {
                        const sel = await brw.storage.local.get({
                            enabledFilterLists: [],
                            threatFeeds: {}
                        });
                        const hasLists = (sel.enabledFilterLists || []).length > 0
                            || Object.values(sel.threatFeeds || {}).some(Boolean);
                        if (!hasLists) {
                            toggle.checked = false;
                            toggle.disabled = false;
                            showDNRWarning('Select at least one filter list before turning AdBlocker on.');
                            return;
                        }
                    }

                    let unbindProgress = () => { };
                    let hideBusy = null;
                    try {
                        if (!enabled) {
                            // Instant pause — no list unload.
                            updateShieldCard(false);
                            const response = await brw.runtime.sendMessage({
                                action: 'toggleModule',
                                module: 'adBlocker',
                                enabled: false
                            });
                            if (response && response.success === false) {
                                toggle.checked = true;
                                updateShieldCard(true);
                                showDNRWarning(response.error || 'Unknown error');
                                return;
                            }
                            return;
                        }

                        // Optimistic UI — network unpause is instant when rules already exist.
                        updateShieldCard(true);
                        const responsePromise = brw.runtime.sendMessage({
                            action: 'toggleModule',
                            module: 'adBlocker',
                            enabled: true
                        });

                        // Only show the busy modal if restore/download actually takes a moment.
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

                        if (response && response.success === false) {
                            toggle.checked = false;
                            updateShieldCard(false);
                            if (hideBusy) {
                                const { updateFilterBusy } = await import(
                                    brw.runtime.getURL('js/filter-busy-ui.mjs')
                                );
                                updateFilterBusy('Could not enable', response.error || 'Unknown error');
                                hideBusy(1200);
                            }
                            showDNRWarning(response.error || 'Unknown error');
                            return;
                        }

                        if (hideBusy && !response?.resumed) {
                            const { updateFilterBusy } = await import(
                                brw.runtime.getURL('js/filter-busy-ui.mjs')
                            );
                            const loaded = (response?.refreshed || 0) + (response?.skipped || 0);
                            const total = response?.total || loaded;
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
                    } catch (err) {
                        console.error(err);
                        toggle.checked = !enabled;
                        updateShieldCard(toggle.checked);
                    } finally {
                        unbindProgress();
                        toggle.disabled = false;
                        updateShieldMetaInfo('inline-shield-mode-info');
                    }
                });
            } else {
                toggle.checked = isModuleEnabled(data.moduleStates, module);
            }
        });

    });

    updateDashboardCards();
}

function initSetupBanner() {
    const banner = document.getElementById('setup-incomplete-banner');
    const btn = document.getElementById('btn-resume-setup');
    if (!banner) return;
    brw.storage.local.get({ setupCompleted: true, enabledFilterLists: null }).then((d) => {
        // Only nudge brand-new installs that never finished welcome.
        const needsSetup = d.setupCompleted === false;
        banner.style.display = needsSetup ? 'flex' : 'none';
    });
    if (btn) {
        btn.addEventListener('click', () => {
            brw.tabs.create({ url: brw.runtime.getURL('welcome.html') });
        });
    }
}

async function handleModuleToggle(moduleName, isEnabled) {
    const syncToggles = (on) => {
        document.querySelectorAll(`input[data-module="${moduleName}"]`).forEach(input => {
            input.checked = on;
        });
    };

    if (isEnabled) {
        try {
            const {
                ensureModulePermissions,
                showPermToast
            } = await import(brw.runtime.getURL('js/optional-permissions.mjs'));
            const result = await ensureModulePermissions(moduleName);
            if (!result.granted) {
                moduleStates[moduleName] = false;
                syncToggles(false);
                updateDashboardCards();
                updateShieldStatus();
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
            moduleStates[moduleName] = false;
            syncToggles(false);
            return;
        }
    }

    moduleStates[moduleName] = isEnabled;
    saveModuleStates();
    syncToggles(isEnabled);
    updateDashboardCards();
    updateShieldStatus();

    brw.runtime.sendMessage({
        action: 'toggleModule',
        module: moduleName,
        enabled: isEnabled
    }).catch(() => { });
}

function updateDashboardCards() {
    // Update all rendered cards in the DOM based on moduleStates
    for (const [moduleName, meta] of Object.entries(MODULE_REGISTRY)) {
        const isActive = !!moduleStates[moduleName];

        // Find dynamically rendered cards for this module
        const cards = document.querySelectorAll(`.status-card[data-mod="${moduleName}"]`);
        cards.forEach(card => {
            const valEl = card.querySelector('.status-card-value');
            if (valEl) {
                valEl.textContent = isActive ? meta.onLabel : meta.offLabel;
                valEl.className = 'status-card-value ' + (isActive ? 'status-on' : 'status-off');
            }
            card.classList.toggle('active', isActive);
        });
    }
}

// ═══════════════════════════════════════════════════════════════════
// SHIELD STATUS
// ═══════════════════════════════════════════════════════════════════
function updateShieldStatus() {
    const badgeEl = document.getElementById('opsec-score-badge');
    const scoreEl = document.getElementById('opsec-score');
    if (!badgeEl || !scoreEl) return;

    let score = 10; // Base score

    const adBlockerOn = isModuleEnabled(moduleStates, 'adBlocker');
    if (adBlockerOn) score += 40;

    // Active modules
    const activeModules = Object.values(moduleStates).filter(Boolean).length;
    score += (activeModules * 5); // +5 per module

    if (score > 100) score = 100;
    if (adBlockerOn === false && activeModules === 0) score = 0;

    // Visuals and Faces
    const iconEl = badgeEl.querySelector('.shield-icon');
    if (score < 40) {
        badgeEl.style.background = 'rgba(239, 83, 80, 0.1)';
        badgeEl.style.borderColor = 'rgba(239, 83, 80, 0.3)';
        badgeEl.style.color = '#ef5350';
        iconEl.textContent = '😨';
        scoreEl.textContent = 'OPSEC: WEAK';
    } else if (score < 70) {
        badgeEl.style.background = 'rgba(255, 167, 38, 0.1)';
        badgeEl.style.borderColor = 'rgba(255, 167, 38, 0.3)';
        badgeEl.style.color = '#ffa726';
        iconEl.textContent = '😐';
        scoreEl.textContent = 'OPSEC: FAIR';
    } else if (score < 90) {
        badgeEl.style.background = 'rgba(0, 230, 118, 0.1)';
        badgeEl.style.borderColor = 'rgba(0, 230, 118, 0.3)';
        badgeEl.style.color = '#00e676';
        iconEl.textContent = '🙂';
        scoreEl.textContent = 'OPSEC: GOOD';
    } else {
        badgeEl.style.background = 'rgba(33, 150, 243, 0.1)';
        badgeEl.style.borderColor = 'rgba(33, 150, 243, 0.3)';
        badgeEl.style.color = '#2196F3';
        iconEl.textContent = '😎';
        scoreEl.textContent = 'OPSEC: MAX';
    }
}

// ═══════════════════════════════════════════════════════════════════
// QUICK ACTIONS
// ═══════════════════════════════════════════════════════════════════
function initQuickActions() {
    // Clear Data
    const clearBtn = document.getElementById('btn-clear-data');
    if (clearBtn) {
        clearBtn.addEventListener('click', async () => {
            try {
                const { ensureFeaturePermissions, showPermToast } = await import(
                    brw.runtime.getURL('js/optional-permissions.mjs')
                );
                const result = await ensureFeaturePermissions('browsingDataTools');
                if (!result.granted) {
                    showPermToast('Clear-data permission declined. Try again anytime.', { isError: true });
                    return;
                }
            } catch (err) {
                console.error(err);
                return;
            }
            brw.runtime.sendMessage({ action: 'clearData' }).catch(() => { });
            flashButton(clearBtn, 'Data Cleared!');
        });
    }

    // Rotate Identity (legacy button may be absent after module removal)
    const rotateBtn = document.getElementById('btn-rotate-identity');
    if (rotateBtn) {
        rotateBtn.style.display = 'none';
    }

    // Pause Shields
    let isPaused = false;
    let pausedStates = {};
    const pauseBtn = document.getElementById('btn-pause-shields');
    if (pauseBtn) {
        pauseBtn.addEventListener('click', () => {
            const icon = document.getElementById('pause-shield-icon');
            const text = document.getElementById('pause-shield-text');
            if (!isPaused) {
                // Pause
                isPaused = true;
                pausedStates = JSON.parse(JSON.stringify(moduleStates));
                for (const mod in moduleStates) {
                    if (moduleStates[mod]) handleModuleToggle(mod, false);
                }
                icon.textContent = '▶️';
                text.textContent = 'Resume Shields';
                pauseBtn.style.color = '#4CAF50';
                pauseBtn.style.background = 'rgba(76, 175, 80, 0.1)';
                pauseBtn.style.borderColor = 'rgba(76, 175, 80, 0.3)';
            } else {
                // Resume
                isPaused = false;
                for (const mod in pausedStates) {
                    if (pausedStates[mod]) handleModuleToggle(mod, true);
                }
                icon.textContent = '⏸️';
                text.textContent = 'Pause All Shields';
                pauseBtn.style.color = '#ff9800';
                pauseBtn.style.background = 'rgba(255, 152, 0, 0.1)';
                pauseBtn.style.borderColor = 'rgba(255, 152, 0, 0.3)';
            }
        });
    }

    // Run OPSEC Tests
    const testBtn = document.getElementById('btn-run-tests');
    if (testBtn) {
        testBtn.addEventListener('click', runOpsecTests);
    }
}

// ═══════════════════════════════════════════════════════════════════
// OPSEC TESTS (Placeholder)
// ═══════════════════════════════════════════════════════════════════
async function runOpsecTests() {
    const btn = document.getElementById('btn-run-tests');
    btn.textContent = '⏳ Running Tests...';
    btn.disabled = true;

    // Placeholder — each test will be implemented as we build modules
    const tests = ['canvas', 'webgl', 'webrtc', 'audio', 'useragent', 'referrer', 'dns', 'honeypot'];

    for (const test of tests) {
        const resultEl = document.getElementById(`result-${test}`);
        if (resultEl) {
            resultEl.textContent = 'Testing...';
            resultEl.className = 'test-result';
        }
    }

    // Simulate test delay (will be replaced with real checks)
    await new Promise(r => setTimeout(r, 1500));

    for (const test of tests) {
        const resultEl = document.getElementById(`result-${test}`);
        if (resultEl) {
            resultEl.textContent = 'Not implemented yet';
            resultEl.className = 'test-result warn';
        }
    }

    btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run All Tests';
    btn.disabled = false;
}

// ═══════════════════════════════════════════════════════════════════
// UTILITIES
// ═══════════════════════════════════════════════════════════════════
function flashButton(btn, text) {
    const original = btn.querySelector('span:last-child')?.textContent;
    const textEl = btn.querySelector('span:last-child');
    if (textEl) {
        textEl.textContent = text;
        setTimeout(() => { textEl.textContent = original; }, 1000);
    }
}

// ═══════════════════════════════════════════════════════════════════
// DASHBOARD CUSTOMIZER & QUICK ACTIONS
// ═══════════════════════════════════════════════════════════════════
function initDashboardCustomizer() {
    const btnEdit = document.getElementById('btn-edit-dashboard');
    const editModeContainer = document.getElementById('dashboard-edit-mode');
    const quickActionsGrid = document.getElementById('quick-actions-grid');
    const btnSave = document.getElementById('btn-save-dashboard');

    if (!btnEdit || !quickActionsGrid || !editModeContainer) return;

    const checkboxes = editModeContainer.querySelectorAll('.qa-checkbox');

    const ALL_ACTIONS = {
        'qa-clear-site': { icon: '🧹', label: 'Clear Site', title: 'Clear Current Site Data', color: '#ff5252', bg: 'rgba(244, 67, 54, 0.1)' },
        'qa-clear-cache': { icon: '🗑️', label: 'Clear Cache', title: 'Clear Global Cache', color: '#ff9800', bg: 'rgba(255, 152, 0, 0.1)' },
        'qa-clear-history': { icon: '🕒', label: 'Clear History', title: 'Delete Last Hour History', color: '#9c27b0', bg: 'rgba(156, 39, 176, 0.1)' },
        'qa-clear-cookies': { icon: '🍪', label: 'Clear Cookies', title: 'Nuke All Active Cookies', color: '#e91e63', bg: 'rgba(233, 30, 99, 0.1)' }
    };

    const renderGrid = (activeIds) => {
        quickActionsGrid.innerHTML = '';
        activeIds.forEach(id => {
            const meta = ALL_ACTIONS[id];
            if (!meta) return;

            const btn = document.createElement('button');
            btn.className = 'action-btn';
            btn.id = 'btn-' + id;
            btn.title = meta.title;
            btn.style.cssText = `background: ${meta.bg}; border: 1px solid ${meta.color}40; border-radius: 8px; padding: 10px; color: ${meta.color}; font-weight: bold; cursor: pointer; display: flex; flex-direction: column; align-items: center; gap: 5px;`;

            const icon = document.createElement('span');
            icon.className = 'action-icon';
            icon.style.fontSize = '20px';
            icon.textContent = meta.icon;

            const lbl = document.createElement('span');
            lbl.style.fontSize = '11px';
            lbl.textContent = meta.label;

            btn.appendChild(icon);
            btn.appendChild(lbl);

            btn.addEventListener('click', async () => {
                const originalText = lbl.textContent;
                try {
                    const { ensureFeaturePermissions, showPermToast } = await import(
                        brw.runtime.getURL('js/optional-permissions.mjs')
                    );
                    const result = await ensureFeaturePermissions('browsingDataTools');
                    if (!result.granted) {
                        showPermToast('Clear-data permission declined. Try again anytime.', { isError: true });
                        return;
                    }
                } catch (err) {
                    console.error(err);
                    return;
                }
                lbl.textContent = 'Running...';
                brw.runtime.sendMessage({ action: 'executeQuickAction', type: id }, () => {
                    lbl.textContent = 'Done!';
                    setTimeout(() => { lbl.textContent = originalText; }, 1500);
                });
            });

            quickActionsGrid.appendChild(btn);
        });
    };

    // Load saved preferences (Default to Site Data and Global Cache)
    brw.storage.local.get({ dashboardActions: ['qa-clear-site', 'qa-clear-cache'] }, (data) => {
        const activeIds = data.dashboardActions;
        checkboxes.forEach(chk => {
            chk.checked = activeIds.includes(chk.value);
        });
        renderGrid(activeIds);
    });

    btnEdit.addEventListener('click', () => {
        const isHidden = editModeContainer.style.display === 'none';
        editModeContainer.style.display = isHidden ? 'block' : 'none';
        btnEdit.style.background = isHidden ? 'rgba(255,255,255,0.1)' : 'transparent';
    });

    btnSave.addEventListener('click', () => {
        const activeIds = Array.from(checkboxes).filter(chk => chk.checked).map(chk => chk.value);
        brw.storage.local.set({ dashboardActions: activeIds }, () => {
            renderGrid(activeIds);
            editModeContainer.style.display = 'none';
            btnEdit.style.background = 'transparent';
        });
    });
}

function showDNRWarning(errorMsg) {
    const errorBanner = document.createElement('div');
    errorBanner.className = 'dnr-error-banner';
    errorBanner.style.cssText = 'position: fixed; bottom: 15px; left: 15px; right: 15px; background: rgba(239, 83, 80, 0.95); color: white; padding: 12px; border-radius: 8px; z-index: 10000; font-size: 11px; text-align: center; box-shadow: 0 4px 10px rgba(0,0,0,0.3); font-weight: 600; line-height: 1.4; border: 1px solid rgba(255,255,255,0.2); animation: slideUp 0.3s ease;';

    const icon = document.createTextNode('⚠️ ');
    errorBanner.appendChild(icon);

    const strong = document.createElement('strong');

    if (errorMsg.includes('limit') || errorMsg.includes('Internal error')) {
        strong.textContent = 'Browser Rule Limit Exceeded:';
        errorBanner.appendChild(strong);
        errorBanner.appendChild(document.createElement('br'));
        const detail = document.createElement('span');
        detail.style.fontWeight = 'normal';
        detail.textContent = 'Chrome MV3 limits dynamic rules to ~30k. Disable some lists, or pick a lighter combo.';
        errorBanner.appendChild(detail);
    } else {
        strong.textContent = 'Switch Failed: ';
        errorBanner.appendChild(strong);
        errorBanner.appendChild(document.createTextNode(errorMsg));
    }

    document.body.appendChild(errorBanner);

    setTimeout(() => {
        errorBanner.style.animation = 'slideDown 0.3s ease';
        setTimeout(() => errorBanner.remove(), 300);
    }, 7000);
}

async function initDynamicThreatLists() {
    // Live threats are checkboxes under AdBlocker & Shield.
}

// ═══════════════════════════════════════════════════════════════════
// RECENT ALERTS LOG SYSTEM
// ═══════════════════════════════════════════════════════════════════
function initAlertLog() {
    const alertBtn = document.getElementById('btn-alert-log');
    const alertPanel = document.getElementById('alert-log-panel');
    const clearBtn = document.getElementById('btn-clear-alerts');

    if (!alertBtn || !alertPanel) return;

    // Toggle dropdown panel
    alertBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = alertPanel.style.display !== 'none';
        alertPanel.style.display = isOpen ? 'none' : 'block';
        if (!isOpen) {
            renderAlertLog();
        }
    });

    // Close panel when clicking anywhere outside
    document.addEventListener('click', (e) => {
        if (alertPanel.style.display !== 'none' && !alertPanel.contains(e.target) && !alertBtn.contains(e.target)) {
            alertPanel.style.display = 'none';
        }
    });

    // Clear alert history
    if (clearBtn) {
        const handleClear = async (e) => {
            e.stopPropagation();
            e.preventDefault();
            try {
                await brw.storage.local.set({ alertLog: [] });
                await renderAlertLog();
            } catch (err) {
                console.error('[OPSECHub] Failed to clear alert log:', err);
            }
        };
        clearBtn.addEventListener('click', handleClear);
    }

    // Initial render and red dot badge check
    renderAlertLog();
}

async function renderAlertLog() {
    const alertList = document.getElementById('alert-log-list');
    const alertDot = document.getElementById('alert-dot');

    try {
        const data = await brw.storage.local.get({ alertLog: [] });
        const logs = data.alertLog || [];

        // Update notification dot indicator
        if (alertDot) {
            alertDot.style.display = logs.length > 0 ? 'block' : 'none';
        }

        if (!alertList) return;
        alertList.innerHTML = '';

        if (logs.length === 0) {
            alertList.innerHTML = '<div class="alert-empty">No recent alerts recorded</div>';
            return;
        }

        const iconMap = {
            mediaBlock: '📸',
            clipboardGuard: '📋',
            locationBlock: '🗺️',
            webrtcBlock: '🌐',
            googleTelemetry: '🚫',
            proxyManager: '🔒'
        };

        const labelMap = {
            mediaBlock: 'Camera & Mic Guard',
            clipboardGuard: 'Clipboard Guard',
            locationBlock: 'Location Guard',
            webrtcBlock: 'WebRTC Leak Block',
            googleTelemetry: 'Telemetry Block',
            proxyManager: 'Proxy Defense'
        };

        const actionCopy = {
            'access camera/microphone': 'Blocked camera & microphone access',
            'access camera/microphone (legacy)': 'Blocked camera & microphone access',
            'access geolocation location': 'Blocked location access',
            'read clipboard text': 'Blocked a clipboard read attempt',
            'read clipboard data': 'Blocked a clipboard read attempt',
            'paste text': 'Blocked a paste attempt'
        };

        logs.forEach((log) => {
            const icon = iconMap[log.module] || '🛡️';
            const title = labelMap[log.module] || log.module || 'OPSEC Alert';
            const desc = actionCopy[log.action]
                || (log.action ? `Blocked attempt to ${log.action}` : 'Access attempt blocked');

            // Format timestamp (Date + Time)
            let dateStr = '';
            if (log.time) {
                const d = new Date(log.time);
                const day = String(d.getDate()).padStart(2, '0');
                const month = String(d.getMonth() + 1).padStart(2, '0');
                const year = d.getFullYear();
                const hours = String(d.getHours()).padStart(2, '0');
                const mins = String(d.getMinutes()).padStart(2, '0');
                const secs = String(d.getSeconds()).padStart(2, '0');
                dateStr = `${day}/${month}/${year} ${hours}:${mins}:${secs}`;
            }

            const item = document.createElement('div');
            item.className = 'alert-entry';

            const iconSpan = document.createElement('span');
            iconSpan.className = 'alert-entry-icon';
            iconSpan.textContent = icon;

            const bodyDiv = document.createElement('div');
            bodyDiv.className = 'alert-entry-body';

            const titleSpan = document.createElement('span');
            titleSpan.className = 'alert-entry-title';
            titleSpan.textContent = title;

            const descSpan = document.createElement('span');
            descSpan.className = 'alert-entry-desc';
            descSpan.textContent = desc;

            bodyDiv.appendChild(titleSpan);
            bodyDiv.appendChild(descSpan);

            if (dateStr) {
                const timeSpan = document.createElement('span');
                timeSpan.className = 'alert-entry-time';
                timeSpan.textContent = `⏰ ${dateStr}`;
                bodyDiv.appendChild(timeSpan);
            }

            item.appendChild(iconSpan);
            item.appendChild(bodyDiv);
            alertList.appendChild(item);
        });
    } catch (err) {
        console.error('[OPSECHub] Failed to render alert log:', err);
    }
}
