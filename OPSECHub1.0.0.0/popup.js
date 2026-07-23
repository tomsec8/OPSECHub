/**
 * OPSECHub – Main Popup Controller
 * Handles UI state, navigation, toggle sync, and module management.
 */

const brw = typeof browser !== 'undefined' ? browser : chrome;

// ═══════════════════════════════════════════════════════════════════
// MODULE REGISTRY
// ═══════════════════════════════════════════════════════════════════
const MODULE_REGISTRY = {

    antiFingerprint: { label: 'Fingerprint', icon: '🎭', onLabel: 'Spoofed', offLabel: 'Exposed' },
    webrtcBlock: { label: 'WebRTC', icon: '📡', onLabel: 'Blocked', offLabel: 'Leaking' },
    userAgentSpoof: { label: 'User-Agent', icon: '🕵️', onLabel: 'Spoofed', offLabel: 'Real' },
    googleTelemetry: { label: 'Google Telemetry', icon: '🚫', onLabel: 'Blocked', offLabel: 'Leaking' },
    privacyHeaders: { label: 'Do Not Track', icon: '🛡️', onLabel: 'Active', offLabel: 'Off' },
    searchReferrerBlock: { label: 'Search Stealth', icon: '🔍', onLabel: 'Hidden', offLabel: 'Leaking' },
    forceHttps: { label: 'HTTPS', icon: '🔒', onLabel: 'Enforced', offLabel: 'Off' },
    cookieGuard: { label: 'Cookies', icon: '🍪', onLabel: 'Guarded', offLabel: 'Off' },
    referrerControl: { label: 'Referrer', icon: '🔗', onLabel: 'Stripped', offLabel: 'Leaking' },
    urlSanitizer: { label: 'URL Sanitizer', icon: '✂️', onLabel: 'Active', offLabel: 'Off' },
    clickjackXss: { label: 'XSS Guard', icon: '🛡️', onLabel: 'Active', offLabel: 'Off' },
    locationBlock: { label: 'Location Guard', icon: '📍', onLabel: 'Spoofed', offLabel: 'Real' },
    mediaBlock: { label: 'Camera & Mic', icon: '📸', onLabel: 'Blocked', offLabel: 'Exposed' },
    hardwareMask: { label: 'Hardware Mask', icon: '💻', onLabel: 'Spoofed', offLabel: 'Exposed' },
    proxyManager: { label: 'Proxy', icon: '🌐', onLabel: 'Connected', offLabel: 'Direct' },
    networkExport: { label: 'Net Export', icon: '💾', onLabel: 'Recording', offLabel: 'Off' },
    decoyTraffic: { label: 'Decoy Traffic', icon: '🌪️', onLabel: 'Active', offLabel: 'Off' },
};

// ═══════════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════════
let moduleStates = {};

// ═══════════════════════════════════════════════════════════════════
// INITIALIZATION
// ═══════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', async () => {
    await loadModuleStates();
    initNavigation();
    initDashboardCustomizer();
    initToggles();
    initQuickActions();
    updateShieldStatus();
    initCustomBlocklists();
    initDynamicThreatLists();
    initAlertLog();

    // iOS Inline Settings Toggles
    const settingsBtns = document.querySelectorAll('.settings-btn');
    settingsBtns.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.stopPropagation();
            const moduleId = btn.id.replace('btn-settings-', '');
            const panel = document.getElementById(`settings-panel-${moduleId}`);
            if (panel) {
                panel.classList.toggle('open');
            }
        });
    });

    const updateShieldMetaInfo = async (mode, elementId) => {
        const infoEl = document.getElementById(elementId);
        if (!infoEl) return;
        const targetMode = (!mode || mode === 'disabled') ? 'Core_Normal' : mode;
        try {
            const res = await fetch(brw.runtime.getURL('rules/metadata.json'));
            if (res.ok) {
                const meta = await res.json();
                const data = meta[targetMode];
                if (data) {
                    const countFormatted = data.count ? data.count.toLocaleString() : '';
                    const dateStr = data.lastUpdated || '2026-07-22';
                    if (mode === 'disabled') {
                        infoEl.innerHTML = `📅 Ruleset Release Date: <strong>${dateStr}</strong> (AdBlocker Disabled)`;
                    } else {
                        infoEl.innerHTML = `📅 Ruleset Release Date: <strong>${dateStr}</strong> (${countFormatted} rules)`;
                    }
                } else {
                    infoEl.textContent = '';
                }
            }
        } catch (_) {
            infoEl.textContent = '';
        }
    };

    // Sync AdBlocker Ruleset (coreShieldMode)
    const inlineShieldMode = document.getElementById('inline-opt-shield-mode');
    if (inlineShieldMode) {
        brw.storage.local.get({ coreShieldMode: 'disabled' }, (data) => {
            inlineShieldMode.value = data.coreShieldMode;
            updateShieldMetaInfo(data.coreShieldMode, 'inline-shield-mode-info');
        });
        inlineShieldMode.addEventListener('change', (e) => {
            const newMode = e.target.value;
            updateShieldMetaInfo(newMode, 'inline-shield-mode-info');
            brw.storage.local.set({ coreShieldMode: newMode }, () => {
                brw.runtime.sendMessage({ action: 'switchCoreRuleset', activeRuleset: newMode });
                updateShieldUI(newMode);
                updateShieldStatus();
            });
        });
    }

    // Sync Anti-Fingerprint Mode
    const inlineAfpMode = document.getElementById('inline-opt-anti-fingerprint-mode');
    if (inlineAfpMode) {
        brw.storage.local.get({ antiFingerprintMode: 'blend-in' }, (data) => {
            inlineAfpMode.value = data.antiFingerprintMode;
        });
        inlineAfpMode.addEventListener('change', (e) => {
            const newMode = e.target.value;
            brw.storage.local.set({ antiFingerprintMode: newMode }, () => {
                // If module is currently enabled, re-trigger it to apply mode
                if (moduleStates['antiFingerprint']) {
                    brw.runtime.sendMessage({ action: 'toggleModule', module: 'antiFingerprint', enabled: true });
                }
            });
        });
    }

    // Sync User-Agent Profile
    const inlineUaProfile = document.getElementById('uaProfileSelect');
    if (inlineUaProfile) {
        brw.storage.local.get({ uaProfile: 'win_chrome' }, (data) => {
            inlineUaProfile.value = data.uaProfile;
        });
        inlineUaProfile.addEventListener('change', (e) => {
            const newProfile = e.target.value;
            brw.storage.local.set({ uaProfile: newProfile }, () => {
                // If module is currently enabled, re-trigger it
                if (moduleStates['userAgentSpoof']) {
                    brw.runtime.sendMessage({ action: 'toggleModule', module: 'userAgentSpoof', enabled: true });
                }
            });
        });
    }

    // Sync Decoy Intensity
    const inlineDecoyInt = document.getElementById('inline-opt-decoy-intensity');
    if (inlineDecoyInt) {
        brw.storage.local.get({ decoyIntensity: 'medium' }, (data) => {
            inlineDecoyInt.value = data.decoyIntensity;
        });
        inlineDecoyInt.addEventListener('change', (e) => {
            const newInt = e.target.value;
            brw.storage.local.set({ decoyIntensity: newInt }, () => {
                if (moduleStates['decoyTraffic']) {
                    brw.runtime.sendMessage({ action: 'toggleModule', module: 'decoyTraffic', enabled: true });
                }
            });
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
                const isEnabled = !!newStates[module];
                if (toggle.checked !== isEnabled) {
                    toggle.checked = isEnabled;
                }
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

        if (changes.coreShieldMode) {
            const newMode = changes.coreShieldMode.newValue || 'disabled';
            const inlineShieldMode = document.getElementById('inline-opt-shield-mode');
            if (inlineShieldMode && inlineShieldMode.value !== newMode) {
                inlineShieldMode.value = newMode;
            }
            updateShieldMetaInfo(newMode, 'inline-shield-mode-info');
            updateShieldUI(newMode);
            updateShieldStatus();
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

        if (changes.uaProfile) {
            const newProfile = changes.uaProfile.newValue || 'win_chrome';
            const inlineUaProfile = document.getElementById('uaProfileSelect');
            if (inlineUaProfile && inlineUaProfile.value !== newProfile) {
                inlineUaProfile.value = newProfile;
            }
        }

        if (changes.antiFingerprintMode) {
            const newAfp = changes.antiFingerprintMode.newValue || 'blend-in';
            const inlineAfpMode = document.getElementById('inline-opt-anti-fingerprint-mode');
            if (inlineAfpMode && inlineAfpMode.value !== newAfp) {
                inlineAfpMode.value = newAfp;
            }
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





        if (changes.decoyIntensity) {
            const newDecoy = changes.decoyIntensity.newValue || 'medium';
            const inlineDecoy = document.getElementById('inline-opt-decoy-intensity');
            if (inlineDecoy && inlineDecoy.value !== newDecoy) {
                inlineDecoy.value = newDecoy;
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
    return new Promise((resolve) => {
        brw.storage.local.get({ moduleStates: {} }, (data) => {
            moduleStates = data.moduleStates || {};
            resolve();
        });
    });
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

    // Refresh all button
    const refreshBtn = document.getElementById('btn-refresh-all');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            // Give a visual feedback first
            refreshBtn.style.transform = 'rotate(360deg)';
            refreshBtn.style.transition = 'transform 1s ease-in-out';

            brw.runtime.sendMessage({ action: 'refreshRules' }, (res) => {
                setTimeout(() => {
                    refreshBtn.style.transform = 'none';
                    refreshBtn.style.transition = 'none';
                    if (res && res.success) {
                        const orig = refreshBtn.innerHTML;
                        refreshBtn.innerHTML = '✓';
                        setTimeout(() => refreshBtn.innerHTML = orig, 2000);
                    } else {
                        console.error('[OPSECHub] Sync failed:', res?.error);
                    }
                }, 1000);
            });
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
            handleModuleToggle(moduleName, e.target.checked);
        }
    });

    // Apply visual state to dashboard cards and sync static
    brw.storage.local.get({ moduleStates: {}, uaProfile: 'win_chrome', antiFingerprintMode: 'blend-in', locationMode: 'block', masterSwitch: true, excludedDomains: [], coreShieldMode: 'disabled' }).then(data => {

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
        if (btnMaster) {
            updateMasterUI(data.masterSwitch);
            btnMaster.addEventListener('click', () => {
                const isNowOn = document.body.classList.contains('master-off'); // toggling ON if currently OFF

                // Disable button and show loading state
                btnMaster.disabled = true;
                btnMaster.style.opacity = '0.4';
                btnMaster.style.cursor = 'wait';

                brw.runtime.sendMessage({ action: 'toggleMaster', enabled: isNowOn }, (response) => {
                    brw.storage.local.set({ masterSwitch: isNowOn }).then(() => {
                        updateMasterUI(isNowOn);

                        // Restore button state
                        btnMaster.disabled = false;
                        btnMaster.style.opacity = '';
                        btnMaster.style.cursor = '';
                    });
                });
            });
        }
        document.querySelectorAll('.module-toggle').forEach(toggle => {
            const module = toggle.getAttribute('data-module');
            if (module === 'adBlocker') {
                toggle.checked = data.coreShieldMode !== 'disabled';
                toggle.addEventListener('change', (e) => {
                    const enabled = e.target.checked;
                    const newMode = enabled ? 'Core_Normal' : 'disabled';
                    toggle.disabled = true;

                    brw.runtime.sendMessage({ action: 'switchCoreRuleset', activeRuleset: newMode }, (response) => {
                        toggle.disabled = false;
                        if (response && !response.success) {
                            toggle.checked = !enabled; // Revert visually
                            showDNRWarning(response.error || 'Unknown error');
                            return;
                        }

                        brw.storage.local.set({ coreShieldMode: newMode }).then(() => {
                            const valShield = document.getElementById('val-shield');
                            const descShield = document.getElementById('desc-shield');
                            const shieldCard = document.getElementById('status-shield');
                            if (valShield) {
                                valShield.textContent = enabled ? 'HaGeZi Pro' : 'Disabled';
                                valShield.className = 'status-card-value ' + (enabled ? 'status-on' : 'status-off');
                            }
                            if (descShield) descShield.textContent = enabled ? 'Recommended all-round protection.' : 'All core protection is off.';
                            if (shieldCard) shieldCard.classList.toggle('active', enabled);
                        });
                    });
                });
            } else {
                toggle.checked = !!data.moduleStates[module];
            }
        });

    });

    updateDashboardCards();
    initShieldDropdowns();
}

function updateShieldUI(value) {
    const valShield = document.getElementById('val-shield');
    const descShield = document.getElementById('desc-shield');
    const shieldCard = document.getElementById('status-shield');
    let label = 'Disabled';
    let desc = 'All core protection is off.';
    let isOn = false;

    if (value === 'Core_Light') { label = 'HaGeZi Light'; desc = 'Basic protection (Blocks Ads & Trackers).'; isOn = true; }
    else if (value === 'Core_Multi') { label = 'HaGeZi Multi'; desc = 'Multi-protection (Ads, Trackers, Telemetry).'; isOn = true; }
    else if (value === 'Core_Normal') { label = 'HaGeZi Pro'; desc = 'Recommended all-round protection.'; isOn = true; }
    else if (value === 'Core_Pro_Plus') { label = 'HaGeZi Pro+'; desc = 'Enhanced protection based on Pro.'; isOn = true; }
    else if (value === 'Core_Aggressive') { label = 'HaGeZi Ultimate'; desc = 'Maximum aggressive protection (may break sites).'; isOn = true; }
    else if (value === 'custom') { label = 'Custom'; desc = 'Using user-defined surgical lists.'; isOn = true; }

    if (valShield) {
        valShield.textContent = label;
        valShield.className = 'status-card-value ' + (isOn ? 'status-on' : 'status-off');
    }
    if (descShield) descShield.textContent = desc;
    if (shieldCard) shieldCard.classList.toggle('active', isOn);

    const customContainer = document.getElementById('dynamic-custom-blocklists');
    if (customContainer) {
        customContainer.style.display = (value === 'custom') ? 'flex' : 'none';
    }
}

function initShieldDropdowns() {
    const btnConfigure = document.getElementById('btn-configure-shield');

    if (btnConfigure) {
        btnConfigure.addEventListener('click', () => {
            if (brw.runtime.openOptionsPage) {
                brw.runtime.openOptionsPage();
            } else {
                window.open(brw.runtime.getURL('options.html'));
            }
        });
    }

    brw.storage.local.get({ coreShieldMode: 'disabled' }, (data) => {
        updateShieldUI(data.coreShieldMode);
    });
}

async function initCustomBlocklists() {
    const container = document.getElementById('dynamic-custom-blocklists');
    if (!container) return;

    let metadata = {};
    try {
        const res = await fetch(brw.runtime.getURL('rules/metadata.json'));
        if (res.ok) metadata = await res.json();
    } catch (e) {
        console.warn('Failed to load rules metadata:', e);
        return;
    }

    try {
        const enabledIds = await brw.declarativeNetRequest.getEnabledRulesets();
        container.innerHTML = '';
        // Insert Progress Bar at the top
        const counterHeader = document.createElement('div');
        counterHeader.className = 'rules-counter-container';
        counterHeader.style.cssText = 'padding: 10px; background: rgba(0,0,0,0.2); border-radius: 6px; margin-bottom: 5px; font-size: 11px;';
        const flexDiv = document.createElement('div');
        flexDiv.style.cssText = 'display: flex; justify-content: space-between; margin-bottom: 6px;';

        const labelSpan = document.createElement('span');
        labelSpan.style.cssText = 'color: var(--text-secondary); font-weight: 600;';
        labelSpan.textContent = 'Browser Rules Capacity';

        const valueSpan = document.createElement('span');
        valueSpan.id = 'rules-counter-text';
        valueSpan.style.cssText = 'color: var(--text-primary); font-weight: bold;';
        valueSpan.textContent = 'Loading...';

        flexDiv.appendChild(labelSpan);
        flexDiv.appendChild(valueSpan);

        const trackDiv = document.createElement('div');
        trackDiv.style.cssText = 'width: 100%; height: 6px; background: var(--bg-card); border-radius: 3px; overflow: hidden;';

        const barDiv = document.createElement('div');
        barDiv.id = 'rules-progress-bar';
        barDiv.style.cssText = 'height: 100%; width: 0%; background: var(--accent-primary); transition: width 0.3s, background 0.3s;';

        trackDiv.appendChild(barDiv);

        counterHeader.appendChild(flexDiv);
        counterHeader.appendChild(trackDiv);
        container.appendChild(counterHeader);

        const updateRulesCounter = async () => {
            if (!brw.declarativeNetRequest.getAvailableStaticRuleCount) return;
            try {
                const available = await brw.declarativeNetRequest.getAvailableStaticRuleCount();
                const max = 330000;
                const used = max - available;
                const percent = (used / max) * 100;

                const textEl = document.getElementById('rules-counter-text');
                const barEl = document.getElementById('rules-progress-bar');

                if (textEl) textEl.textContent = `${used.toLocaleString()} / ${max.toLocaleString()}`;
                if (barEl) {
                    barEl.style.width = `${Math.min(percent, 100)}%`;
                    if (percent > 90) barEl.style.background = '#ef5350';
                    else if (percent > 75) barEl.style.background = '#ffa726';
                    else barEl.style.background = 'var(--accent-primary)';
                }
            } catch (e) { }
        };

        // Group by category
        const categories = {};
        for (const [id, meta] of Object.entries(metadata)) {
            const cat = meta.category || 'General';
            if (!categories[cat]) categories[cat] = [];
            categories[cat].push({ id, ...meta });
        }

        // Render by category
        for (const [catName, lists] of Object.entries(categories)) {
            // Sort ascending by rule count
            lists.sort((a, b) => (a.count || 0) - (b.count || 0));

            const catHeader = document.createElement('div');
            catHeader.style.cssText = 'margin-top: 10px; margin-bottom: 6px; border-bottom: 1px solid var(--border-color); padding-bottom: 4px;';
            const h3 = document.createElement('h3');
            h3.style.cssText = 'margin: 0; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--accent-primary); font-weight: 700;';
            h3.textContent = `📁 ${catName}`;
            catHeader.appendChild(h3);
            container.appendChild(catHeader);

            for (const list of lists) {
                const id = list.id;
                const isChecked = enabledIds.some(eid => eid === id || eid.startsWith(id + '_'));
                const title = list.title || id;
                const desc = list.description || 'Custom user blocklist.';
                const countStr = list.count ? ` (${list.count.toLocaleString()} rules)` : '';
                const ruleCount = list.count || 0;

                const row = document.createElement('div');
                row.style.cssText = 'display: flex; justify-content: space-between; align-items: center; background: rgba(0,0,0,0.1); padding: 8px 12px; border-radius: 6px; border: 1px solid var(--border-color); margin-bottom: 6px;';
                const infoDiv = document.createElement('div');
                infoDiv.style.cssText = 'flex: 1; padding-right: 10px;';

                const h4 = document.createElement('h4');
                h4.style.cssText = 'margin: 0; font-size: 12px; color: var(--text-primary); font-weight: 600;';
                h4.textContent = title;

                const descDiv = document.createElement('div');
                descDiv.style.cssText = 'font-size: 10px; color: var(--text-muted); margin-top: 2px;';
                descDiv.textContent = desc + countStr;

                infoDiv.appendChild(h4);
                infoDiv.appendChild(descDiv);

                const label = document.createElement('label');
                label.className = 'toggle-switch';
                label.style.cssText = 'transform: scale(0.85); transform-origin: right center;';

                const input = document.createElement('input');
                input.type = 'checkbox';
                input.className = 'static-rule-toggle';
                input.dataset.ruleset = id;
                input.dataset.count = ruleCount;
                input.dataset.title = title;
                if (isChecked) input.checked = true;

                const slider = document.createElement('span');
                slider.className = 'toggle-slider';

                label.appendChild(input);
                label.appendChild(slider);

                row.appendChild(infoDiv);
                row.appendChild(label);
                container.appendChild(row);
            }
        }

        updateRulesCounter();

        const checkboxes = container.querySelectorAll('.static-rule-toggle');
        checkboxes.forEach(toggle => {
            toggle.addEventListener('change', async (e) => {
                const rulesetId = e.target.dataset.ruleset;
                const isEnabled = e.target.checked;
                const count = parseInt(e.target.dataset.count, 10) || 0;
                const title = e.target.dataset.title || rulesetId;

                if (isEnabled) {
                    try {
                        const available = await brw.declarativeNetRequest.getAvailableStaticRuleCount();
                        if (count > available) {
                            e.target.checked = false;
                            showDNRWarning(`Not enough rule capacity to enable "${title}". Requires ${count.toLocaleString()}, but only ${available.toLocaleString()} available.`);
                            return;
                        }
                    } catch (err) { }
                }

                e.target.disabled = true; // prevent spamming
                brw.runtime.sendMessage({
                    action: 'toggleStaticRuleset',
                    rulesetId: rulesetId,
                    enabled: isEnabled
                }, (response) => {
                    e.target.disabled = false;
                    if (response && !response.success) {
                        e.target.checked = !isEnabled; // Revert visually
                        showDNRWarning(response.error);
                    }
                    setTimeout(updateRulesCounter, 300);
                });
            });
        });

    } catch (err) {
        console.error('Failed to init custom blocklists:', err);
    }
}

function handleModuleToggle(moduleName, isEnabled) {
    moduleStates[moduleName] = isEnabled;
    saveModuleStates();

    // Sync all toggles with same module name
    document.querySelectorAll(`input[data-module="${moduleName}"]`).forEach(input => {
        input.checked = isEnabled;
    });

    // Update dashboard card visual
    updateDashboardCards();
    updateShieldStatus();

    // Send message to background to activate/deactivate module
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

    // Core shield
    const coreSelect = document.getElementById('inline-opt-shield-mode');
    if (coreSelect) {
        if (coreSelect.value === 'Core_Light') score += 20;
        else if (coreSelect.value === 'Core_Multi') score += 30;
        else if (coreSelect.value === 'Core_Normal') score += 40;
        else if (coreSelect.value === 'Core_Pro_Plus') score += 50;
        else if (coreSelect.value === 'Core_Aggressive') score += 60;
        else if (coreSelect.value === 'custom') score += 30;
    }

    // Active modules
    const activeModules = Object.values(moduleStates).filter(Boolean).length;
    score += (activeModules * 5); // +5 per module

    if (score > 100) score = 100;
    if (coreSelect && coreSelect.value === 'disabled' && activeModules === 0) score = 0;

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
        clearBtn.addEventListener('click', () => {
            brw.runtime.sendMessage({ action: 'clearData' }).catch(() => { });
            flashButton(clearBtn, 'Data Cleared!');
        });
    }

    // Rotate Identity
    const rotateBtn = document.getElementById('btn-rotate-identity');
    if (rotateBtn) {
        rotateBtn.addEventListener('click', () => {
            const profiles = ['win_chrome', 'mac_safari', 'linux_firefox', 'ios_safari', 'android_chrome'];
            brw.storage.local.get({ uaProfile: 'win_chrome' }).then(data => {
                let next = profiles[(profiles.indexOf(data.uaProfile) + 1) % profiles.length];
                brw.storage.local.set({ uaProfile: next }).then(() => {
                    const uaSelect = document.getElementById('uaProfileSelect');
                    if (uaSelect) uaSelect.value = next;

                    // Enable the modules if they were off, otherwise just re-trigger them to apply the new identity
                    if (!moduleStates['userAgentSpoof']) handleModuleToggle('userAgentSpoof', true);
                    else brw.runtime.sendMessage({ action: 'toggleModule', module: 'userAgentSpoof', enabled: true });

                    if (!moduleStates['antiFingerprint']) handleModuleToggle('antiFingerprint', true);
                    else brw.runtime.sendMessage({ action: 'toggleModule', module: 'antiFingerprint', enabled: true });

                    flashButton(rotateBtn, 'Rotated!');
                });
            });
        });
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

            // Send action to background on click
            btn.addEventListener('click', () => {
                const originalText = lbl.textContent;
                lbl.textContent = 'Running...';
                brw.runtime.sendMessage({ action: 'executeQuickAction', type: id }, () => {
                    lbl.textContent = 'Done!';
                    setTimeout(() => lbl.textContent = originalText, 1500);
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
        detail.textContent = 'Chrome MV3 limits rules to 330k. Try disabling other adblockers, or select Normal (Pro) list.';
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

// Append to popup.js to handle Live Threat Intelligence


// Append to popup.js to handle Live Threat Intelligence

async function initDynamicThreatLists() {
    const container = document.getElementById('dynamic-threat-blocklists');
    if (!container) return;

    try {
        const response = await fetch(brw.runtime.getURL('rules/Malware_Phishing_Threat_Intelligence/Threat_list.json'));
        if (!response.ok) throw new Error('Failed to load Threat_list.json');

        const data = await response.json();

        // Retrieve enabled states and counts from local storage
        const storageData = await brw.storage.local.get({ threatFeeds: {}, threatCounts: {} });
        const enabledState = storageData.threatFeeds || {};
        const threatCounts = storageData.threatCounts || {};

        container.innerHTML = ''; // Clear

        for (const entry of data.entries) {
            const itemDiv = document.createElement('div');
            itemDiv.className = 'custom-list-item';
            itemDiv.style.display = 'flex';
            itemDiv.style.justifyContent = 'space-between';
            itemDiv.style.alignItems = 'center';
            itemDiv.style.padding = '5px 0';
            itemDiv.style.borderBottom = '1px solid var(--border-color)';

            const labelDiv = document.createElement('div');
            labelDiv.style.flex = '1';

            const nameEl = document.createElement('div');
            nameEl.textContent = entry.name;
            nameEl.style.fontSize = '12px';
            nameEl.style.fontWeight = '500';

            const sourceEl = document.createElement('div');
            const attributionText = entry.attribution ? ` (${entry.attribution})` : '';
            sourceEl.textContent = `Source: ${entry.source || 'Online Feed'}${attributionText}`;
            sourceEl.style.fontSize = '10px';
            sourceEl.style.color = 'var(--text-muted)';
            sourceEl.style.marginTop = '1px';

            const statusEl = document.createElement('div');
            statusEl.className = 'live-status-text';
            const isActive = !!enabledState[entry.id];
            const ruleCount = threatCounts[entry.id];
            statusEl.textContent = isActive ? (ruleCount ? `Active (${ruleCount} rules)` : 'Active') : 'Inactive';
            statusEl.style.fontSize = '10px';
            statusEl.style.color = isActive ? 'var(--primary-color)' : 'var(--text-muted)';
            statusEl.style.marginTop = '2px';

            labelDiv.appendChild(nameEl);
            labelDiv.appendChild(sourceEl);
            labelDiv.appendChild(statusEl);

            const toggleLabel = document.createElement('label');
            toggleLabel.className = 'toggle-switch';

            const toggleInput = document.createElement('input');
            toggleInput.type = 'checkbox';
            toggleInput.className = 'threat-feed-toggle';
            toggleInput.dataset.feedId = entry.id;
            toggleInput.checked = enabledState[entry.id];

            const toggleSlider = document.createElement('span');
            toggleSlider.className = 'toggle-slider';

            toggleLabel.appendChild(toggleInput);
            toggleLabel.appendChild(toggleSlider);

            itemDiv.appendChild(labelDiv);
            itemDiv.appendChild(toggleLabel);
            container.appendChild(itemDiv);

            // Handle toggle
            toggleInput.addEventListener('change', async (e) => {
                const isChecked = e.target.checked;
                toggleInput.disabled = true; // disable while loading
                statusEl.textContent = isChecked ? 'Fetching live rules...' : 'Disabling...';
                statusEl.style.color = 'var(--text-muted)';

                brw.runtime.sendMessage({
                    action: 'toggleDynamicList',
                    listId: entry.id,
                    url: entry.url,
                    enabled: isChecked
                }, (response) => {
                    toggleInput.disabled = false;
                    if (response && response.success) {
                        statusEl.textContent = isChecked ? `Active (${response.count} rules)` : 'Inactive';
                        statusEl.style.color = isChecked ? 'var(--primary-color)' : 'var(--text-muted)';
                        updateShieldStatus();
                    } else {
                        // Error, revert
                        toggleInput.checked = !isChecked;
                        statusEl.textContent = 'Error: ' + (response?.error || 'Unknown');
                        statusEl.style.color = 'var(--danger-color)';
                    }
                });
            });
        }
    } catch (e) {
        console.warn('[OPSECHub] Failed to load dynamic lists:', e);
        container.innerHTML = ''; // clear first
        const errDiv = document.createElement('div');
        errDiv.style.cssText = 'color:var(--text-muted);font-size:12px;';
        errDiv.textContent = 'Failed to load live threats.';
        container.appendChild(errDiv);
    }
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
            clickjackXss: '🛡️',
            antiFingerprint: '🎭',
            userAgentSpoof: '🕵️',
            googleTelemetry: '🚫',
            proxyManager: '🔒'
        };

        const labelMap = {
            mediaBlock: 'Camera & Mic Guard',
            clipboardGuard: 'Clipboard Guard',
            locationBlock: 'Location Guard',
            webrtcBlock: 'WebRTC Leak Block',
            clickjackXss: 'XSS & Clickjack Guard',
            antiFingerprint: 'Anti-Fingerprint',
            userAgentSpoof: 'User-Agent Spoof',
            googleTelemetry: 'Telemetry Block',
            proxyManager: 'Proxy Defense'
        };

        logs.forEach((log) => {
            const icon = iconMap[log.module] || '🛡️';
            const title = labelMap[log.module] || log.module || 'OPSEC Alert';
            const desc = log.action ? `Blocked attempt to ${log.action}` : 'Access attempt blocked';

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
