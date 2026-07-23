/**
 * OPSECHub – Extra Tools Controller
 */

const brw = typeof browser !== 'undefined' ? browser : chrome;

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
    const container = document.getElementById('dynamic-threat-blocklists');
    if (!container) return;

    fetch(chrome.runtime.getURL('rules/Malware_Phishing_Threat_Intelligence/Threat_list.json'))
        .then(res => res.json())
        .then(data => {
            container.innerHTML = '';
            data.entries.forEach(entry => {
                const item = document.createElement('div');
                item.style.display = 'flex';
                item.style.justifyContent = 'space-between';
                item.style.alignItems = 'center';
                item.style.padding = '10px';
                item.style.background = 'rgba(255,255,255,0.05)';
                item.style.borderRadius = '6px';

                const parts = entry.name.split(' - ');
                const title = parts[0];
                const desc = parts[1] || entry.name;

                const info = document.createElement('div');
                info.style.flex = '1';
                info.style.paddingRight = '10px';

                const titleRow = document.createElement('div');
                titleRow.style.display = 'flex';
                titleRow.style.alignItems = 'center';
                titleRow.style.gap = '8px';

                const titleEl = document.createElement('h4');
                titleEl.style.margin = '0';
                titleEl.style.fontSize = '13px';
                titleEl.style.color = '#e0e0e0';
                titleEl.textContent = title;

                const statusEl = document.createElement('span');
                statusEl.style.fontSize = '11px';
                statusEl.style.padding = '2px 6px';
                statusEl.style.borderRadius = '12px';
                statusEl.style.background = 'rgba(255,255,255,0.1)';
                statusEl.style.color = 'var(--text-muted)';
                statusEl.textContent = 'Inactive';

                titleRow.appendChild(titleEl);
                titleRow.appendChild(statusEl);

                const descEl = document.createElement('p');
                descEl.style.margin = '4px 0 0';
                descEl.style.fontSize = '11px';
                descEl.style.color = 'var(--text-muted)';
                descEl.style.lineHeight = '1.3';
                descEl.textContent = desc;

                info.appendChild(titleRow);
                info.appendChild(descEl);

                if (entry.attribution) {
                    const attrEl = document.createElement('div');
                    attrEl.style.fontSize = '10px';
                    attrEl.style.color = '#78909c';
                    attrEl.style.marginTop = '4px';
                    attrEl.style.fontStyle = 'italic';
                    attrEl.textContent = `Source: ${entry.source} (${entry.attribution})`;
                    info.appendChild(attrEl);
                }

                const toggle = document.createElement('label');
                toggle.className = 'toggle-switch';

                const input = document.createElement('input');
                input.type = 'checkbox';
                input.className = 'threat-feed-toggle';
                input.dataset.feedId = entry.id;

                const updateStatusUI = (enabled, count = null) => {
                    if (enabled) {
                        statusEl.style.background = 'rgba(76, 175, 80, 0.1)';
                        statusEl.style.color = '#4CAF50';
                        statusEl.textContent = count !== null ? `Active (${count} rules)` : 'Active';
                    } else {
                        statusEl.style.background = 'rgba(255,255,255,0.1)';
                        statusEl.style.color = 'var(--text-muted)';
                        statusEl.textContent = 'Inactive';
                    }
                };

                brw.storage.local.get({ threatFeeds: {}, threatCounts: {} }).then(d => {
                    const isEnabled = !!(d.threatFeeds && d.threatFeeds[entry.id]);
                    input.checked = isEnabled;
                    const count = d.threatCounts ? d.threatCounts[entry.id] : null;
                    updateStatusUI(isEnabled, count);
                });

                input.addEventListener('change', async (e) => {
                    const enabled = e.target.checked;
                    input.disabled = true;

                    if (enabled) {
                        statusEl.textContent = '⏳ Fetching...';
                        statusEl.style.color = '#ff9800';
                        statusEl.style.background = 'rgba(255, 152, 0, 0.1)';

                        // Auto-enable threatIntel master toggle if it was OFF
                        const store = await brw.storage.local.get({ moduleStates: {} });
                        const states = store.moduleStates || {};
                        if (!states.threatIntel) {
                            states.threatIntel = true;
                            await brw.storage.local.set({ moduleStates: states });
                            const masterToggle = document.querySelector('.opt-module-toggle[data-module="threatIntel"]');
                            if (masterToggle) masterToggle.checked = true;
                        }
                    }

                    brw.runtime.sendMessage({ action: 'toggleDynamicList', listId: entry.id, url: entry.url, enabled }, (res) => {
                        input.disabled = false;
                        if (res && res.success) {
                            updateStatusUI(enabled, res.count);
                        } else {
                            input.checked = !enabled; // Revert
                            statusEl.textContent = '❌ Failed';
                            statusEl.style.color = '#F44336';
                            statusEl.style.background = 'rgba(244, 67, 54, 0.1)';
                            console.error('[OPSECHub] Failed to toggle threat list:', res?.error);
                        }
                    });
                });

                const slider = document.createElement('span');
                slider.className = 'toggle-slider';

                toggle.appendChild(input);
                toggle.appendChild(slider);
                item.appendChild(info);
                item.appendChild(toggle);
                container.appendChild(item);
            });
        })
        .catch(err => {
            console.error('[OPSECHub] Failed to load threat feeds:', err);
            container.innerHTML = `<div style="color: #F44336; font-size: 13px; text-align: center;">Failed to load threat feeds.</div>`;
        });
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

    // Auto-open Guides tab if setup=true in URL
    const params = new URLSearchParams(window.location.search);
    if (params.get('setup') === 'true') {
        const guideTopTab = document.querySelector('.top-tab[data-topcat="guides"]');
        if (guideTopTab) {
            guideTopTab.click();
            const guideSidebarTab = document.querySelector('.sidebar-tab[data-tab="opt-guide-setup"]');
            if (guideSidebarTab) guideSidebarTab.click();
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
    brw.storage.local.get({ coreShieldMode: 'disabled', uaProfile: 'win_chrome', antiFingerprintMode: 'blend-in', decoyIntensity: 'medium', includeSearches: true, excludedDomains: [], moduleStates: {}, activeProxy: null, customProxies: [] }).then(data => {

        // Init toggles
        document.querySelectorAll('.opt-module-toggle').forEach(toggle => {
            const module = toggle.getAttribute('data-module');
            toggle.checked = !!data.moduleStates[module];

            toggle.addEventListener('change', (e) => {
                const enabled = e.target.checked;
                brw.storage.local.get({ moduleStates: {} }).then(st => {
                    const states = st.moduleStates || {};
                    states[module] = enabled;
                    brw.storage.local.set({ moduleStates: states }).then(() => {
                        brw.runtime.sendMessage({ action: 'toggleModule', module, enabled });
                    });
                });
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
                            infoEl.innerHTML = `📅 Ruleset Release Date: <strong>${dateStr}</strong> (AdBlocker currently Disabled)`;
                        } else {
                            infoEl.innerHTML = `📅 Ruleset Release Date: <strong>${dateStr}</strong> (${countFormatted} compiled rules)`;
                        }
                    } else {
                        infoEl.textContent = '';
                    }
                }
            } catch (_) {
                infoEl.textContent = '';
            }
        };

        const shieldSelect = document.getElementById('opt-select-shield-mode');
        if (shieldSelect) {
            let currentMode = data.coreShieldMode;
            shieldSelect.value = currentMode;
            updateShieldMetaInfo(currentMode, 'opt-shield-mode-info');

            shieldSelect.addEventListener('change', (e) => {
                const newMode = e.target.value;
                shieldSelect.disabled = true;

                brw.runtime.sendMessage({ action: 'switchCoreRuleset', activeRuleset: newMode }, (response) => {
                    shieldSelect.disabled = false;
                    if (response && !response.success) {
                        shieldSelect.value = currentMode; // Revert visually
                        console.error('Failed to enable ruleset:', response.error);
                        return;
                    }
                    currentMode = newMode;
                    updateShieldMetaInfo(newMode, 'opt-shield-mode-info');
                    brw.storage.local.set({ coreShieldMode: newMode });
                });
            });
        }

        const uaSelect = document.getElementById('opt-user-agent-select');
        if (uaSelect) {
            uaSelect.value = data.uaProfile;
            uaSelect.addEventListener('change', (e) => {
                const newProfile = e.target.value;
                brw.storage.local.set({ uaProfile: newProfile }).then(() => {
                    brw.storage.local.get({ moduleStates: {} }).then(st => {
                        if (st.moduleStates.userAgentSpoof) {
                            brw.runtime.sendMessage({ action: 'toggleModule', module: 'userAgentSpoof', enabled: true });
                        }
                    });
                });
            });
        }

        const afSelect = document.getElementById('opt-anti-fingerprint-mode');
        if (afSelect) {
            afSelect.value = data.antiFingerprintMode;
            afSelect.addEventListener('change', (e) => {
                const newMode = e.target.value;
                brw.storage.local.set({ antiFingerprintMode: newMode }).then(() => {
                    brw.storage.local.get({ moduleStates: {} }).then(st => {
                        if (st.moduleStates.antiFingerprint) {
                            brw.runtime.sendMessage({ action: 'toggleModule', module: 'antiFingerprint', enabled: true });
                        }
                    });
                });
            });
        }



        const decoySelect = document.getElementById('sel-decoy-intensity');
        if (decoySelect) {
            decoySelect.value = data.decoyIntensity || 'medium';
            decoySelect.addEventListener('change', (e) => {
                const newInt = e.target.value;
                brw.storage.local.set({ decoyIntensity: newInt }).then(() => {
                    brw.storage.local.get({ moduleStates: {} }).then(st => {
                        if (st.moduleStates.decoyTraffic) {
                            brw.runtime.sendMessage({ action: 'toggleModule', module: 'decoyTraffic', enabled: true });
                        }
                    });
                });
            });
        }

        const decoySearches = document.getElementById('chk-decoy-searches');
        if (decoySearches) {
            decoySearches.checked = data.includeSearches !== false;
            decoySearches.addEventListener('change', (e) => {
                brw.storage.local.set({ includeSearches: e.target.checked });
            });
        }

        // Manual allowlist entry handler
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
                if (toggle.checked !== !!newStates[module]) {
                    toggle.checked = !!newStates[module];
                }
            });
        }

        if (changes.coreShieldMode) {
            const val = changes.coreShieldMode.newValue || 'disabled';
            const select = document.getElementById('opt-select-shield-mode');
            if (select && select.value !== val) {
                select.value = val;
            }
        }

        if (changes.uaProfile) {
            const val = changes.uaProfile.newValue || 'win_chrome';
            const select = document.getElementById('opt-user-agent-select');
            if (select && select.value !== val) {
                select.value = val;
            }
        }

        if (changes.antiFingerprintMode) {
            const val = changes.antiFingerprintMode.newValue || 'blend-in';
            const select = document.getElementById('opt-anti-fingerprint-mode');
            if (select && select.value !== val) {
                select.value = val;
            }
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





        if (changes.decoyIntensity) {
            const val = changes.decoyIntensity.newValue || 'medium';
            const select = document.getElementById('sel-decoy-intensity');
            if (select && select.value !== val) {
                select.value = val;
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

        fetch('https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.json')
            .then(res => res.json())
            .then(data => {
                // Map the proxifly JSON schema to our expected schema
                const proxies = data.map(p => ({
                    type: p.protocol || 'socks5',
                    host: p.ip,
                    port: p.port,
                    country: (p.geolocation && p.geolocation.country) ? p.geolocation.country : 'Unknown'
                }));

                brw.storage.local.set({ [CACHE_KEY]: proxies, [CACHE_TIME_KEY]: Date.now() });
                renderFreeProxies(proxies);
                if (btn) btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16"/></svg> Force Refresh';
            })
            .catch(err => {
                console.error('[OPSECHub] Failed to fetch free proxies:', err);
                if (btn) btn.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 2v6h-6M3 12a9 9 0 0 1 15-6.7L21 8M3 22v-6h6M21 12a9 9 0 0 1-15 6.7L3 16"/></svg> Error';
                brw.storage.local.get(CACHE_KEY).then(d => {
                    if (d[CACHE_KEY]) renderFreeProxies(d[CACHE_KEY]); // fallback to old cache
                });
            });
    }

    const btnRefresh = document.getElementById('btn-refresh-proxies');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', fetchProxies);
    }

    const btnGlobalRefresh = document.getElementById('btn-global-refresh');
    if (btnGlobalRefresh) {
        btnGlobalRefresh.addEventListener('click', () => {
            const originalHTML = btnGlobalRefresh.innerHTML;
            btnGlobalRefresh.innerHTML = '⏳ Refreshing...';
            btnGlobalRefresh.disabled = true;
            brw.runtime.sendMessage({ action: 'refreshRules' }, (res) => {
                btnGlobalRefresh.disabled = false;
                btnGlobalRefresh.innerHTML = originalHTML;
                if (res && res.success) {
                    btnGlobalRefresh.innerHTML = '✓ Synchronized!';
                    setTimeout(() => btnGlobalRefresh.innerHTML = originalHTML, 2000);
                } else {
                    btnGlobalRefresh.innerHTML = '❌ Sync Failed';
                    setTimeout(() => btnGlobalRefresh.innerHTML = originalHTML, 2000);
                }
            });
        });
    }

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
        const isMasterIntelEnabled = d.masterSwitch !== false && d.moduleStates.threatIntel !== false;

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


