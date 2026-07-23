const brw = typeof browser !== 'undefined' ? browser : chrome;

// Cache original functions to allow dynamic evaluation and comparison
const originalUA = navigator.userAgent;
const originalPlatform = navigator.platform;
const originalAppVersion = navigator.appVersion;
const originalTouchPoints = navigator.maxTouchPoints;
const originalUAData = navigator.userAgentData;

const UA_PROFILES_LOCAL = {
    win_chrome: {
        label: 'Windows 10 / Chrome',
        ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        platform: 'Win32',
        touchPoints: 0,
        ch_uaData: {
            brands: [{brand: 'Not_A Brand', version: '8'}, {brand: 'Chromium', version: '120'}, {brand: 'Google Chrome', version: '120'}],
            mobile: false,
            platform: 'Windows'
        }
    },
    mac_safari: {
        label: 'macOS / Safari',
        ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        platform: 'MacIntel',
        touchPoints: 0,
        ch_uaData: undefined
    },
    linux_firefox: {
        label: 'Linux / Firefox',
        ua: 'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
        platform: 'Linux x86_64',
        touchPoints: 0,
        ch_uaData: undefined
    },
    ios_safari: {
        label: 'iPhone / Safari',
        ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/605.1.15',
        platform: 'iPhone',
        touchPoints: 5,
        ch_uaData: undefined
    },
    android_chrome: {
        label: 'Android / Chrome',
        ua: 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        platform: 'Linux armv8l',
        touchPoints: 5,
        ch_uaData: {
            brands: [{brand: 'Not_A Brand', version: '8'}, {brand: 'Chromium', version: '120'}, {brand: 'Google Chrome', version: '120'}],
            mobile: true,
            platform: 'Android'
        }
    }
};

function applyLocalUAPatches(profileKey) {
    const profile = UA_PROFILES_LOCAL[profileKey] || UA_PROFILES_LOCAL['win_chrome'];

    // Helper to override getters
    function spoofGetter(targetObj, propName, spoofedValue) {
        Object.defineProperty(targetObj, propName, {
            get: () => typeof spoofedValue === 'function' ? spoofedValue() : spoofedValue,
            configurable: true
        });
    }

    if (window.Navigator) {
        spoofGetter(Navigator.prototype, 'userAgent', profile.ua);
        spoofGetter(Navigator.prototype, 'appVersion', profile.ua.replace(/^Mozilla\//, ''));
        spoofGetter(Navigator.prototype, 'platform', profile.platform);
        spoofGetter(Navigator.prototype, 'maxTouchPoints', profile.touchPoints);

        if (Navigator.prototype.hasOwnProperty('userAgentData') || navigator.userAgentData !== undefined) {
            if (profile.ch_uaData) {
                spoofGetter(Navigator.prototype, 'userAgentData', () => ({
                    brands: profile.ch_uaData.brands,
                    mobile: profile.ch_uaData.mobile,
                    platform: profile.ch_uaData.platform,
                    getHighEntropyValues: async (hints) => {
                        let values = {};
                        if (hints.includes('platform')) values.platform = profile.ch_uaData.platform;
                        if (hints.includes('model')) values.model = profile.ch_uaData.mobile ? 'K' : '';
                        if (hints.includes('uaFullVersion')) values.uaFullVersion = '120.0.0.0';
                        return values;
                    }
                }));
            } else {
                spoofGetter(Navigator.prototype, 'userAgentData', undefined);
            }
        }
    }
}

async function renderDiagnostics() {
    // 1. Basic properties
    document.getElementById('val-useragent').textContent = navigator.userAgent;
    document.getElementById('val-platform').textContent = navigator.platform;
    document.getElementById('val-appversion').textContent = navigator.appVersion;
    document.getElementById('val-touchpoints').textContent = navigator.maxTouchPoints;

    // 2. Client Hints (userAgentData)
    const chPresentEl = document.getElementById('val-ch-present');
    const chDetailsEl = document.getElementById('val-ch-details');

    if (navigator.userAgentData) {
        chPresentEl.textContent = 'Available (Supported)';
        chPresentEl.style.color = '#4caf50';

        try {
            const highEntropy = await navigator.userAgentData.getHighEntropyValues(['platform', 'model', 'uaFullVersion']);
            const details = {
                brands: navigator.userAgentData.brands,
                mobile: navigator.userAgentData.mobile,
                platform: navigator.userAgentData.platform,
                highEntropyValues: highEntropy
            };
            chDetailsEl.textContent = JSON.stringify(details, null, 4);
            chDetailsEl.style.display = 'block';
        } catch (e) {
            chDetailsEl.textContent = `Error reading high entropy hints: ${e.toString()}`;
            chDetailsEl.style.display = 'block';
        }
    } else {
        chPresentEl.textContent = 'Not Available (Undefined/Hidden)';
        chPresentEl.style.color = '#f44336';
        chDetailsEl.style.display = 'none';
    }
}

function refreshDiagnostics() {
    brw.storage.local.get({ moduleStates: {}, uaProfile: 'win_chrome' }).then(async data => {
        const enabled = data.moduleStates.userAgentSpoof;
        const profileKey = data.uaProfile;

        const banner = document.getElementById('status-banner');
        const statusText = document.getElementById('status-text');
        const badge = document.getElementById('active-profile-badge');

        if (enabled) {
            banner.className = 'status-banner active';
            const profile = UA_PROFILES_LOCAL[profileKey] || UA_PROFILES_LOCAL['win_chrome'];
            statusText.textContent = `Identity Spoofing: ACTIVE (Simulated)`;
            badge.textContent = profile.label;
            badge.style.background = 'rgba(76, 175, 80, 0.2)';

            if (!window.__ua_patched) {
                applyLocalUAPatches(profileKey);
                window.__ua_patched = profileKey;
            } else if (window.__ua_patched !== profileKey) {
                // If profile changed, reload to clear prototypes
                location.reload();
                return;
            }
        } else {
            banner.className = 'status-banner inactive';
            statusText.textContent = 'Identity Spoofing: Disabled / Unpatched';
            badge.textContent = 'Real Identity';
            badge.style.background = 'rgba(244, 67, 54, 0.2)';

            if (window.__ua_patched) {
                // Reload to restore original prototype values safely
                location.reload();
                return;
            }
        }

        await renderDiagnostics();
    });
}

document.addEventListener('DOMContentLoaded', () => {
    // Initial diagnostics run
    refreshDiagnostics();

    const refreshBtn = document.getElementById('btn-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshDiagnostics);
    }
});
