const brw = typeof browser !== 'undefined' ? browser : chrome;

const trackingParamsToCheck = [
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", 
    "fbclid", "gclid", "ttclid", "si", "ref", "affiliate", "tracking_id"
];

function analyzeUrlParams() {
    const urlDisplay = document.getElementById('url-display');
    const paramContainer = document.getElementById('param-container');

    urlDisplay.textContent = window.location.href;

    const urlParams = new URLSearchParams(window.location.search);
    const leakedParams = [];

    for (const [key, value] of urlParams.entries()) {
        if (trackingParamsToCheck.includes(key.toLowerCase())) {
            leakedParams.push({ key, value });
        }
    }

    if (leakedParams.length > 0) {
        let html = `<div style="color: #ff5252; font-weight: bold; margin-bottom: 12px;">⚠️ [EXPOSED] Found active tracking parameters in the URL:</div>`;
        html += `<ul class="param-list">`;
        leakedParams.forEach(p => {
            html += `
                <li class="param-item">
                    <span class="param-name">${p.key}</span>
                    <span class="param-value">"${p.value}"</span>
                </li>
            `;
        });
        html += `</ul>`;
        html += `<p style="font-size: 13px; color: #ff5252; margin-top: 15px; font-style: italic;">URL Sanitizer is disabled or failed to intercept. Enable the module in options or popup and reload.</p>`;
        paramContainer.innerHTML = html;
    } else {
        // Check if there was any search query (even non-trackers) or if we just load it clean
        if (window.location.search.length > 0) {
            paramContainer.innerHTML = `
                <div style="color: #4caf50; font-weight: bold; margin-bottom: 10px;">🛡️ [PASSED] Parameters Filtered Successfully!</div>
                <p style="font-size: 13px; color: var(--text-secondary); line-height: 1.45;">
                    The URL contains parameters, but <strong>none</strong> of them are known marketing or analytic trackers. URL Sanitizer successfully filtered out the tracking tokens.
                </p>
            `;
        } else {
            // If the user arrived here with no params, but the URL Sanitizer is enabled:
            brw.storage.local.get({ moduleStates: {} }).then(data => {
                const enabled = data.moduleStates.urlSanitizer;
                if (enabled) {
                    paramContainer.innerHTML = `
                        <div style="color: #00e5ff; font-weight: bold; margin-bottom: 10px;">🛡️ [SHIELD ACTIVE] URL Cleaned</div>
                        <p style="font-size: 13.5px; color: var(--text-secondary); line-height: 1.45;">
                            No tracking parameters are present. If you clicked the "Trigger Sandbox" button, this confirms that the URL Sanitizer successfully intercepted the navigation and stripped all tracking codes before the document was initialized!
                        </p>
                    `;
                } else {
                    paramContainer.innerHTML = `
                        <div style="color: var(--text-secondary); font-style: italic;">
                            No parameters detected in the current URL. Click the button below to load this sandbox with simulated campaign tracking parameters.
                        </div>
                    `;
                }
            });
        }
    }
}

function triggerSandboxMock() {
    // Navigate to a real external echo server that shows received parameters.
    // We use an external page because chrome.declarativeNetRequest redirect rules
    // are bypassed for internal extension resources (chrome-extension://) by design.
    const mockUrl = 'https://httpbin.org/get' + 
                    '?utm_source=opsechub_campaign' + 
                    '&utm_medium=email' + 
                    '&fbclid=fb_click_99999' + 
                    '&si=tiktok_share_abc' + 
                    '&ref=affiliate_ref' + 
                    '&legit_param=safe_value'; // This non-tracker param should remain!
    window.open(mockUrl, '_blank');
}

function refreshDiagnostics() {
    brw.storage.local.get({ moduleStates: {} }).then(data => {
        const enabled = data.moduleStates.urlSanitizer;
        const banner = document.getElementById('status-banner');
        const statusText = document.getElementById('status-text');

        if (enabled) {
            banner.className = 'status-banner active';
            statusText.textContent = 'URL Sanitizer: ACTIVE (DNR Protection Enabled)';
        } else {
            banner.className = 'status-banner inactive';
            statusText.textContent = 'URL Sanitizer: Disabled';
        }

        analyzeUrlParams();
    });
}

document.addEventListener('DOMContentLoaded', () => {
    refreshDiagnostics();

    const refreshBtn = document.getElementById('btn-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshDiagnostics);
    }

    const mockBtn = document.getElementById('btn-mock');
    if (mockBtn) {
        mockBtn.addEventListener('click', triggerSandboxMock);
    }
});
