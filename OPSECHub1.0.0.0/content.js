/**
 * OPSECHub – Content Script
 * Runs on every page at document_start.
 * Listens for background messages to inject protection modules.
 */

const brw = typeof browser !== 'undefined' ? browser : chrome;

// ═══════════════════════════════════════════════════════════════════
// MODULE STATE LISTENER
// ═══════════════════════════════════════════════════════════════════
brw.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'injectModule') {
        injectModule(message.module);
        sendResponse({ success: true });
    } else if (message.action === 'toggleModule') {
        injectModule(message.module);
        sendResponse({ success: true });
    } else if (message.action === 'masterToggle') {
        sendResponse({ success: true });
    }
    return true;
});

// ═══════════════════════════════════════════════════════════════════
// MODULE INJECTION
// ═══════════════════════════════════════════════════════════════════
function injectModule(moduleName) {
    switch (moduleName) {
        case 'antiFingerprint':
            // Managed directly from the Background Worker (scripting.registerContentScripts) to avoid race conditions.
            break;
        case 'webrtcBlock':
            // WebRTC is handled natively in the background service worker via chrome.privacy.
            // No content script injection required.
            break;
        case 'clipboardGuard':
            injectClipboardGuard();
            break;
        case 'clickjackXss':
            injectClickjackXss();
            break;
        case 'userAgentSpoof':
            // In content.js we can't easily read the profile synchronously without blocking, 
            // but the background service worker handles DNR, so the actual JS injection 
            // is triggered on load via storage check below.
            break;
        default:
            break;
    }
}

// ═══════════════════════════════════════════════════════════════════
// CLICKJACKING & XSS GUARD INJECTION
// ═══════════════════════════════════════════════════════════════════
function injectClickjackXss() {
    if (document.getElementById('opsechub-clickjack-xss')) return;
    const script = document.createElement('script');
    script.id = 'opsechub-clickjack-xss';
    script.src = brw.runtime.getURL('modules/clickjackXss/inject.js');
    (document.head || document.documentElement).appendChild(script);
    script.onload = () => script.remove();
}

// ═══════════════════════════════════════════════════════════════════
// ANTI-FINGERPRINT INJECTION STUB
// ═══════════════════════════════════════════════════════════════════
function injectAntiFingerprint() {
    // Removed: antiFingerprint is now managed purely via background scripting.registerContentScripts to prevent race conditions.
}

// ═══════════════════════════════════════════════════════════════════


function injectClipboardGuard() {
    if (document.getElementById('opsechub-clipboard-guard')) return;
    const script = document.createElement('script');
    script.id = 'opsechub-clipboard-guard';
    script.src = brw.runtime.getURL('modules/clipboardGuard/inject.js');
    (document.head || document.documentElement).appendChild(script);
    script.onload = () => script.remove();
}

// ═══════════════════════════════════════════════════════════════════
// INIT: Check stored state and apply modules on page load
// ═══════════════════════════════════════════════════════════════════
(async function init() {
    try {
        const data = await brw.storage.local.get({ moduleStates: {}, antiFingerprintMode: 'blend-in', locationMode: 'block', masterSwitch: true, excludedDomains: [] });
        if (!data.masterSwitch) return; // Halt injections if master switch is off
        if (data.excludedDomains && data.excludedDomains.includes(location.hostname)) {
            console.log(`[OPSECHub] Site excluded: ${location.hostname}`);
            return;
        }
        const states = data.moduleStates || {};
        const mode = data.antiFingerprintMode || 'blend-in';
        const locMode = data.locationMode || 'block';

        if (document.documentElement) {
            document.documentElement.setAttribute('data-opsechub-mode', mode);
            document.documentElement.setAttribute('data-opsechub-location-mode', locMode);
        }

        // states.antiFingerprint is now handled purely at the background level (scripting.registerContentScripts)
        if (states.webrtcBlock) {
            // WebRTC blocking operates at the network level in background.js
        }
        if (states.clipboardGuard) injectClipboardGuard();
        if (states.clickjackXss) injectClickjackXss();
    } catch (err) {
        // Content script may not have storage access in some contexts
    }
})();

// ═══════════════════════════════════════════════════════════════════
// IN-PAGE TOAST NOTIFICATION SYSTEM
// ═══════════════════════════════════════════════════════════════════
let toastContainer = null;

function showToast(moduleName, actionText) {
    if (!toastContainer) {
        const div = document.createElement('div');
        div.id = 'opsechub-toast-container';
        (document.body || document.documentElement).appendChild(div);
        
        const shadow = div.attachShadow({ mode: 'closed' });
        
        const container = document.createElement('div');
        container.id = 'toast-container';
        shadow.appendChild(container);
        
        const style = document.createElement('style');
        style.textContent = `
            #toast-container {
                position: fixed;
                bottom: 20px;
                right: 20px;
                z-index: 2147483647;
                display: flex;
                flex-direction: column;
                gap: 10px;
                font-family: system-ui, -apple-system, sans-serif;
                pointer-events: none;
            }
            .toast {
                pointer-events: auto;
                background: rgba(10, 14, 23, 0.95);
                backdrop-filter: blur(8px);
                border: 1px solid rgba(0, 229, 255, 0.3);
                border-radius: 8px;
                padding: 12px 20px;
                color: #ffffff;
                width: 280px;
                box-shadow: 0 4px 20px rgba(0, 0, 0, 0.6);
                display: flex;
                align-items: center;
                gap: 12px;
                transform: translateX(120%);
                transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275), opacity 0.3s;
                opacity: 0;
                box-sizing: border-box;
            }
            .toast.show {
                transform: translateX(0);
                opacity: 1;
            }
            .toast.hide {
                transform: translateY(20px);
                opacity: 0;
            }
            .icon {
                font-size: 20px;
                flex-shrink: 0;
            }
            .content {
                display: flex;
                flex-direction: column;
                gap: 2px;
            }
            .title {
                font-size: 13px;
                font-weight: 700;
                color: #00e5ff;
            }
            .desc {
                font-size: 11px;
                color: #b0bec5;
                line-height: 1.3;
            }
        `;
        shadow.appendChild(style);
        
        toastContainer = container;
    }
    
    let icon = '🛡️';
    let title = 'OPSECHub Protection';
    switch (moduleName) {
        case 'mediaBlock':
            icon = '📸';
            title = 'Camera & Mic Guard';
            break;
        case 'clipboardGuard':
            icon = '📋';
            title = 'Clipboard Guard';
            break;
        case 'locationBlock':
            icon = '🗺️';
            title = 'Location Guard';
            break;
        case 'webrtcBlock':
            icon = '🌐';
            title = 'WebRTC Leak Block';
            break;
        case 'clickjackXss':
            icon = '🛡️';
            title = 'Clickjacking / XSS Guard';
            break;
    }
    
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
        <span class="icon">${icon}</span>
        <div class="content">
            <span class="title">${title}</span>
            <span class="desc">Blocked attempt to ${actionText}.</span>
        </div>
    `;
    
    toastContainer.appendChild(toast);
    
    setTimeout(() => toast.classList.add('show'), 50);
    
    setTimeout(() => {
        toast.classList.remove('show');
        toast.classList.add('hide');
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

// Listen for block events dispatched by the MAIN world injected scripts
window.addEventListener('opsechub-block-event', (e) => {
    if (e.detail && e.detail.module && e.detail.action) {
        showToast(e.detail.module, e.detail.action);
        brw.runtime.sendMessage({ action: 'registerBlock', module: e.detail.module, detail: e.detail.action }).catch(() => {});
    }
});
