/**
 * OPSECHub – Content Script
 * Runs on top-level pages at document_start (ISOLATED world).
 * Kept off iframes to avoid Chrome noise on sandboxed about:blank frames
 * ("allow-scripts" permission is not set). Cosmetic/scriptlet injects still
 * cover frames via the scripting API when AdBlocker lists need them.
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
        // Only inject when switching a module ON. This used to inject
        // unconditionally, so turning a module off re-ran its page hooks.
        // Turning one off cannot undo hooks already installed in the page's
        // own world, so it takes effect on the next load.
        if (message.enabled !== false) {
            injectModule(message.module);
        }
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
        case 'webrtcBlock':
            // WebRTC is handled natively in the background service worker via chrome.privacy.
            // No content script injection required.
            break;
        case 'clipboardGuard':
            // Registered from the background worker, nothing to do per-page.
            break;
        default:
            break;
    }
}

// ═══════════════════════════════════════════════════════════════════
// INIT: Check stored state and apply modules on page load
// ═══════════════════════════════════════════════════════════════════
(async function init() {
    try {
        const data = await brw.storage.local.get({ moduleStates: {}, locationMode: 'block', masterSwitch: true, excludedDomains: [] });
        if (!data.masterSwitch) return;
        if (data.excludedDomains && data.excludedDomains.includes(location.hostname)) {
            console.log(`[OPSECHub] Site excluded: ${location.hostname}`);
            return;
        }
        const locMode = data.locationMode || 'block';

        if (document.documentElement) {
            document.documentElement.setAttribute('data-opsechub-location-mode', locMode);
        }
        // clipboardGuard is registered by the background worker.
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
    let desc = 'Blocked a sensitive access attempt.';

    const actionCopy = {
        'access camera/microphone': 'Blocked camera & microphone access.',
        'access camera/microphone (legacy)': 'Blocked camera & microphone access.',
        'access geolocation location': 'Blocked location access.',
        'read clipboard text': 'Blocked a clipboard read attempt.',
        'read clipboard data': 'Blocked a clipboard read attempt.',
        'paste text': 'Blocked a paste attempt.'
    };

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
    }

    if (actionCopy[actionText]) {
        desc = actionCopy[actionText];
    } else if (actionText) {
        desc = `Blocked attempt to ${actionText}.`;
    }

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
        <span class="icon">${icon}</span>
        <div class="content">
            <span class="title">${title}</span>
            <span class="desc">${desc}</span>
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
