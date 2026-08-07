/**
 * OPSECHub - Cookie & Storage Guard Module
 * Auto-deletes cookies and storage for a specific origin when the last tab of that origin is closed.
 */

const brw = typeof browser !== 'undefined' ? browser : chrome;

let isEnabled = false;

// Track active origins by tabId
// Map<tabId, origin>
const tabOrigins = new Map();

// Update tab origin when it navigates
function onTabUpdated(tabId, changeInfo, tab) {
    if (!isEnabled) return;
    const urlStr = changeInfo.url || tab.url;
    if (urlStr) {
        try {
            const url = new URL(urlStr);
            // Ignore browser internal pages
            if (url.protocol.startsWith('chrome') || url.protocol.startsWith('about') || url.protocol.startsWith('moz')) {
                tabOrigins.delete(tabId);
                return;
            }
            tabOrigins.set(tabId, url.origin);
        } catch (e) {
            tabOrigins.delete(tabId);
        }
    }
}

// When a tab is closed, check if its origin is completely gone
async function onTabRemoved(tabId, removeInfo) {
    if (!isEnabled) return;

    const origin = tabOrigins.get(tabId);
    tabOrigins.delete(tabId);

    if (!origin) return;

    try {
        // Query live open tabs directly from Chrome API (immune to MV3 Service Worker idle restarts)
        const allTabs = await brw.tabs.query({});
        let originStillOpen = false;

        for (const t of allTabs) {
            if (t.id !== tabId && t.url) {
                try {
                    const u = new URL(t.url);
                    if (u.origin === origin) {
                        originStillOpen = true;
                        break;
                    }
                } catch(e) {}
            }
        }

        if (!originStillOpen) {
            // Last tab for this origin was closed, nuke the data!
            console.log(`[OPSECHub:CookieGuard] Last tab for ${origin} closed. Wiping storage...`);
            await brw.browsingData.remove({
                origins: [origin]
            }, {
                cookies: true,
                localStorage: true,
                indexedDB: true,
                cacheStorage: true,
                serviceWorkers: true,
                webSQL: true
            });
            console.log(`[OPSECHub:CookieGuard] Storage wiped for ${origin}.`);
        }
    } catch (e) {
        console.error(`[OPSECHub:CookieGuard] Failed to check/wipe storage for ${origin}:`, e);
    }
}

function enable() {
    if (isEnabled) return;
    isEnabled = true;
    
    // Register listeners
    brw.tabs.onUpdated.addListener(onTabUpdated);
    brw.tabs.onRemoved.addListener(onTabRemoved);
    
    // Populate current tabs into the map so we don't accidentally wipe them if one closes
    brw.tabs.query({}).then(tabs => {
        tabs.forEach(tab => {
            if (tab.url) {
                try {
                    const url = new URL(tab.url);
                    if (!url.protocol.startsWith('chrome') && !url.protocol.startsWith('about') && !url.protocol.startsWith('moz')) {
                        tabOrigins.set(tab.id, url.origin);
                    }
                } catch(e) {}
            }
        });
    });
    
    console.log('[OPSECHub] Cookie & Storage Guard ENABLED');
}

function disable() {
    if (!isEnabled) return;
    isEnabled = false;
    
    brw.tabs.onUpdated.removeListener(onTabUpdated);
    brw.tabs.onRemoved.removeListener(onTabRemoved);
    tabOrigins.clear();
    
    console.log('[OPSECHub] Cookie & Storage Guard DISABLED');
}

export default {
    toggle: (enabled) => {
        if (enabled) enable();
        else disable();
    }
};
