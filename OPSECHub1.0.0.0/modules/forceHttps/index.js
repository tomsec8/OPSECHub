/**
 * OPSECHub - Force HTTPS Module
 * Upgrades all HTTP connections to HTTPS, excluding local networks and Tor/I2P.
 */

const brw = typeof browser !== 'undefined' ? browser : chrome;

const RULE_IDS = [500000, 500001, 500002, 500003, 500004];

async function enable() {
    try {
        await brw.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: [500000, 500001, 500002, 500003, 500004], // Remove all old rules
            addRules: [
                {
                    // Main Upgrade Rule
                    id: 500000,
                    priority: 1,
                    action: { type: "upgradeScheme" },
                    condition: {
                        urlFilter: "http://*",
                        excludedRequestDomains: ["localhost", "127.0.0.1", "onion", "i2p", "local"],
                        resourceTypes: ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "csp_report", "media", "websocket", "other"]
                    }
                }
            ]
        });
        console.log('[OPSECHub] Force HTTPS ENABLED');
    } catch (e) {
        console.error('[OPSECHub:ForceHTTPS] Failed to enable:', e);
    }
}

async function disable() {
    try {
        await brw.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: RULE_IDS
        });
        console.log('[OPSECHub] Force HTTPS DISABLED');
    } catch (e) {
        console.error('[OPSECHub:ForceHTTPS] Failed to disable:', e);
    }
}

export default {
    toggle: (enabled) => {
        if (enabled) enable();
        else disable();
    }
};
