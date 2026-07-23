const brw = typeof browser !== 'undefined' ? browser : chrome;

const RULE_ID = 999001; // Unique ID for DNR rule
let bfcacheNavListener = null;

export default {
    async toggle(enabled) {
        const logDiag = (msg, data = null) => {
            console.log(`[OPSECHub:ReferrerControl] ${msg}`, data || '');
        };

        try {
            logDiag(`Toggle called: enabled=${enabled}`);
            let addRules = [];
            if (enabled) {
                addRules.push({
                    "id": RULE_ID,
                    "priority": 250,
                    "action": {
                        "type": "modifyHeaders",
                        "requestHeaders": [
                            { "header": "Referer", "operation": "remove" }
                        ],
                        "responseHeaders": [
                            { "header": "Referrer-Policy", "operation": "set", "value": "no-referrer" }
                        ]
                    },
                    "condition": {
                        "resourceTypes": [
                            "main_frame", "sub_frame", "stylesheet", "script", 
                            "image", "font", "object", "xmlhttprequest", 
                            "ping", "csp_report", "media", "websocket", 
                            "other"
                        ]
                    }
                });
            }

            logDiag('Updating dynamic rules...', { removeRuleIds: [RULE_ID], addRules });
            await brw.declarativeNetRequest.updateDynamicRules({
                removeRuleIds: [RULE_ID],
                addRules: addRules
            });
            logDiag('Dynamic rules updated successfully');
        } catch (e) {
            logDiag('Error toggling session rules', e.toString());
        }

        // Set native browser-level privacy setting for Referrer
        try {
            if (brw.privacy && brw.privacy.websites && brw.privacy.websites.referrersEnabled) {
                logDiag(`Setting native referrersEnabled to ${!enabled}`);
                await brw.privacy.websites.referrersEnabled.set({ value: !enabled });
                logDiag('Native referrersEnabled updated successfully');
            }
        } catch (e) {
            logDiag('Error setting native referrersEnabled', e.toString());
        }

        try {
            logDiag('Checking registered scripts...');
            const existing = await brw.scripting.getRegisteredContentScripts({ ids: ['referrerControl'] });
            logDiag('Existing scripts found', existing);
            if (enabled) {
                if (existing.length === 0) {
                    logDiag('Registering script...');
                    await brw.scripting.registerContentScripts([{
                        id: 'referrerControl',
                        matches: ["<all_urls>"],
                        js: ['modules/referrerControl/inject.js'],
                        runAt: "document_start",
                        world: "MAIN",
                        allFrames: true,
                        matchOriginAsFallback: true
                    }]);
                    logDiag('Script registered successfully');
                }
            } else {
                if (existing.length > 0) {
                    logDiag('Unregistering script...');
                    await brw.scripting.unregisterContentScripts({ ids: ['referrerControl'] });
                    logDiag('Script unregistered successfully');
                }
            }
        } catch (e) {
            logDiag('Error toggling inject script', e.toString());
        }

        // Handle bfcache: re-inject referrer patches on back/forward navigations
        try {
            if (enabled) {
                if (!bfcacheNavListener) {
                    bfcacheNavListener = (details) => {
                        if (details.transitionQualifiers &&
                            details.transitionQualifiers.includes('forward_back')) {
                            brw.scripting.executeScript({
                                target: { tabId: details.tabId, allFrames: true },
                                func: () => {
                                    try {
                                        Object.defineProperty(document, 'referrer', {
                                            get: () => '', configurable: true
                                        });
                                    } catch(e) {}
                                    try {
                                        Object.defineProperty(Document.prototype, 'referrer', {
                                            get: () => '', configurable: true, enumerable: true
                                        });
                                    } catch(e) {}
                                    // Re-enforce meta referrer tag
                                    let meta = document.querySelector('meta[name="referrer"]');
                                    if (meta) {
                                        meta.content = 'no-referrer';
                                    } else if (document.head) {
                                        meta = document.createElement('meta');
                                        meta.name = 'referrer';
                                        meta.content = 'no-referrer';
                                        document.head.appendChild(meta);
                                    }
                                },
                                world: 'MAIN'
                            }).catch(() => {});
                        }
                    };
                    brw.webNavigation.onCommitted.addListener(bfcacheNavListener);
                    logDiag('bfcache navigation listener installed');
                }
            } else {
                if (bfcacheNavListener) {
                    brw.webNavigation.onCommitted.removeListener(bfcacheNavListener);
                    bfcacheNavListener = null;
                    logDiag('bfcache navigation listener removed');
                }
            }
        } catch (e) {
            logDiag('Error managing bfcache navigation listener', e.toString());
        }
    }
};
