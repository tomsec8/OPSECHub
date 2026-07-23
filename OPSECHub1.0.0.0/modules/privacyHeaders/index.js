const brw = typeof browser !== 'undefined' ? browser : chrome;

const DNR_RULE_ID = 900003;

export default {
    async toggle(enabled) {
        try {
            if (!enabled) {
                await brw.declarativeNetRequest.updateSessionRules({ removeRuleIds: [DNR_RULE_ID] });
                try { await brw.scripting.unregisterContentScripts({ ids: ['privacyDOM'] }); } catch (e) { }
                console.log('[OPSECHub:PrivacyHeaders] Disabled');
                return;
            }

            const rule = {
                id: DNR_RULE_ID,
                priority: 150,
                action: {
                    type: "modifyHeaders",
                    requestHeaders: [
                        { header: "DNT", operation: "set", value: "1" },
                        { header: "Sec-GPC", operation: "set", value: "1" }
                    ]
                },
                condition: {
                    resourceTypes: ["main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object", "xmlhttprequest", "ping", "websocket", "other"]
                }
            };

            await brw.declarativeNetRequest.updateSessionRules({
                removeRuleIds: [DNR_RULE_ID],
                addRules: [rule]
            });
            try {
                await brw.scripting.registerContentScripts([{
                    id: 'privacyDOM',
                    js: ['modules/privacyHeaders/inject.js'],
                    matches: ['<all_urls>'],
                    world: 'MAIN',
                    runAt: 'document_start',
                    allFrames: true,
                    matchOriginAsFallback: true
                }]);
            } catch (e) {
                // Might already be registered
            }
            console.log('[OPSECHub:PrivacyHeaders] Enabled - DNT & Sec-GPC active');
        } catch (e) {
            console.error('[OPSECHub:PrivacyHeaders] Error:', e);
        }
    }
};
