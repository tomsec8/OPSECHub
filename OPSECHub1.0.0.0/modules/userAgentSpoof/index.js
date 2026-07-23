const brw = typeof browser !== 'undefined' ? browser : chrome;

const DNR_RULE_ID = 900001;

// Define default profiles
export const UA_PROFILES = {
    win_chrome: {
        label: 'Windows 10 / Chrome',
        ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        platform: 'Win32',
        ch_ua: '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        ch_platform: '"Windows"',
        ch_mobile: '?0',
        ch_model: '""'
    },
    mac_safari: {
        label: 'macOS / Safari',
        ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        platform: 'MacIntel',
        ch_ua: '""', // Safari typically doesn't send Sec-CH-UA yet, but we clear it
        ch_platform: '"macOS"',
        ch_mobile: '?0',
        ch_model: '""'
    },
    linux_firefox: {
        label: 'Linux / Firefox',
        ua: 'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0',
        platform: 'Linux x86_64',
        ch_ua: '""', // Firefox doesn't use Client Hints by default
        ch_platform: '"Linux"',
        ch_mobile: '?0',
        ch_model: '""'
    },
    ios_safari: {
        label: 'iPhone / Safari',
        ua: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/605.1.15',
        platform: 'iPhone',
        ch_ua: '""',
        ch_platform: '"iOS"',
        ch_mobile: '?1',
        ch_model: '"iPhone"'
    },
    android_chrome: {
        label: 'Android / Chrome',
        ua: 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        platform: 'Linux armv8l',
        ch_ua: '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        ch_platform: '"Android"',
        ch_mobile: '?1',
        ch_model: '"K"'
    }
};

export default {
    async toggle(enabled, profileKey = 'win_chrome') {
        try {
            if (!enabled) {
                await brw.declarativeNetRequest.updateSessionRules({ removeRuleIds: [DNR_RULE_ID] });
                try { await brw.scripting.unregisterContentScripts({ ids: ['userAgentDOM'] }); } catch(e){}
                console.log('[OPSECHub:UASpoof] Disabled');
                return;
            }

            const profile = UA_PROFILES[profileKey] || UA_PROFILES['win_chrome'];

            const rule = {
                id: DNR_RULE_ID,
                priority: 100,
                action: {
                    type: "modifyHeaders",
                    requestHeaders: [
                        { header: "User-Agent", operation: "set", value: profile.ua },
                        { header: "Sec-CH-UA", operation: "set", value: profile.ch_ua },
                        { header: "Sec-CH-UA-Platform", operation: "set", value: profile.ch_platform },
                        { header: "Sec-CH-UA-Mobile", operation: "set", value: profile.ch_mobile },
                        { header: "Sec-CH-UA-Model", operation: "set", value: profile.ch_model }
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
                await brw.scripting.unregisterContentScripts({ ids: ['userAgentDOM'] });
            } catch(e) {}
            try {
                await brw.scripting.registerContentScripts([{
                    id: 'userAgentDOM',
                    js: [`modules/userAgentSpoof/inject_${profileKey}.js`],
                    matches: ['<all_urls>'],
                    world: 'MAIN',
                    runAt: 'document_start',
                    allFrames: true,
                    matchOriginAsFallback: true
                }]);
            } catch(e) {}
            console.log(`[OPSECHub:UASpoof] Enabled using profile: ${profile.label}`);
        } catch (e) {
            console.error('[OPSECHub:UASpoof] Error:', e);
        }
    }
};
