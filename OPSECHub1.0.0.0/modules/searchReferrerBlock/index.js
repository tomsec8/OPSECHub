const brw = typeof browser !== 'undefined' ? browser : chrome;

const DNR_RULE_ID = 900004;

export default {
    async toggle(enabled) {
        try {
            if (!enabled) {
                await brw.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [DNR_RULE_ID] });
                console.log('[OPSECHub:SearchReferrerBlock] Disabled');
                return;
            }

            const rule = {
                id: DNR_RULE_ID,
                priority: 150,
                action: {
                    type: "modifyHeaders",
                    requestHeaders: [
                        { header: "Referer", operation: "remove" }
                    ]
                },
                condition: {
                    initiatorDomains: [
                        "google.com", "google.co.il", "google.co.uk", "google.ca", 
                        "google.de", "google.fr", "google.co.jp", "google.es", 
                        "google.it", "google.com.br", "google.com.mx", "google.ru", 
                        "google.com.hk", "google.co.in", "google.com.sg", "google.co.au",
                        "bing.com",
                        "duckduckgo.com",
                        "yahoo.com", "yahoo.co.jp", "yahoo.co.uk", "yahoo.com.br",
                        "yandex.com", "yandex.ru", "yandex.by", "yandex.kz", "yandex.uz",
                        "ecosia.org",
                        "startpage.com",
                        "qwant.com",
                        "baidu.com",
                        "naver.com",
                        "ask.com"
                    ],
                    domainType: "thirdParty",
                    resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest"]
                }
            };

            await brw.declarativeNetRequest.updateDynamicRules({
                removeRuleIds: [DNR_RULE_ID],
                addRules: [rule]
            });
            console.log('[OPSECHub:SearchReferrerBlock] Enabled - Search queries hidden from destination sites');
        } catch (e) {
            console.error('[OPSECHub:SearchReferrerBlock] Error:', e);
        }
    }
};
