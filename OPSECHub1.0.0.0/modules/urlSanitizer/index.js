const brw = typeof browser !== 'undefined' ? browser : chrome;

const DNR_RULE_ID = 900005;

// Comprehensive list of tracking parameters based on AdGuard/ClearURLs filters + Modern 2026 Additions
const trackingParams = [
    // Google & Modern iOS Bypasses
    "utm_source", "utm_medium", "utm_term", "utm_campaign", "utm_content", "utm_name", "utm_cid", "utm_reader", "utm_viz_id", "utm_pubreferrer", "utm_swu", "gclid", "gclsrc", "dclid", "_gl", "_ga", "wbraid", "gbraid", "gad_source", "gad_campaignid", "srsltid", "utm_id",
    // Facebook / Instagram / Pinterest / LinkedIn
    "fbclid", "igshid", "igsh", "fb_action_ids", "fb_action_types", "fb_ref", "fb_source", "epik", "li_fat_id",
    // Microsoft / Bing
    "msclkid", "cvid",
    // Twitter & TikTok & Youtube Sharing
    "twclid", "ttclid", "si",
    // Yandex
    "yclid", "_openstat",
    // HubSpot / MailChimp / Klaviyo / ActiveCampaign
    "_hsenc", "_hsmi", "__hssc", "__hstc", "hsCtaTracking", "mc_cid", "mc_eid", "_ke", "_kx", "vgo_ee",
    // Generic / Affiliate (CJ, Impact Radius, etc)
    "click_id", "ref", "referrer", "aff_id", "affiliate", "tracking_id", "mkt_tok", "irclickid", "cjevent",
    // Matomo (Open Source Analytics)
    "mtm_source", "mtm_medium", "mtm_campaign", "mtm_cid"
];

export default {
    async toggle(enabled) {
        try {
            if (!enabled) {
                await brw.declarativeNetRequest.updateSessionRules({ removeRuleIds: [DNR_RULE_ID] });
                console.log('[OPSECHub:URLSanitizer] Disabled');
                return;
            }

            const rule = {
                id: DNR_RULE_ID,
                priority: 250,
                action: {
                    type: "redirect",
                    redirect: {
                        transform: {
                            queryTransform: {
                                removeParams: trackingParams
                            }
                        }
                    }
                },
                condition: {
                    resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest"]
                }
            };

            await brw.declarativeNetRequest.updateSessionRules({
                removeRuleIds: [DNR_RULE_ID],
                addRules: [rule]
            });
            console.log(`[OPSECHub:URLSanitizer] Enabled - Stripping ${trackingParams.length} tracking parameters`);
        } catch (e) {
            console.error('[OPSECHub:URLSanitizer] Error:', e);
        }
    }
};
