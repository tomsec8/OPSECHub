const brw = typeof browser !== 'undefined' ? browser : chrome;

export default {
    async toggle(enabled) {
        console.log(`[OPSECHub:ClickjackXSS] ${enabled ? 'ENABLED' : 'DISABLED'}`);
        try {
            const tabs = await brw.tabs.query({});
            for (const tab of tabs) {
                if (tab.url && !tab.url.startsWith('chrome://')) {
                    brw.tabs.sendMessage(tab.id, {
                        action: 'toggleModule',
                        module: 'clickjackXss',
                        enabled: enabled
                    }).catch(() => {});
                }
            }
        } catch(e) {}
    }
};
