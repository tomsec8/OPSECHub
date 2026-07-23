const brw = typeof browser !== 'undefined' ? browser : chrome;

export default {
    async toggle(enabled) {
        if (!brw.contentSettings || !brw.contentSettings.location) {
            console.error('[OPSECHub:LocationBlock] ContentSettings API not available.');
            return;
        }

        let setting = 'ask';
        if (enabled) {
            const data = await brw.storage.local.get({ locationMode: 'block' });
            setting = (data.locationMode === 'block') ? 'block' : 'allow';
        }

        brw.contentSettings.location.set({
            primaryPattern: '<all_urls>',
            setting: setting
        }, async () => {
            if (brw.runtime.lastError) {
                console.error('[OPSECHub:LocationBlock] Set Error:', brw.runtime.lastError);
            } else {
                console.log(`[OPSECHub:LocationBlock] Location globally set to: ${setting}`);
            }
        });

        try {
            const existing = await brw.scripting.getRegisteredContentScripts({ ids: ['locationBlock'] });
            if (enabled) {
                if (existing.length === 0) {
                    await brw.scripting.registerContentScripts([{
                        id: 'locationBlock',
                        matches: ["<all_urls>"],
                        js: ['modules/locationBlock/inject.js'],
                        runAt: "document_start",
                        world: "MAIN",
                        allFrames: true,
                        matchOriginAsFallback: true
                    }]);
                    console.log(`[OPSECHub:LocationBlock] Inject script ENABLED`);
                }
            } else {
                if (existing.length > 0) {
                    await brw.scripting.unregisterContentScripts({ ids: ['locationBlock'] });
                    console.log(`[OPSECHub:LocationBlock] Inject script DISABLED`);
                }
            }
        } catch (e) {
            console.warn(`[OPSECHub:LocationBlock] Error toggling inject script:`, e);
        }
    }
};
