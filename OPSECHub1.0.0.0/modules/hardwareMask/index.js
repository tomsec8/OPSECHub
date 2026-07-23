const brw = typeof browser !== 'undefined' ? browser : chrome;

export default {
    async toggle(enabled) {
        try {
            const existing = await brw.scripting.getRegisteredContentScripts({ ids: ['hardwareMask'] });
            if (enabled) {
                if (existing.length === 0) {
                    await brw.scripting.registerContentScripts([{
                        id: 'hardwareMask',
                        matches: ["<all_urls>"],
                        js: ['modules/hardwareMask/inject.js'],
                        runAt: "document_start",
                        world: "MAIN",
                        allFrames: true,
                        matchOriginAsFallback: true
                    }]);
                    console.log(`[OPSECHub:HardwareMask] Script ENABLED`);
                }
            } else {
                if (existing.length > 0) {
                    await brw.scripting.unregisterContentScripts({ ids: ['hardwareMask'] });
                    console.log(`[OPSECHub:HardwareMask] Script DISABLED`);
                }
            }
        } catch (e) {
            console.warn(`[OPSECHub:HardwareMask] Error toggling script:`, e);
        }
    }
};
