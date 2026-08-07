const brw = typeof browser !== 'undefined' ? browser : chrome;

export default {
    async toggle(enabled) {
        if (!brw.contentSettings || !brw.contentSettings.camera || !brw.contentSettings.microphone) {
            console.error('[OPSECHub:MediaBlock] ContentSettings API not available.');
            return;
        }

        const setting = enabled ? 'block' : 'ask';

        brw.contentSettings.camera.set({
            primaryPattern: '<all_urls>',
            setting: setting
        }, () => {
            if (brw.runtime.lastError) console.error(brw.runtime.lastError);
        });

        brw.contentSettings.microphone.set({
            primaryPattern: '<all_urls>',
            setting: setting
        }, () => {
            if (brw.runtime.lastError) console.error(brw.runtime.lastError);
            else console.log(`[OPSECHub:MediaBlock] Camera & Mic globally set to: ${setting}`);
        });

        try {
            const existing = await brw.scripting.getRegisteredContentScripts({ ids: ['mediaBlock'] });
            if (enabled) {
                if (existing.length === 0) {
                    await brw.scripting.registerContentScripts([{
                        id: 'mediaBlock',
                        matches: ["<all_urls>"],
                        js: ['modules/mediaBlock/inject.js'],
                        runAt: "document_start",
                        world: "MAIN",
                        allFrames: true,
                        matchOriginAsFallback: true
                    }]);
                    console.log(`[OPSECHub:MediaBlock] Inject script ENABLED`);
                }
            } else {
                if (existing.length > 0) {
                    await brw.scripting.unregisterContentScripts({ ids: ['mediaBlock'] });
                    console.log(`[OPSECHub:MediaBlock] Inject script DISABLED`);
                }
            }
        } catch (e) {
            console.warn(`[OPSECHub:MediaBlock] Error toggling script:`, e);
        }
    }
};
