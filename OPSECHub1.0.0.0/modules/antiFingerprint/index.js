const brw = typeof browser !== 'undefined' ? browser : chrome;

export default {
    async toggle(enabled, mode = 'noise') {
        try {
            // Clean up any previous registration
            try { await brw.scripting.unregisterContentScripts({ ids: ['antiFingerprintDOM'] }); } catch (e) {}

            if (!enabled) {
                console.log('[OPSECHub:AntiFingerprint] Disabled');
                return;
            }

            let scriptFile = '';
            if (mode === 'noise') {
                scriptFile = 'modules/antiFingerprint/inject.js';
                console.log('[OPSECHub:AntiFingerprint] Enabled - Noise Mode (Randomized Pixels + HW)');
            } else if (mode === 'blend-in') {
                scriptFile = 'modules/antiFingerprint/injectBlendIn.js';
                console.log('[OPSECHub:AntiFingerprint] Enabled - Blend-In Mode (Standard HW Spoofing only)');
            } else {
                console.log('[OPSECHub:AntiFingerprint] Unknown mode, disabled.');
                return;
            }

            await brw.scripting.registerContentScripts([{
                id: 'antiFingerprintDOM',
                js: [scriptFile],
                matches: ['<all_urls>'],
                world: 'MAIN',
                runAt: 'document_start',
                allFrames: true,
                matchOriginAsFallback: true
            }]);
        } catch (e) {
            console.error('[OPSECHub:AntiFingerprint] Error:', e);
        }
    }
};
