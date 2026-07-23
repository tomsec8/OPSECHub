const brw = typeof browser !== 'undefined' ? browser : chrome;

export default {
    async toggle(enabled, mode = 'noise') {
        try {
            // Clean up any previous registration safely
            try {
                const existing = await brw.scripting.getRegisteredContentScripts({ ids: ['antiFingerprintDOM'] });
                if (existing && existing.length > 0) {
                    await brw.scripting.unregisterContentScripts({ ids: ['antiFingerprintDOM'] });
                }
            } catch (e) {
                try { await brw.scripting.unregisterContentScripts({ ids: ['antiFingerprintDOM'] }); } catch (err) {}
            }

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

            try {
                await brw.scripting.registerContentScripts([{
                    id: 'antiFingerprintDOM',
                    js: [scriptFile],
                    matches: ['<all_urls>'],
                    world: 'MAIN',
                    runAt: 'document_start',
                    allFrames: true,
                    matchOriginAsFallback: true
                }]);
            } catch (regErr) {
                if (!regErr.message || !regErr.message.includes('Duplicate script ID')) {
                    console.error('[OPSECHub:AntiFingerprint] Registration Error:', regErr);
                }
            }
        } catch (e) {
            console.error('[OPSECHub:AntiFingerprint] Error:', e);
        }
    }
};
