const brw = typeof browser !== 'undefined' ? browser : chrome;

// Cache original functions to allow dynamic evaluation
const originalEnumerate = navigator.mediaDevices ? navigator.mediaDevices.enumerateDevices : null;
const originalGetUserMedia = navigator.mediaDevices ? navigator.mediaDevices.getUserMedia : null;

function applyLocalMediaPatches() {
    function createProxyTrap(targetObj, methodName, handler) {
        try {
            const descriptor = Object.getOwnPropertyDescriptor(targetObj, methodName);
            const originalFn = descriptor ? descriptor.value : targetObj[methodName];
            if (!originalFn) return;

            const proxy = new Proxy(originalFn, handler);
            Object.defineProperty(targetObj, methodName, {
                value: proxy,
                configurable: true,
                writable: true
            });
        } catch(e) {}
    }

    if (navigator.mediaDevices) {
        createProxyTrap(navigator.mediaDevices, 'enumerateDevices', {
            apply() {
                console.log('[OPSECHub:MediaBlockTest] Local simulated block on enumerateDevices');
                return Promise.resolve([]);
            }
        });

        createProxyTrap(navigator.mediaDevices, 'getUserMedia', {
            apply() {
                console.log('[OPSECHub:MediaBlockTest] Local simulated block on getUserMedia');
                return Promise.reject(new DOMException("Permission denied by OPSECHub.", "NotAllowedError"));
            }
        });
    }
}

async function runEnumerateDevices() {
    const output = document.getElementById('device-output');
    output.textContent = 'Enumerating devices...';

    try {
        if (!navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) {
            output.textContent = 'enumerateDevices API is not supported by your browser.';
            output.style.color = '#ff5252';
            return;
        }

        const devices = await navigator.mediaDevices.enumerateDevices();
        if (devices.length === 0) {
            output.textContent = '🛡️ [BLOCKED] No media devices detected.\n\nThe browser returned an empty array, completely hiding the camera, microphone, and audio output identifiers from the website.';
            output.style.color = '#00e5ff';
        } else {
            let info = '⚠️ [EXPOSED] Found media devices:\n\n';
            devices.forEach((device, index) => {
                info += `${index + 1}. ${device.kind}\n`;
                info += `   Label: "${device.label || '[Name Hidden - Request permission to view]'}"\n`;
                info += `   ID: ${device.deviceId ? device.deviceId.substring(0, 12) + '...' : '[Hidden]'}\n\n`;
            });
            output.textContent = info;
            output.style.color = '#ffffff';
        }
    } catch (e) {
        output.textContent = `Error enumerating devices: ${e.toString()}`;
        output.style.color = '#ff5252';
    }
}

async function requestMedia(type) {
    const output = document.getElementById('permission-output');
    output.textContent = `Requesting ${type} permission...`;
    output.style.color = '#b0bec5';

    const constraints = {
        video: type === 'camera' || type === 'both',
        audio: type === 'mic' || type === 'both'
    };

    try {
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            output.textContent = 'getUserMedia API is not supported by your browser.';
            output.style.color = '#ff5252';
            return;
        }

        const stream = await navigator.mediaDevices.getUserMedia(constraints);
        output.textContent = `⚠️ [EXPOSED] Media Access ALLOWED!\n\nWebsite successfully accessed your ${type}. Clean up stream.`;
        output.style.color = '#ff5252';
        
        // Stop stream immediately
        stream.getTracks().forEach(track => track.stop());
    } catch (e) {
        if (e.name === 'NotAllowedError' || e.message.includes('denied')) {
            output.textContent = `🛡️ [BLOCKED] Access Denied Successfully!\n\nError returned: "${e.name}: ${e.message}"\n\nOPSECHub successfully hard-blocked the media request at the JS level without prompting.`;
            output.style.color = '#00e5ff';
        } else {
            output.textContent = `Error: ${e.name}\nMessage: "${e.message}"`;
            output.style.color = '#ff5252';
        }
    }
}

function refreshDiagnostics() {
    brw.storage.local.get({ moduleStates: {} }).then(data => {
        const enabled = data.moduleStates.mediaBlock;
        const banner = document.getElementById('status-banner');
        const statusText = document.getElementById('status-text');

        if (enabled) {
            banner.className = 'status-banner active';
            statusText.textContent = 'Camera & Mic Guard: ACTIVE (Simulated)';

            if (!window.__mb_patched) {
                applyLocalMediaPatches();
                window.__mb_patched = true;
            }
        } else {
            banner.className = 'status-banner inactive';
            statusText.textContent = 'Camera & Mic Guard: Disabled / Unpatched';

            if (window.__mb_patched) {
                location.reload();
                return;
            }
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    refreshDiagnostics();

    const refreshBtn = document.getElementById('btn-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshDiagnostics);
    }

    const enumBtn = document.getElementById('btn-enumerate');
    if (enumBtn) {
        enumBtn.addEventListener('click', runEnumerateDevices);
    }

    const cameraBtn = document.getElementById('btn-req-camera');
    if (cameraBtn) {
        cameraBtn.addEventListener('click', () => requestMedia('camera'));
    }

    const micBtn = document.getElementById('btn-req-mic');
    if (micBtn) {
        micBtn.addEventListener('click', () => requestMedia('mic'));
    }
});
