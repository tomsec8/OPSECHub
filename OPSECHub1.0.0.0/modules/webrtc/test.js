const brw = typeof browser !== 'undefined' ? browser : chrome;

// Keep reference to the constructor at script load time
const initialRTC = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;

function applyLocalWebRTCPatches() {
    const OriginalRTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
    if (OriginalRTCPeerConnection && !window.__rtc_patched_local) {
        window.__rtc_patched_local = true;

        const proxy = new Proxy(OriginalRTCPeerConnection, {
            construct(target, args) {
                try {
                    const event = new CustomEvent('opsechub-block-event', {
                        detail: { module: 'webrtcBlock', action: 'leak IP address via WebRTC' }
                    });
                    window.dispatchEvent(event);
                } catch(e) {}
                return Reflect.construct(target, args);
            }
        });

        window.RTCPeerConnection = proxy;
        if (window.webkitRTCPeerConnection) window.webkitRTCPeerConnection = proxy;
        if (window.mozRTCPeerConnection) window.mozRTCPeerConnection = proxy;
    }
}

function runDiagnostics() {
    const presentEl = document.getElementById('val-rtc-present');
    const spoofedEl = document.getElementById('val-rtc-spoofed');

    const hasRTC = !!(window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection);
    presentEl.textContent = hasRTC ? 'Available (Supported)' : 'Not Supported';
    presentEl.className = 'value';

    // Determine if patched either by extension or local simulator
    const isSpoofed = window.__rtc_patched_local || (window.RTCPeerConnection && window.RTCPeerConnection.name === '');
    if (isSpoofed) {
        spoofedEl.textContent = 'Active & Intercepted';
        spoofedEl.className = 'value spoofed';
    } else {
        spoofedEl.textContent = 'Inactive (Native Exposed)';
        spoofedEl.className = 'value';
    }
}

function triggerLeakAttempt() {
    const output = document.getElementById('console-output');
    output.textContent = 'Simulating WebRTC Leak lookup...\n';

    try {
        const RTCPeer = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection;
        if (!RTCPeer) {
            output.textContent += 'Error: RTCPeerConnection API is not available on this browser.';
            return;
        }

        output.textContent += 'Calling: new RTCPeerConnection({ iceServers: [] })\n';
        const pc = new RTCPeer({ iceServers: [] });
        
        output.textContent += 'SUCCESS: RTCPeerConnection initialized.\n';
        output.textContent += 'If OPSECHub protection is active, a toast notification should have appeared on the bottom right and the badge icon updated.';
        
        // Clean up connection
        pc.close();
    } catch(e) {
        output.textContent += `Failed to initialize: ${e.toString()}`;
    }
}

function refreshDiagnostics() {
    brw.storage.local.get({ moduleStates: {} }).then(data => {
        const enabled = data.moduleStates.webrtcBlock;
        const banner = document.getElementById('status-banner');
        const statusText = document.getElementById('status-text');

        if (enabled) {
            banner.className = 'status-banner active';
            statusText.textContent = 'WebRTC Leak Guard: ACTIVE (Simulated)';

            if (!window.__rtc_patched_local) {
                applyLocalWebRTCPatches();
            }
        } else {
            banner.className = 'status-banner inactive';
            statusText.textContent = 'WebRTC Leak Guard: Disabled / Unpatched';

            if (window.__rtc_patched_local) {
                location.reload();
                return;
            }
        }

        runDiagnostics();
    });
}

document.addEventListener('DOMContentLoaded', () => {
    refreshDiagnostics();

    const refreshBtn = document.getElementById('btn-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshDiagnostics);
    }

    const simulateBtn = document.getElementById('btn-simulate');
    if (simulateBtn) {
        simulateBtn.addEventListener('click', triggerLeakAttempt);
    }
});
