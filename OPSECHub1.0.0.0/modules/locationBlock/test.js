const brw = typeof browser !== 'undefined' ? browser : chrome;

let activeWatchId = null;

function applyLocalLocationPatches() {
    const originalGeo = Object.getOwnPropertyDescriptor(Navigator.prototype, 'geolocation');
    if (originalGeo && originalGeo.get && !window.__loc_patched_local) {
        window.__loc_patched_local = true;
        const originalGeoObj = originalGeo.get.call(navigator);
        const spoofedGeo = Object.create(originalGeoObj);
        
        spoofedGeo.getCurrentPosition = function(successCallback, errorCallback) {
            try {
                const event = new CustomEvent('opsechub-block-event', {
                    detail: { module: 'locationBlock', action: 'access geolocation location' }
                });
                window.dispatchEvent(event);
            } catch(e) {}
            setTimeout(() => {
                if (errorCallback) errorCallback({ code: 1, message: "User denied Geolocation by OPSECHub" });
            }, 50);
        };

        spoofedGeo.watchPosition = function(successCallback, errorCallback) {
            try {
                const event = new CustomEvent('opsechub-block-event', {
                    detail: { module: 'locationBlock', action: 'access geolocation location' }
                });
                window.dispatchEvent(event);
            } catch(e) {}
            const watchId = Math.floor(Math.random() * 100000) + 1;
            const triggerWatch = () => {
                if (errorCallback) errorCallback({ code: 1, message: "User denied Geolocation by OPSECHub" });
            };
            setTimeout(triggerWatch, 50);
            const intervalId = setInterval(triggerWatch, 10000);
            if (!window.__opsechub_watches) window.__opsechub_watches = {};
            window.__opsechub_watches[watchId] = intervalId;
            return watchId;
        };

        spoofedGeo.clearWatch = function(watchId) {
            if (window.__opsechub_watches && window.__opsechub_watches[watchId]) {
                clearInterval(window.__opsechub_watches[watchId]);
                delete window.__opsechub_watches[watchId];
            }
        };

        Object.defineProperty(Navigator.prototype, 'geolocation', {
            get: function() { return spoofedGeo; },
            configurable: true
        });
    }
}

function queryCoordinates() {
    const output = document.getElementById('coord-output');
    output.textContent = 'Querying Geolocation API...';
    output.style.color = '#b0bec5';

    if (!navigator.geolocation) {
        output.textContent = 'Error: navigator.geolocation is not supported by this browser.';
        output.style.color = '#ff5252';
        return;
    }

    navigator.geolocation.getCurrentPosition(
        (pos) => {
            output.innerHTML = `<span style="color: #f44336; font-weight: bold;">⚠️ [EXPOSED] Location Accessed!</span>\n\n` +
                               `Latitude:  ${pos.coords.latitude}\n` +
                               `Longitude: ${pos.coords.longitude}\n` +
                               `Accuracy:  ${pos.coords.accuracy}m`;
            output.style.color = '#ffffff';
        },
        (err) => {
            if (err.code === 1 || err.message.includes('denied') || err.message.includes('OPSECHub')) {
                output.innerHTML = `<span style="color: #00e5ff; font-weight: bold;">🛡️ [BLOCKED] Access Denied Successfully!</span>\n\n` +
                                   `Error Code: ${err.code} (PERMISSION_DENIED)\n` +
                                   `Message: "${err.message}"\n\n` +
                                   `OPSECHub successfully intercepted and hard-blocked the geolocation request at the JS level.`;
                output.style.color = '#00e5ff';
            } else {
                output.textContent = `Error (${err.code}): ${err.message}`;
                output.style.color = '#ff5252';
            }
        },
        { enableHighAccuracy: true, timeout: 5000, maximumAge: 0 }
    );
}

function toggleTracking() {
    const btn = document.getElementById('btn-track');
    const output = document.getElementById('track-output');

    if (activeWatchId !== null) {
        // Stop tracking
        navigator.geolocation.clearWatch(activeWatchId);
        activeWatchId = null;
        btn.textContent = 'Start Tracking';
        output.textContent = 'Tracking stopped.';
        output.style.color = '#b0bec5';
        return;
    }

    output.textContent = 'Starting watchPosition query...';
    output.style.color = '#b0bec5';

    activeWatchId = navigator.geolocation.watchPosition(
        (pos) => {
            output.innerHTML = `<span style="color: #f44336; font-weight: bold;">⚠️ [EXPOSED] Live Coordinates Update:</span>\n\n` +
                               `Latitude:  ${pos.coords.latitude}\n` +
                               `Longitude: ${pos.coords.longitude}`;
            output.style.color = '#ffffff';
        },
        (err) => {
            output.innerHTML = `<span style="color: #00e5ff; font-weight: bold;">🛡️ [BLOCKED] Tracking Denied Successfully!</span>\n\n` +
                               `Error Code: ${err.code}\n` +
                               `Message: "${err.message}"`;
            output.style.color = '#00e5ff';
            
            // Clean up watch since it is blocked
            navigator.geolocation.clearWatch(activeWatchId);
            activeWatchId = null;
            btn.textContent = 'Start Tracking';
        }
    );

    if (activeWatchId !== null) {
        btn.textContent = 'Stop Tracking';
    }
}

function refreshDiagnostics() {
    brw.storage.local.get({ moduleStates: {} }).then(data => {
        const enabled = data.moduleStates.locationBlock;
        const banner = document.getElementById('status-banner');
        const statusText = document.getElementById('status-text');

        if (enabled) {
            banner.className = 'status-banner active';
            statusText.textContent = 'Location Guard: ACTIVE (Simulated)';

            if (!window.__loc_patched_local) {
                applyLocalLocationPatches();
            }
        } else {
            banner.className = 'status-banner inactive';
            statusText.textContent = 'Location Guard: Disabled / Unpatched';

            if (window.__loc_patched_local) {
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

    const queryBtn = document.getElementById('btn-query');
    if (queryBtn) {
        queryBtn.addEventListener('click', queryCoordinates);
    }

    const trackBtn = document.getElementById('btn-track');
    if (trackBtn) {
        trackBtn.addEventListener('click', toggleTracking);
    }
});
