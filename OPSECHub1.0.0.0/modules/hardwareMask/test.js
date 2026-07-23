const brw = typeof browser !== 'undefined' ? browser : chrome;

// Keep original values to determine if spoofing is currently active
const originalCores = navigator.hardwareConcurrency;
const originalMemory = navigator.deviceMemory;
const originalTouch = navigator.maxTouchPoints;

function applyLocalHardwarePatches() {
    function spoof(obj, prop, value) {
        try {
            Object.defineProperty(obj, prop, {
                get: () => value,
                configurable: true,
                enumerable: true
            });
        } catch(e) {}
    }

    // Spoof CPU, RAM & Touch Points
    spoof(Navigator.prototype, 'hardwareConcurrency', 8);
    spoof(Navigator.prototype, 'deviceMemory', 8);
    spoof(Navigator.prototype, 'maxTouchPoints', 0);

    // Spoof Battery
    if (Navigator.prototype.getBattery) {
        const fakeBattery = {
            charging: true,
            chargingTime: 0,
            dischargingTime: Infinity,
            level: 1.0,
            onchargingchange: null,
            onchargingtimechange: null,
            ondischargingtimechange: null,
            onlevelchange: null,
            addEventListener: function() {},
            removeEventListener: function() {},
            dispatchEvent: function() { return true; }
        };
        spoof(Navigator.prototype, 'getBattery', () => Promise.resolve(fakeBattery));
    }

    // Spoof Screen Information
    const screenProps = {
        width: 1920, height: 1080,
        availWidth: 1920, availHeight: 1040,
        colorDepth: 24, pixelDepth: 24
    };
    for (const [prop, value] of Object.entries(screenProps)) {
        spoof(Screen.prototype, prop, value);
    }

    // Hook dynamically appended Same-Origin iframe creations (realm poisoning simulation)
    if (window.Node) {
        const originalAppend = Node.prototype.appendChild;
        Node.prototype.appendChild = function(node) {
            const result = originalAppend.call(this, node);
            if (node && node.tagName === 'IFRAME') {
                try {
                    if (node.contentWindow) {
                        applyIframeLocalPatches(node.contentWindow);
                    }
                } catch(e) {}
            }
            return result;
        };
    }
}

function applyIframeLocalPatches(win) {
    function spoof(obj, prop, value) {
        try {
            Object.defineProperty(obj, prop, {
                get: () => value,
                configurable: true,
                enumerable: true
            });
        } catch(e) {}
    }
    spoof(win.Navigator.prototype, 'hardwareConcurrency', 8);
    spoof(win.Navigator.prototype, 'deviceMemory', 8);
    spoof(win.Navigator.prototype, 'maxTouchPoints', 0);
}

async function renderDiagnostics() {
    const coresEl = document.getElementById('val-cores');
    const memoryEl = document.getElementById('val-memory');
    const touchEl = document.getElementById('val-touch');

    const screenSzEl = document.getElementById('val-screen-size');
    const screenAvEl = document.getElementById('val-screen-avail');
    const screenDpEl = document.getElementById('val-screen-depth');

    const batSupEl = document.getElementById('val-bat-supported');
    const batChgEl = document.getElementById('val-bat-charging');
    const batLvlEl = document.getElementById('val-bat-level');

    // 1. Processor & Memory
    const currentCores = navigator.hardwareConcurrency;
    coresEl.textContent = `${currentCores} Cores`;
    if (currentCores === 8) {
        coresEl.className = 'value spoofed';
        coresEl.textContent += ' (Spoofed)';
    } else {
        coresEl.className = 'value';
    }

    const currentMemory = navigator.deviceMemory;
    memoryEl.textContent = currentMemory ? `${currentMemory} GB` : 'Not Available';
    if (currentMemory === 8) {
        memoryEl.className = 'value spoofed';
        memoryEl.textContent += ' (Spoofed)';
    } else {
        memoryEl.className = 'value';
    }

    const currentTouch = navigator.maxTouchPoints;
    touchEl.textContent = currentTouch;
    if (currentTouch === 0) {
        touchEl.className = 'value spoofed';
        touchEl.textContent += ' (Spoofed)';
    } else {
        touchEl.className = 'value';
    }

    // 2. Screen
    screenSzEl.textContent = `${screen.width} x ${screen.height}`;
    if (screen.width === 1920 && screen.height === 1080) {
        screenSzEl.className = 'value spoofed';
        screenSzEl.textContent += ' (Spoofed)';
    } else {
        screenSzEl.className = 'value';
    }

    screenAvEl.textContent = `${screen.availWidth} x ${screen.availHeight}`;
    if (screen.availWidth === 1920 && screen.availHeight === 1040) {
        screenAvEl.className = 'value spoofed';
        screenAvEl.textContent += ' (Spoofed)';
    } else {
        screenAvEl.className = 'value';
    }

    screenDpEl.textContent = `${screen.colorDepth}-bit / ${screen.pixelDepth}-bit`;
    if (screen.colorDepth === 24) {
        screenDpEl.className = 'value spoofed';
        screenDpEl.textContent += ' (Spoofed)';
    } else {
        screenDpEl.className = 'value';
    }

    // 3. Battery API
    if (navigator.getBattery) {
        batSupEl.textContent = 'Supported';
        batSupEl.className = 'value';

        try {
            const battery = await navigator.getBattery();
            batChgEl.textContent = battery.charging ? 'Charging (Spoofed/Full)' : 'Discharging';
            if (battery.charging && battery.level === 1.0) {
                batChgEl.className = 'value spoofed';
            } else {
                batChgEl.className = 'value';
            }

            batLvlEl.textContent = `${Math.round(battery.level * 100)}%`;
            if (battery.level === 1.0) {
                batLvlEl.className = 'value spoofed';
            } else {
                batLvlEl.className = 'value';
            }
        } catch(e) {
            batChgEl.textContent = 'Error reading values';
            batLvlEl.textContent = 'Error';
        }
    } else {
        batSupEl.textContent = 'Not Supported';
        batSupEl.className = 'value';
        batChgEl.textContent = 'N/A';
        batLvlEl.textContent = 'N/A';
    }
}

function refreshDiagnostics() {
    brw.storage.local.get({ moduleStates: {} }).then(async data => {
        const enabled = data.moduleStates.hardwareMask;
        const banner = document.getElementById('status-banner');
        const statusText = document.getElementById('status-text');

        if (enabled) {
            banner.className = 'status-banner active';
            statusText.textContent = 'Hardware Masking: ACTIVE (Simulated)';

            if (!window.__hwm_patched) {
                applyLocalHardwarePatches();
                window.__hwm_patched = true;
            }
        } else {
            banner.className = 'status-banner inactive';
            statusText.textContent = 'Hardware Masking: Disabled / Unpatched';

            if (window.__hwm_patched) {
                location.reload();
                return;
            }
        }

        await renderDiagnostics();
    });
}

function testDynamicIFrame() {
    const iframeEl = document.getElementById('val-iframe-cores');
    iframeEl.textContent = 'Creating IFrame...';

    // Create a temporary Same-Origin iframe
    const iframe = document.createElement('iframe');
    iframe.style.display = 'none';
    document.body.appendChild(iframe);

    try {
        const iframeCores = iframe.contentWindow.navigator.hardwareConcurrency;
        iframeEl.textContent = `${iframeCores} Cores`;
        if (iframeCores === 8) {
            iframeEl.className = 'value spoofed';
            iframeEl.textContent += ' (Spoofed)';
        } else {
            iframeEl.className = 'value';
            iframeEl.textContent += ' (Exposed!)';
        }
    } catch(e) {
        iframeEl.textContent = `Error: ${e.toString()}`;
    }

    // Clean up
    document.body.removeChild(iframe);
}

document.addEventListener('DOMContentLoaded', () => {
    refreshDiagnostics();

    const refreshBtn = document.getElementById('btn-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshDiagnostics);
    }

    const testIframeBtn = document.getElementById('btn-test-iframe');
    if (testIframeBtn) {
        testIframeBtn.addEventListener('click', testDynamicIFrame);
    }
});
