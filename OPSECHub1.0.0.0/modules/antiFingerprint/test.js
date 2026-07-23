const brw = typeof browser !== 'undefined' ? browser : chrome;

// Session Seed for simulating the background script behavior
let SESSION_SEED_VAL = (crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296.0);
let SESSION_SEED = Math.floor(SESSION_SEED_VAL * 1000000);

function djb2Hash(str) {
    let hash = 5381;
    for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) + hash) + str.charCodeAt(i);
        hash = hash & hash; // Convert to 32bit integer
    }
    return Math.abs(hash).toString(16).toUpperCase();
}

function applyCanvasNoise(dataArray) {
    const shift = Math.floor(SESSION_SEED_VAL * 10) + 15; // 15 to 24
    for (let i = 0; i < dataArray.length; i += 4) {
        if (dataArray[i+3] > 0) {
            dataArray[i] = (dataArray[i] + shift) & 0xFF;
            dataArray[i+1] = (dataArray[i+1] + shift) & 0xFF;
            dataArray[i+2] = (dataArray[i+2] + shift) & 0xFF;
        }
    }
}

// Apply local patches to simulate content script injection on extension-level pages in Noise Mode
function applyLocalFingerprintPatches() {
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;

    HTMLCanvasElement.prototype.toDataURL = function(...args) {
        if (this.width > 0 && this.height > 0) {
            try {
                if (this.getContext('2d')) {
                    const cloneCanvas = document.createElement('canvas');
                    cloneCanvas.width = this.width;
                    cloneCanvas.height = this.height;
                    const cloneCtx = cloneCanvas.getContext('2d', { willReadFrequently: true });
                    
                    cloneCtx.drawImage(this, 0, 0);
                    const imgData = originalGetImageData.call(cloneCtx, 0, 0, cloneCanvas.width, cloneCanvas.height);
                    applyCanvasNoise(imgData.data);
                    cloneCtx.putImageData(imgData, 0, 0);
                    return originalToDataURL.apply(cloneCanvas, args); 
                }
            } catch(e) {}
        }
        return originalToDataURL.apply(this, args);
    };

    const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(param) {
        if (param === 37445) return 'Google Inc. (Intel)';
        if (param === 37446) {
            const models = ['Intel(R) Iris(TM) Plus Graphics 640', 'Intel(R) UHD Graphics 620', 'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)', 'Apple M1', 'AMD Radeon Pro 5300M'];
            return models[Math.floor(SESSION_SEED_VAL * models.length)];
        }
        return originalGetParameter.apply(this, arguments);
    };

    if (window.WebGL2RenderingContext) {
        const originalGetParameter2 = WebGL2RenderingContext.prototype.getParameter;
        WebGL2RenderingContext.prototype.getParameter = function(param) {
            if (param === 37445) return 'Google Inc. (Intel)';
            if (param === 37446) {
                const models = ['Intel(R) Iris(TM) Plus Graphics 640', 'Intel(R) UHD Graphics 620', 'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)', 'Apple M1', 'AMD Radeon Pro 5300M'];
                return models[Math.floor(SESSION_SEED_VAL * models.length)];
            }
            return originalGetParameter2.apply(this, arguments);
        };
    }

    Object.defineProperty(navigator, 'deviceMemory', {
        get: () => 8,
        configurable: true
    });
}

// Apply local patches to simulate content script injection in Blend-In (Standard Spoofing) Mode
function applyLocalBlendInPatches() {
    const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
    WebGLRenderingContext.prototype.getParameter = function(param) {
        if (param === 37445) return 'Google Inc. (Intel)';
        if (param === 37446) return 'Intel(R) UHD Graphics 620';
        return originalGetParameter.apply(this, arguments);
    };

    if (window.WebGL2RenderingContext) {
        const originalGetParameter2 = WebGL2RenderingContext.prototype.getParameter;
        WebGL2RenderingContext.prototype.getParameter = function(param) {
            if (param === 37445) return 'Google Inc. (Intel)';
            if (param === 37446) return 'Intel(R) UHD Graphics 620';
            return originalGetParameter2.apply(this, arguments);
        };
    }

    Object.defineProperty(navigator, 'deviceMemory', {
        get: () => 8,
        configurable: true
    });
}

function runDiagnostics() {
    const canvas = document.getElementById('test-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    
    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Draw complex Canvas Fingerprinting shapes & texts
    ctx.fillStyle = "#f60";
    ctx.fillRect(10, 10, 50, 50);
    ctx.fillStyle = "#09f";
    ctx.beginPath();
    ctx.arc(100, 35, 25, 0, Math.PI * 2, true);
    ctx.closePath();
    ctx.fill();
    
    ctx.font = "16px Arial";
    ctx.fillStyle = "#000";
    ctx.fillText("OPSECHub Test", 50, 70);
    
    // Calculate hash of Canvas data
    const dataUrl = canvas.toDataURL();
    const hash = djb2Hash(dataUrl);
    
    // Display values
    document.getElementById('canvas-hash').textContent = hash;
    
    // Check WebGL Spoofing
    try {
        const glCanvas = document.createElement('canvas');
        const gl = glCanvas.getContext('webgl') || glCanvas.getContext('experimental-webgl');
        if (gl) {
            const dbgRenderInfo = gl.getExtension('WEBGL_debug_renderer_info');
            const renderer = dbgRenderInfo ? gl.getParameter(dbgRenderInfo.UNMASKED_RENDERER_WEBGL) : 'Not Available';
            document.getElementById('webgl-renderer').textContent = renderer;
        } else {
            document.getElementById('webgl-renderer').textContent = 'WebGL Disabled';
        }
    } catch (e) {
        document.getElementById('webgl-renderer').textContent = 'Error';
    }
    
    // Check Navigator Spoofing
    const memory = navigator.deviceMemory || 'Not Available';
    document.getElementById('hw-memory').textContent = memory + ' GB';
}

document.addEventListener('DOMContentLoaded', () => {
    function refreshDiagnostics() {
        brw.storage.local.get({ moduleStates: {}, antiFingerprintMode: 'blend-in' }).then(data => {
            const enabled = data.moduleStates.antiFingerprint;
            const mode = data.antiFingerprintMode;

            if (enabled) {
                if (mode === 'noise') {
                    if (!window.__afp_patched) {
                        applyLocalFingerprintPatches();
                        window.__afp_patched = 'noise';
                    } else if (window.__afp_patched === 'blend-in') {
                        location.reload();
                        return;
                    }
                    SESSION_SEED = crypto.getRandomValues(new Uint32Array(1))[0];
                } else if (mode === 'blend-in') {
                    if (!window.__afp_patched) {
                        applyLocalBlendInPatches();
                        window.__afp_patched = 'blend-in';
                    } else if (window.__afp_patched === 'noise') {
                        location.reload();
                        return;
                    }
                }
            } else {
                if (window.__afp_patched) {
                    location.reload();
                    return;
                }
            }

            runDiagnostics();
        });
    }

    // Initial run
    refreshDiagnostics();

    const refreshBtn = document.getElementById('btn-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshDiagnostics);
    }
});
