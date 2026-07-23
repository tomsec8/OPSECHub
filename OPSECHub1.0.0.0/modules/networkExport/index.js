const brw = typeof browser !== 'undefined' ? browser : chrome;

let isEnabled = false;
let networkLogs = [];

function logRequest(details) {
    if (!isEnabled) return;
    networkLogs.push({
        url: details.url,
        method: details.method,
        type: details.type,
        timestamp: Date.now()
    });
    // Keep only last 1000 logs to prevent memory leak
    if (networkLogs.length > 1000) {
        networkLogs.shift();
    }
}

function enable() {
    if (isEnabled) return;
    isEnabled = true;
    console.log('[OPSECHub] Network Export ENABLED');
    
    // Add listener for all completed requests
    if (brw.webRequest && brw.webRequest.onCompleted) {
        brw.webRequest.onCompleted.addListener(logRequest, { urls: ["<all_urls>"] });
    } else {
        console.warn('[OPSECHub:NetworkExport] webRequest API not available.');
    }
}

function disable() {
    if (!isEnabled) return;
    isEnabled = false;
    console.log('[OPSECHub] Network Export DISABLED');
    
    if (brw.webRequest && brw.webRequest.onCompleted) {
        brw.webRequest.onCompleted.removeListener(logRequest);
    }
    networkLogs = []; // Clear logs on disable
}

export default {
    toggle: (enabled) => {
        if (enabled) enable();
        else disable();
    }
};
