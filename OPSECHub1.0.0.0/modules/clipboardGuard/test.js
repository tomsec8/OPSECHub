const brw = typeof browser !== 'undefined' ? browser : chrome;

function applyLocalClipboardPatches() {
    if (navigator.clipboard && !window.__clipboard_patched_local) {
        window.__clipboard_patched_local = true;

        const originalClipboard = navigator.clipboard;
        const clipboardProxy = new Proxy(originalClipboard, {
            get(target, prop) {
                if (prop === 'readText') {
                    return function() {
                        try {
                            const event = new CustomEvent('opsechub-block-event', {
                                detail: { module: 'clipboardGuard', action: 'read clipboard text' }
                            });
                            window.dispatchEvent(event);
                        } catch(e) {}
                        return Promise.reject(new DOMException("Clipboard read denied by OPSECHub."));
                    };
                }
                if (prop === 'read') {
                    return function() {
                        try {
                            const event = new CustomEvent('opsechub-block-event', {
                                detail: { module: 'clipboardGuard', action: 'read clipboard data' }
                            });
                            window.dispatchEvent(event);
                        } catch(e) {}
                        return Promise.reject(new DOMException("Clipboard read denied by OPSECHub."));
                    };
                }
                const val = target[prop];
                if (typeof val === 'function') {
                    return val.bind(target);
                }
                return val;
            }
        });

        Object.defineProperty(navigator, 'clipboard', {
            get: function() { return clipboardProxy; },
            configurable: true
        });
    }

    if (typeof Document !== 'undefined' && Document.prototype.execCommand && !window.__execcommand_patched_local) {
        window.__execcommand_patched_local = true;
        const originalExecCommand = Document.prototype.execCommand;
        Document.prototype.execCommand = function(command, showUI, value) {
            if (command.toLowerCase() === 'paste') {
                try {
                    const event = new CustomEvent('opsechub-block-event', {
                        detail: { module: 'clipboardGuard', action: 'paste text' }
                    });
                    window.dispatchEvent(event);
                } catch(e) {}
                return false;
            }
            return originalExecCommand.call(this, command, showUI, value);
        };
    }
}

async function copyTestData() {
    const text = document.getElementById('copy-input').value;
    const status = document.getElementById('copy-status');
    status.textContent = 'Copying...';
    status.style.color = '#00e5ff';
    try {
        await navigator.clipboard.writeText(text);
        status.textContent = '✓ Copied successfully!';
        status.style.color = '#4caf50';
    } catch(e) {
        status.textContent = '✗ Failed: ' + e.name;
        status.style.color = '#f44336';
    }
}

async function readClipboard() {
    const output = document.getElementById('read-output');
    output.textContent = 'Reading clipboard contents...';
    output.style.color = '#b0bec5';

    try {
        if (!navigator.clipboard || !navigator.clipboard.readText) {
            output.textContent = 'Error: navigator.clipboard.readText is not supported by your browser.';
            output.style.color = '#ff5252';
            return;
        }

        const text = await navigator.clipboard.readText();
        output.innerHTML = `<span style="color: #f44336; font-weight: bold;">⚠️ [EXPOSED] Clipboard Contents Read!</span>\n\nValue: "${text}"\n\nWarning: Webpage was able to read your system clipboard silently.`;
        output.style.color = '#ffffff';
    } catch(e) {
        if (e.message.includes('denied') || e.message.includes('OPSECHub')) {
            output.innerHTML = `<span style="color: #00e5ff; font-weight: bold;">🛡️ [BLOCKED] Read Blocked Successfully!</span>\n\nReturned Error:\n"${e.name}: ${e.message}"\n\nOPSECHub successfully intercepted and blocked the read request.`;
            output.style.color = '#00e5ff';
        } else {
            output.textContent = `Error: ${e.name}\nMessage: "${e.message}"`;
            output.style.color = '#ff5252';
        }
    }
}

function triggerPasteCommand() {
    const output = document.getElementById('paste-output');
    output.textContent = 'Triggering document.execCommand("paste")...\n';
    output.style.color = '#b0bec5';

    try {
        // Focus on copy input to run execCommand
        const input = document.getElementById('copy-input');
        input.focus();
        input.select();

        const success = document.execCommand('paste');
        if (success) {
            output.innerHTML = `<span style="color: #f44336; font-weight: bold;">⚠️ [EXPOSED] paste Command Allowed!</span>\n\nThe execCommand("paste") call returned true.`;
            output.style.color = '#ffffff';
        } else {
            output.innerHTML = `<span style="color: #00e5ff; font-weight: bold;">🛡️ [BLOCKED] paste Command Blocked Successfully!</span>\n\nReturned: false\n\nOPSECHub successfully intercepted and returned false to block the pasting event.`;
            output.style.color = '#00e5ff';
        }
    } catch(e) {
        output.textContent = `Error executing command: ${e.toString()}`;
        output.style.color = '#ff5252';
    }
}

function refreshDiagnostics() {
    brw.storage.local.get({ moduleStates: {} }).then(data => {
        const enabled = data.moduleStates.clipboardGuard;
        const banner = document.getElementById('status-banner');
        const statusText = document.getElementById('status-text');

        if (enabled) {
            banner.className = 'status-banner active';
            statusText.textContent = 'Clipboard Guard: ACTIVE (Simulated)';

            if (!window.__clipboard_patched_local) {
                applyLocalClipboardPatches();
            }
        } else {
            banner.className = 'status-banner inactive';
            statusText.textContent = 'Clipboard Guard: Disabled / Unpatched';

            if (window.__clipboard_patched_local) {
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

    const copyBtn = document.getElementById('btn-copy');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyTestData);
    }

    const readBtn = document.getElementById('btn-read');
    if (readBtn) {
        readBtn.addEventListener('click', readClipboard);
    }

    const pasteBtn = document.getElementById('btn-paste');
    if (pasteBtn) {
        pasteBtn.addEventListener('click', triggerPasteCommand);
    }
});
