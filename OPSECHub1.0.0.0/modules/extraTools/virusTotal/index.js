// 🔍 Tool: Dedicated VirusTotal Hash Checker (Privacy-First)
function initVirusTotalTool() {
    const fileInput = document.getElementById('input-vt-file');
    const hashInput = document.getElementById('txt-vt-hash');
    const searchBtn = document.getElementById('btn-vt-search');
    const statusEl = document.getElementById('status-vt-tool');

    if (!searchBtn) return;

    // Helper to calculate SHA-256
    const calcSHA256 = async (file) => {
        const buffer = await file.arrayBuffer();
        const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    };

    if (fileInput) {
        fileInput.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;

            statusEl.textContent = '⏳ Computing file hash locally...';
            statusEl.style.color = '#00e5ff';

            try {
                const sha256 = await calcSHA256(file);
                hashInput.value = sha256;
                statusEl.textContent = '✅ Hash computed! Click search to check VirusTotal.';
                statusEl.style.color = '#30d158';
            } catch (err) {
                console.error(err);
                statusEl.textContent = '❌ Failed to compute file hash.';
                statusEl.style.color = '#ff453a';
            }
        });
    }

    searchBtn.addEventListener('click', () => {
        const hash = hashInput.value.trim();
        if (!hash) {
            statusEl.textContent = '❌ Please select a file or paste a file hash (MD5, SHA-1, SHA-256).';
            statusEl.style.color = '#ff453a';
            return;
        }

        // Validate hash length (MD5=32, SHA1=40, SHA256=64)
        if (!/^[a-fA-F0-9]{32}$/.test(hash) && !/^[a-fA-F0-9]{40}$/.test(hash) && !/^[a-fA-F0-9]{64}$/.test(hash)) {
            statusEl.textContent = '❌ Invalid hash format. Must be MD5, SHA-1, or SHA-256 hex string.';
            statusEl.style.color = '#ff453a';
            return;
        }

        statusEl.textContent = '🚀 Opening VirusTotal report...';
        statusEl.style.color = '#30d158';

        chrome.tabs.create({ url: `https://www.virustotal.com/gui/file/${hash}` }).catch(() => {});
    });
}
