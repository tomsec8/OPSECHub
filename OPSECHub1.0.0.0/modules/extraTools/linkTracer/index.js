// 🔗 Tool: Short Link Tracer (CORS-immune background redirect resolver)
function initLinkTracerTool() {
    const txtUrl = document.getElementById('txt-tracer-url');
    const traceBtn = document.getElementById('btn-trace-url');
    const resultBox = document.getElementById('result-link-tracer');
    const listHops = document.getElementById('list-tracer-hops');
    const statusEl = document.getElementById('status-link-tracer');

    if (!traceBtn || !txtUrl) return;

    // Security: Escape HTML entities to prevent XSS via malicious redirect URLs
    function escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    traceBtn.addEventListener('click', () => {
        let url = txtUrl.value.trim();
        if (!url) {
            statusEl.textContent = '❌ Please enter a valid URL.';
            statusEl.style.color = '#ff453a';
            return;
        }

        if (!/^https?:\/\//i.test(url)) {
            url = 'http://' + url;
        }

        statusEl.textContent = '⏳ Tracing redirection path (CORS-immune background probe)...';
        statusEl.style.color = '#00e5ff';
        resultBox.style.display = 'block';
        listHops.innerHTML = '';

        // Delegate network request to the service worker to bypass CORS blocking
        chrome.runtime.sendMessage({
            action: 'trace_redirects_background',
            url: url
        }, (res) => {
            if (chrome.runtime.lastError) {
                console.error(chrome.runtime.lastError);
                statusEl.textContent = '❌ Background connection lost.';
                statusEl.style.color = '#ff453a';
                return;
            }

            if (res && res.success && res.hops) {
                res.hops.forEach((hop, idx) => {
                    const li = document.createElement('li');
                    li.style.cssText = 'padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.05); font-family: monospace; font-size: 12px; color: #b0bec5; word-break: break-all;';
                    
                    if (idx === 0) {
                        li.innerHTML = `<strong>Start:</strong> <span style="color: #ff9800;">${escapeHtml(hop)}</span>`;
                    } else if (idx === res.hops.length - 1) {
                        li.innerHTML = `<strong>Final Destination:</strong> 🏁 <span style="color: #30d158; font-weight: bold;">${escapeHtml(hop)}</span>`;
                    } else {
                        li.innerHTML = `<strong>Hop ${idx}:</strong> Redirecting ➔ <span style="color: #00e5ff;">${escapeHtml(hop)}</span>`;
                    }
                    listHops.appendChild(li);
                });

                statusEl.textContent = '✅ REDIRECT TRACE COMPLETE!';
                statusEl.style.color = '#30d158';
            } else {
                statusEl.textContent = '❌ Redirection trace failed. Host offline or unreachable.';
                statusEl.style.color = '#ff453a';
                
                const li = document.createElement('li');
                li.style.cssText = 'padding: 8px; font-family: monospace; font-size: 12px; color: #ff453a;';
                li.textContent = `Error details: ${res ? res.error : 'No response from service worker.'}`;
                listHops.appendChild(li);
            }
        });
    });
}
