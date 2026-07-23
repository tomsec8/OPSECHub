// 🕵️ Tool: CSP & Security Headers Analyzer (headerAnalyzer)
function initHeaderAnalyzerTool() {
    const input = document.getElementById('inp-header-domain');
    const checkBtn = document.getElementById('btn-check-headers');
    const resultBox = document.getElementById('result-header-analyzer');
    const scoreBadge = document.getElementById('badge-header-score');
    const summaryText = document.getElementById('text-header-summary');
    const tableContainer = document.getElementById('container-header-table');

    if (!input || !checkBtn) return;

    function escapeHtml(str) {
        if (!str) return '';
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    const checkHeaders = async () => {
        let domain = input.value.trim();
        if (!domain) {
            // Try active tab domain if empty
            if (typeof chrome !== 'undefined' && chrome.tabs) {
                try {
                    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
                    if (tabs && tabs[0] && tabs[0].url && tabs[0].url.startsWith('http')) {
                        domain = new URL(tabs[0].url).hostname;
                        input.value = domain;
                    }
                } catch (_) {}
            }
        }

        if (!domain) {
            alert('Please enter a target domain (e.g. google.com)');
            return;
        }

        // Clean domain string
        domain = domain.replace(/^https?:\/\//i, '').split('/')[0].split('?')[0].trim();
        const targetUrl = 'https://' + domain;

        resultBox.style.display = 'block';
        scoreBadge.textContent = '⏳';
        scoreBadge.style.background = 'rgba(0, 229, 255, 0.2)';
        scoreBadge.style.color = '#00e5ff';
        summaryText.textContent = `Fetching HTTP response headers for ${domain}...`;
        tableContainer.innerHTML = '';

        try {
            let res = await new Promise((resolve) => {
                try {
                    if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.id) {
                        return resolve({ success: false, error: 'Context invalidated. Please refresh the options page.' });
                    }
                    chrome.runtime.sendMessage({ action: 'fetchSecurityHeaders', targetUrl }, (response) => {
                        try {
                            if (chrome.runtime && chrome.runtime.lastError) {
                                resolve({ success: false, error: chrome.runtime.lastError.message });
                            } else {
                                resolve(response);
                            }
                        } catch (err) {
                            resolve({ success: false, error: err.message });
                        }
                    });
                } catch (e) {
                    resolve({ success: false, error: e.message });
                }
            });

            // Fallback: If background messaging failed, attempt direct fetch from options page
            if (!res || !res.success) {
                try {
                    const directRes = await fetch(targetUrl, { method: 'GET', redirect: 'follow', cache: 'no-store' });
                    const headersObj = {};
                    directRes.headers.forEach((val, key) => {
                        headersObj[key.toLowerCase()] = val;
                    });
                    res = { success: true, headers: headersObj };
                } catch (fetchErr) {
                    throw new Error(res?.error || fetchErr.message || 'Network request failed');
                }
            }

            const getHeader = (key) => (res.headers ? res.headers[key.toLowerCase()] : null) || null;

            // Header definitions & evaluation
            const securityHeaderChecks = [
                {
                    name: 'Content-Security-Policy',
                    key: 'content-security-policy',
                    importance: 'Critical',
                    desc: 'Protects against XSS, data injection, and unauthorized script execution.',
                    evaluate: (val) => {
                        if (!val) return { pass: false, grade: 'FAIL', text: 'Missing! Vulnerable to Cross-Site Scripting (XSS) and code injection.' };
                        if (val.includes("unsafe-inline") || val.includes("unsafe-eval") || val.includes("*")) {
                            return { pass: true, warn: true, grade: 'WARN', text: 'Present, but contains weak directives (unsafe-inline / unsafe-eval / wildcard).' };
                        }
                        return { pass: true, grade: 'PASS', text: 'Strong CSP rules enforced.' };
                    }
                },
                {
                    name: 'Strict-Transport-Security (HSTS)',
                    key: 'strict-transport-security',
                    importance: 'High',
                    desc: 'Forces browsers to connect exclusively over encrypted HTTPS.',
                    evaluate: (val) => {
                        if (!val) return { pass: false, grade: 'FAIL', text: 'Missing! Susceptible to SSL-Stripping and Man-in-the-Middle (MiTM) attacks.' };
                        if (!val.includes('includeSubDomains') || !val.includes('max-age')) {
                            return { pass: true, warn: true, grade: 'WARN', text: 'Present, but missing includeSubDomains or low max-age.' };
                        }
                        return { pass: true, grade: 'PASS', text: 'Strict HTTPS enforced across subdomains.' };
                    }
                },
                {
                    name: 'X-Frame-Options',
                    key: 'x-frame-options',
                    importance: 'High',
                    desc: 'Prevents Clickjacking attacks by controlling iframe embedding.',
                    evaluate: (val) => {
                        if (!val) return { pass: false, grade: 'FAIL', text: 'Missing! Site can be embedded inside attacker iframes for Clickjacking.' };
                        const v = val.toUpperCase();
                        if (v === 'DENY' || v === 'SAMEORIGIN') return { pass: true, grade: 'PASS', text: `Protected (${v}).` };
                        return { pass: true, warn: true, grade: 'WARN', text: `Weak frame configuration (${val}).` };
                    }
                },
                {
                    name: 'X-Content-Type-Options',
                    key: 'x-content-type-options',
                    importance: 'Medium',
                    desc: 'Prevents MIME-sniffing exploits where non-executable files are executed as scripts.',
                    evaluate: (val) => {
                        if (!val) return { pass: false, grade: 'FAIL', text: 'Missing! Vulnerable to MIME-type sniffing attacks.' };
                        if (val.toLowerCase().includes('nosniff')) return { pass: true, grade: 'PASS', text: 'MIME-sniffing blocked (nosniff).' };
                        return { pass: true, warn: true, grade: 'WARN', text: `Unexpected value (${val}).` };
                    }
                },
                {
                    name: 'Referrer-Policy',
                    key: 'referrer-policy',
                    importance: 'Medium',
                    desc: 'Controls how much sensitive URL referrer data is sent to external sites.',
                    evaluate: (val) => {
                        if (!val) return { pass: false, grade: 'FAIL', text: 'Missing! Full URL paths may leak in Referer headers to external links.' };
                        if (val.includes('no-referrer') || val.includes('strict-origin') || val.includes('same-origin')) {
                            return { pass: true, grade: 'PASS', text: `Privacy protected (${val}).` };
                        }
                        return { pass: true, warn: true, grade: 'WARN', text: `Weak referrer policy (${val}).` };
                    }
                },
                {
                    name: 'Permissions-Policy',
                    key: 'permissions-policy',
                    importance: 'Medium',
                    desc: 'Restricts access to sensitive browser features (Camera, Mic, Geolocation, Payment).',
                    evaluate: (val) => {
                        if (!val) return { pass: false, grade: 'FAIL', text: 'Missing! Hardware APIs (Camera, Mic, GPS) are unrestricted.' };
                        return { pass: true, grade: 'PASS', text: 'Browser feature permissions restricted.' };
                    }
                },
                {
                    name: 'Server Header Leak',
                    key: 'server',
                    importance: 'Low',
                    desc: 'Reveals backend server software & version to attackers.',
                    evaluate: (val) => {
                        if (!val) return { pass: true, grade: 'PASS', text: 'Server technology hidden (Good OPSEC).' };
                        return { pass: false, warn: true, grade: 'LEAK', text: `Exposes server software: ${val}` };
                    }
                }
            ];

            let score = 100;
            const results = [];

            securityHeaderChecks.forEach(check => {
                const headerVal = getHeader(check.key);
                const evalRes = check.evaluate(headerVal);

                // Balanced industry-standard penalty weighting
                if (evalRes.grade === 'FAIL') {
                    if (check.importance === 'Critical') score -= 25;
                    else if (check.importance === 'High') score -= 20;
                    else if (check.importance === 'Medium') score -= 15;
                    else score -= 10;
                } else if (evalRes.grade === 'WARN' || evalRes.grade === 'LEAK') {
                    score -= 5;
                }

                results.push({
                    name: check.name,
                    value: headerVal || 'Not Set',
                    grade: evalRes.grade,
                    desc: check.desc,
                    feedback: evalRes.text
                });
            });

            if (score < 0) score = 0;

            // Render score badge & summary
            let gradeLetter = 'A+';
            let badgeColor = '#30d158';

            if (score >= 90) { gradeLetter = 'A+'; badgeColor = '#30d158'; }
            else if (score >= 75) { gradeLetter = 'B'; badgeColor = '#00e5ff'; }
            else if (score >= 50) { gradeLetter = 'C'; badgeColor = '#ff9f0a'; }
            else { gradeLetter = 'F'; badgeColor = '#ff453a'; }

            scoreBadge.textContent = gradeLetter;
            scoreBadge.style.background = badgeColor;
            scoreBadge.style.color = '#000';

            summaryText.innerHTML = `Security Header Score: <strong style="color:${badgeColor}">${score} / 100</strong> for <span style="color:#fff">${escapeHtml(domain)}</span>`;

            // Render Results Table
            const table = document.createElement('table');
            table.style.width = '100%';
            table.style.borderCollapse = 'collapse';
            table.style.marginTop = '10px';

            const headerRow = table.insertRow();
            headerRow.innerHTML = `
                <th style="padding: 8px; color: #60a5fa; text-align: left; font-size: 12px; border-bottom: 1px solid rgba(255,255,255,0.1);">Header</th>
                <th style="padding: 8px; color: #60a5fa; text-align: left; font-size: 12px; border-bottom: 1px solid rgba(255,255,255,0.1);">Status</th>
                <th style="padding: 8px; color: #60a5fa; text-align: left; font-size: 12px; border-bottom: 1px solid rgba(255,255,255,0.1);">Details & Vulnerability Impact</th>
            `;

            results.forEach(r => {
                const row = table.insertRow();
                let statusBadge = '';
                if (r.grade === 'PASS') statusBadge = '<span style="background: rgba(48,209,88,0.2); color: #30d158; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">PASS</span>';
                else if (r.grade === 'WARN') statusBadge = '<span style="background: rgba(255,159,10,0.2); color: #ff9f0a; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">WARNING</span>';
                else if (r.grade === 'LEAK') statusBadge = '<span style="background: rgba(255,159,10,0.2); color: #ff9f0a; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">INFO LEAK</span>';
                else statusBadge = '<span style="background: rgba(255,69,58,0.2); color: #ff453a; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">MISSING</span>';

                row.innerHTML = `
                    <td style="padding: 10px 8px; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 12.5px; font-weight: bold; color: #fff;">
                        ${escapeHtml(r.name)}
                        <div style="font-size: 10.5px; color: #78909c; font-weight: normal; margin-top: 2px;">${escapeHtml(r.desc)}</div>
                    </td>
                    <td style="padding: 10px 8px; border-bottom: 1px solid rgba(255,255,255,0.05);">${statusBadge}</td>
                    <td style="padding: 10px 8px; border-bottom: 1px solid rgba(255,255,255,0.05); font-size: 12px; color: #b0bec5; line-height: 1.4;">
                        ${escapeHtml(r.feedback)}
                        <div style="font-size: 11px; font-family: monospace; color: #64b5f6; margin-top: 3px;">Value: ${escapeHtml(r.value)}</div>
                    </td>
                `;
            });

            tableContainer.appendChild(table);

        } catch (err) {
            console.error('Header check failed:', err);
            scoreBadge.textContent = 'ERR';
            scoreBadge.style.background = '#ff453a';
            scoreBadge.style.color = '#fff';
            summaryText.textContent = `Failed to fetch response headers for ${domain}. (${err.message})`;
        }
    };

    checkBtn.addEventListener('click', checkHeaders);
    input.addEventListener('keypress', (e) => { if (e.key === 'Enter') checkHeaders(); });
}
