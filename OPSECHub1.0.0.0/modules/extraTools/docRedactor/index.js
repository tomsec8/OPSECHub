// 🔒 Tool: Dedicated Document Redaction & Sensitive Data Blackout (DLP Redactor)
function initDocRedactorTool() {
    const dropzone = document.getElementById('dropzone-doc-redact');
    const input = document.getElementById('input-doc-redact');
    const resultBox = document.getElementById('result-doc-redact');
    const statusEl = document.getElementById('status-doc-redact');
    const detailsEl = document.getElementById('details-doc-redact');
    const tableEl = document.getElementById('table-doc-redact');
    const redactBtn = document.getElementById('btn-execute-doc-redact');

    if (!dropzone || !input) return;

    function escapeHtml(str) {
        if (!str) return '';
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    let loadedFile = null;
    let originalBuffer = null;
    let sanitizedBlob = null;
    let redactedFileName = 'redacted_document';

    // Comprehensive Enterprise DLP Detection Patterns
    const sensitivePatterns = [
        { name: 'Passwords & Credentials', regex: /\b(password|passwd|pwd|pass|secret)\s*[:=]\s*[^\s"'>,;]+/gi },
        { name: 'AWS Access Key ID', regex: /\bAKIA[0-9A-Z]{16}\b/g },
        { name: 'GitHub Access Token', regex: /\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b/g },
        { name: 'OpenAI / Stripe API Key', regex: /\b(sk_live_[0-9a-zA-Z]{24,}|sk-[a-zA-Z0-9]{32,})\b/g },
        { name: 'Slack Bot / User Token', regex: /\bxox[baprs]-[0-9a-zA-Z]{10,48}\b/g },
        { name: 'JWT Web Token', regex: /\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*\b/g },
        { name: 'RSA / PGP Private Key', regex: /-----BEGIN\s+(RSA|PGP|EC|OPENSSH)\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+\1\s+PRIVATE\s+KEY-----/gi },
        { name: 'Credit Card Number', regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g },
        { name: 'Social Security Number (SSN)', regex: /\b\d{3}-\d{2}-\d{4}\b/g },
        { name: 'Email Address', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g },
        { name: 'IPv4 Address (Routable)', regex: /\b(?!0\.0\.0\.0)(?!127\.)(?!10\.)(?!192\.168\.)(?!172\.(?:1[6-9]|2[0-9]|3[01])\.)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g },
        { name: 'MD5 Cryptographic Hash', regex: /\b[a-fA-F0-9]{32}\b/g },
        { name: 'SHA-1 Cryptographic Hash', regex: /\b[a-fA-F0-9]{40}\b/g },
        { name: 'SHA-256 Cryptographic Hash', regex: /\b[a-fA-F0-9]{64}\b/g }
    ];

    const replaceSensitiveData = (str) => {
        let text = str;
        let matchCount = 0;

        sensitivePatterns.forEach(item => {
            text = text.replace(item.regex, (m) => {
                matchCount++;
                return '[REDACTED_SENSITIVE_DATA]';
            });
        });

        return { text, matchCount };
    };

    const handleFile = (file) => {
        if (!file) return;
        loadedFile = file;
        redactedFileName = 'redacted_' + file.name;
        resultBox.style.display = 'block';
        statusEl.textContent = '⏳ Scanning document with Enterprise DLP engine...';
        statusEl.style.color = '#00e5ff';
        detailsEl.textContent = `Analyzing ${file.name} (${Math.round(file.size / 1024)} KB)...`;
        tableEl.innerHTML = '';
        redactBtn.style.display = 'none';

        const reader = new FileReader();
        reader.onload = async (e) => {
            originalBuffer = e.target.result;
            let detectedItems = [];

            if (file.name.endsWith('.docx') || file.name.endsWith('.xlsx') || file.name.endsWith('.pptx')) {
                try {
                    const bufferCopy = originalBuffer.slice(0);
                    const zip = await JSZip.loadAsync(bufferCopy);
                    for (const [path, entry] of Object.entries(zip.files)) {
                        if (path.endsWith('.xml') || path.endsWith('.rels') || path.endsWith('.txt')) {
                            const content = await entry.async('string');
                            sensitivePatterns.forEach(p => {
                                const matches = content.match(p.regex);
                                if (matches) {
                                    matches.forEach(m => detectedItems.push({ type: p.name, value: m, path }));
                                }
                            });
                        }
                    }
                } catch (err) {
                    console.error('Office document redact scan error:', err);
                }
            } else if (file.name.endsWith('.pdf')) {
                try {
                    const pdfDoc = await PDFLib.PDFDocument.load(originalBuffer, { ignoreEncryption: true });
                    const author = pdfDoc.getAuthor() || '';
                    const title = pdfDoc.getTitle() || '';
                    const subject = pdfDoc.getSubject() || '';
                    const producer = pdfDoc.getProducer() || '';
                    const keywords = pdfDoc.getKeywords() || '';

                    const metaStr = `${author} ${title} ${subject} ${producer} ${keywords}`;
                    sensitivePatterns.forEach(p => {
                        const matches = metaStr.match(p.regex);
                        if (matches) {
                            matches.forEach(m => detectedItems.push({ type: p.name, value: m, path: 'PDF Metadata Header' }));
                        }
                    });

                    // Also scan form fields and annotations
                    try {
                        const form = pdfDoc.getForm();
                        const fields = form.getFields();
                        fields.forEach(field => {
                            const val = field.getText ? field.getText() : '';
                            if (val) {
                                sensitivePatterns.forEach(p => {
                                    const matches = val.match(p.regex);
                                    if (matches) {
                                        matches.forEach(m => detectedItems.push({ type: p.name, value: m, path: `PDF Form Field (${field.getName()})` }));
                                    }
                                });
                            }
                        });
                    } catch(fe) {}

                    // Scan raw PDF binary for secrets in text streams
                    const rawText = new TextDecoder('latin1').decode(new Uint8Array(originalBuffer));
                    sensitivePatterns.forEach(p => {
                        const matches = rawText.match(p.regex);
                        if (matches) {
                            matches.forEach(m => {
                                // Avoid duplicates from metadata scan
                                if (!detectedItems.some(d => d.value === m)) {
                                    detectedItems.push({ type: p.name, value: m, path: 'PDF Content Stream' });
                                }
                            });
                        }
                    });

                } catch (err) {
                    console.error('PDF redact scan error:', err);
                }
            } else {
                const textContent = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(originalBuffer));
                sensitivePatterns.forEach(p => {
                    const matches = textContent.match(p.regex);
                    if (matches) {
                        matches.forEach(m => detectedItems.push({ type: p.name, value: m, path: 'Flat File Text' }));
                    }
                });
            }

            renderDlpMatches(detectedItems);
        };

        reader.readAsArrayBuffer(file);
    };

    const renderDlpMatches = (matches) => {
        tableEl.innerHTML = '';
        if (matches.length === 0) {
            statusEl.textContent = '✅ DLP Scan Passed: Zero Passwords, Tokens, or Secrets Found!';
            statusEl.style.color = '#30d158';
            detailsEl.textContent = `No passwords, API tokens, cryptographic keys, credit cards, or hashes detected in ${loadedFile.name}.`;
            return;
        }

        statusEl.textContent = `⚠️ DLP Alert: ${matches.length} Sensitive Secrets / Leaks Detected!`;
        statusEl.style.color = '#ff453a';
        detailsEl.textContent = `Review the detected secrets below. Click "Redact & Download" to replace all secrets with [REDACTED_SENSITIVE_DATA].`;
        redactBtn.style.display = 'block';

        const table = document.createElement('table');
        table.style.width = '100%';
        table.style.borderCollapse = 'collapse';
        table.style.marginTop = '10px';

        const headerRow = table.insertRow();
        headerRow.innerHTML = `<th style="padding: 6px; color: #60a5fa; text-align: left;">Category</th><th style="padding: 6px; color: #60a5fa; text-align: left;">Detected Secret / String</th>`;

        matches.forEach(m => {
            const row = table.insertRow();
            row.style.background = 'rgba(255, 69, 58, 0.1)';
            row.innerHTML = `
                <td style="padding: 6px; color: #ff453a; font-weight: bold; border-bottom: 1px solid rgba(255,255,255,0.05);">${escapeHtml(m.type)}</td>
                <td style="padding: 6px; color: #fff; font-family: monospace; word-break: break-all; border-bottom: 1px solid rgba(255,255,255,0.05);">${escapeHtml(m.value)}</td>
            `;
        });

        tableEl.appendChild(table);
    };

    const executeRedaction = async () => {
        if (!loadedFile || !originalBuffer) return;
        statusEl.textContent = '⏳ Blacking out sensitive strings...';
        statusEl.style.color = '#00e5ff';

        try {
            if (loadedFile.name.endsWith('.docx') || loadedFile.name.endsWith('.xlsx') || loadedFile.name.endsWith('.pptx')) {
                const bufferCopy = originalBuffer.slice(0);
                const zip = await JSZip.loadAsync(bufferCopy);
                for (const [path, entry] of Object.entries(zip.files)) {
                    if (path.endsWith('.xml') || path.endsWith('.rels') || path.endsWith('.txt')) {
                        let content = await entry.async('string');
                        const { text, matchCount } = replaceSensitiveData(content);
                        if (matchCount > 0) {
                            zip.file(path, text);
                        }
                    }
                }
                sanitizedBlob = await zip.generateAsync({ type: 'blob', mimeType: loadedFile.type });
            } else if (loadedFile.name.endsWith('.pdf')) {
                const pdfDoc = await PDFLib.PDFDocument.load(originalBuffer, { ignoreEncryption: true });
                let author = pdfDoc.getAuthor() || '';
                let title = pdfDoc.getTitle() || '';
                let subject = pdfDoc.getSubject() || '';
                let producer = pdfDoc.getProducer() || '';
                let keywords = pdfDoc.getKeywords() || '';

                pdfDoc.setAuthor(replaceSensitiveData(author).text);
                pdfDoc.setTitle(replaceSensitiveData(title).text);
                pdfDoc.setSubject(replaceSensitiveData(subject).text);
                pdfDoc.setProducer(replaceSensitiveData(producer).text);
                pdfDoc.setKeywords([replaceSensitiveData(keywords).text]);

                try {
                    const form = pdfDoc.getForm();
                    const fields = form.getFields();
                    fields.forEach(field => {
                        if (field.getText && field.setText) {
                            const val = field.getText();
                            if (val) {
                                field.setText(replaceSensitiveData(val).text);
                            }
                        }
                    });
                } catch(fe) {}

                const pdfBytes = await pdfDoc.save();
                sanitizedBlob = new Blob([pdfBytes], { type: 'application/pdf' });
            } else {
                let textContent = new TextDecoder('utf-8', { fatal: false }).decode(new Uint8Array(originalBuffer));
                const { text } = replaceSensitiveData(textContent);
                sanitizedBlob = new Blob([text], { type: 'text/plain' });
            }

            const url = URL.createObjectURL(sanitizedBlob);
            const a = document.createElement('a');
            a.href = url;
            a.download = redactedFileName;
            a.click();
            URL.revokeObjectURL(url);

            statusEl.textContent = '🔒 Document Secrets Redacted & Downloaded Successfully!';
            statusEl.style.color = '#30d158';
        } catch (err) {
            console.error('Redaction failed:', err);
            statusEl.textContent = '❌ Redaction Failed: ' + err.message;
            statusEl.style.color = '#ff453a';
        }
    };

    dropzone.addEventListener('click', () => input.click());
    input.addEventListener('change', (e) => handleFile(e.target.files[0]));
    dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.style.borderColor = '#ff453a'; });
    dropzone.addEventListener('dragleave', () => { dropzone.style.borderColor = 'rgba(255, 69, 58, 0.4)'; });
    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.style.borderColor = 'rgba(255, 69, 58, 0.4)';
        if (e.dataTransfer.files && e.dataTransfer.files[0]) handleFile(e.dataTransfer.files[0]);
    });

    if (redactBtn) {
        redactBtn.addEventListener('click', executeRedaction);
    }
}
