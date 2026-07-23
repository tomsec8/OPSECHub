// Runs in the page's MAIN world context
(function() {
    console.log('[OPSECHub] clickjackXss.js INJECTED AND RUNNING!');

    // ═══════════════════════════════════════════════════════════════════
    // 1. CLICKJACKING PROTECTION (WARNING ONLY)
    // ═══════════════════════════════════════════════════════════════════
    try {
        if (window.self !== window.top) {
            let isTrustedEmbed = false;
            try {
                // Check if embedded by a same-origin parent
                const topOrigin = window.top.location.origin;
                const myOrigin = window.location.origin;
                if (topOrigin === myOrigin) {
                    isTrustedEmbed = true;
                }
            } catch (e) {
                isTrustedEmbed = false;
            }

            if (!isTrustedEmbed) {
                const checkAndDrawShield = () => {
                    const width = window.innerWidth || document.documentElement.clientWidth;
                    const height = window.innerHeight || document.documentElement.clientHeight;
                    
                    // Relaxed threshold to support split-screen development testing, while keeping ads/recaptchas unblocked
                    if (width > 250 && height > 200) {
                        if (document.getElementById('opsechub-clickjack-shield')) return;
                        
                        // Defer overlay injection until document.body is initialized to prevent body styles from occluding the shield
                        if (!document.body) return;
                        
                        // Styled console.log will not flag the extension with warning/error badges in chrome://extensions
                        console.log('%c[OPSECHub] Clickjacking attempt shielded. Enforcing frame breakout blocker.', 'color: #ff5252; font-weight: bold;');
                        
                        const shield = document.createElement('div');
                        shield.id = 'opsechub-clickjack-shield';
                        shield.style.position = 'fixed';
                        shield.style.top = '0';
                        shield.style.left = '0';
                        shield.style.width = '100vw';
                        shield.style.height = '100vh';
                        shield.style.background = '#121824'; // Solid opaque premium dark theme background (completely blocks the framed site underneath)
                        shield.style.color = '#ff5252';
                        shield.style.zIndex = '2147483647';
                        shield.style.display = 'flex';
                        shield.style.flexDirection = 'column';
                        shield.style.justifyContent = 'center';
                        shield.style.alignItems = 'center';
                        shield.style.fontFamily = 'system-ui, -apple-system, sans-serif';
                        shield.style.padding = '20px';
                        shield.style.boxSizing = 'border-box';
                        shield.style.textAlign = 'center';

                        // Premium vector SVG shield icon avoids character set encoding issues (e.g. broken emoji characters)
                        shield.innerHTML = `
                            <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#ff5252" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-bottom: 15px;">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                            </svg>
                            <h2 style="margin: 0 0 10px; font-size: 20px; font-weight: 700; color: #ff5252;">Clickjacking Attempt Shielded</h2>
                            <p style="margin: 0 0 25px; font-size: 13.5px; color: #b0bec5; max-width: 420px; line-height: 1.5;">
                                OPSECHub detected that this page is embedded inside an untrusted cross-origin website. Interaction has been disabled to prevent click hijacking.
                            </p>
                            <button id="btn-clickjack-breakout" style="padding: 10px 22px; background: #ff5252; color: #fff; border: none; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer; transition: 0.2s; box-shadow: 0 4px 12px rgba(255, 82, 82, 0.3);">
                                Break Out & Open Safely
                            </button>
                        `;

                        document.body.appendChild(shield);

                        const breakoutBtn = shield.querySelector('#btn-clickjack-breakout');
                        if (breakoutBtn) {
                            breakoutBtn.addEventListener('click', () => {
                                try {
                                    window.top.location = window.location.href;
                                } catch (e) {
                                    window.open(window.location.href, '_blank');
                                }
                            });
                        }
                    } else {
                        // If it becomes smaller than threshold, tear down the shield
                        const existing = document.getElementById('opsechub-clickjack-shield');
                        if (existing) existing.remove();
                    }
                };

                // Run immediately to capture initial size and prevent loading delays
                checkAndDrawShield();

                // Attach to lifecycle points to handle dynamic page/frame layout calculations
                document.addEventListener('DOMContentLoaded', checkAndDrawShield);
                window.addEventListener('load', checkAndDrawShield);
                window.addEventListener('resize', checkAndDrawShield);
            }
        }
    } catch(e) {
        console.error('[OPSECHub:Clickjacking] Shield initialization error:', e);
    }

    // ═══════════════════════════════════════════════════════════════════
    // 2. DOM-BASED XSS PROTECTION (HTML SANITIZER)
    // ═══════════════════════════════════════════════════════════════════
    function sanitiseHTML(htmlString) {
        if (typeof htmlString !== 'string' || !htmlString) return htmlString;
        try {
            const parser = new DOMParser();
            const doc = parser.parseFromString(htmlString, 'text/html');
            
            // Remove script elements safely
            const scripts = doc.querySelectorAll('script');
            scripts.forEach(s => s.remove());

            // Strip inline on* event handlers and dangerous javascript: URIs
            const allElements = doc.querySelectorAll('*');
            allElements.forEach(el => {
                const attrs = Array.from(el.attributes || []);
                attrs.forEach(attr => {
                    const name = attr.name.toLowerCase();
                    const val = (attr.value || '').toLowerCase().trim();
                    if (name.startsWith('on') || val.startsWith('javascript:')) {
                        el.removeAttribute(attr.name);
                    }
                });
            });

            return doc.body.innerHTML;
        } catch(e) {
            return htmlString;
        }
    }

    // Intercept Element.prototype.innerHTML setter
    try {
        const originalInnerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
        if (originalInnerHTMLDesc && originalInnerHTMLDesc.set) {
            const originalSet = originalInnerHTMLDesc.set;
            Object.defineProperty(Element.prototype, 'innerHTML', {
                set(value) {
                    if (typeof value === 'string' && value.includes('speculationrules')) {
                        return originalSet.call(this, value);
                    }
                    const sanitised = sanitiseHTML(value);
                    return originalSet.call(this, sanitised);
                },
                get: originalInnerHTMLDesc.get,
                enumerable: originalInnerHTMLDesc.enumerable,
                configurable: originalInnerHTMLDesc.configurable
            });
        }
    } catch(e) {
        console.error('[OPSECHub:XSS] innerHTML intercept error:', e);
    }

    // Intercept Element.prototype.outerHTML setter
    try {
        const originalOuterHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
        if (originalOuterHTMLDesc && originalOuterHTMLDesc.set) {
            const originalSet = originalOuterHTMLDesc.set;
            Object.defineProperty(Element.prototype, 'outerHTML', {
                set(value) {
                    const sanitised = sanitiseHTML(value);
                    return originalSet.call(this, sanitised);
                },
                get: originalOuterHTMLDesc.get,
                enumerable: originalOuterHTMLDesc.enumerable,
                configurable: originalOuterHTMLDesc.configurable
            });
        }
    } catch(e) {
        console.error('[OPSECHub:XSS] outerHTML intercept error:', e);
    }

    // Intercept document.write and document.writeln
    try {
        if (Document && Document.prototype.write) {
            const originalWrite = Document.prototype.write;
            Document.prototype.write = function(...args) {
                const sanitisedArgs = args.map(arg => typeof arg === 'string' ? sanitiseHTML(arg) : arg);
                return originalWrite.apply(this, sanitisedArgs);
            };
        }
        if (Document && Document.prototype.writeln) {
            const originalWriteln = Document.prototype.writeln;
            Document.prototype.writeln = function(...args) {
                const sanitisedArgs = args.map(arg => typeof arg === 'string' ? sanitiseHTML(arg) : arg);
                return originalWriteln.apply(this, sanitisedArgs);
            };
        }
    } catch(e) {
        console.error('[OPSECHub:XSS] document.write intercept error:', e);
    }

})();
