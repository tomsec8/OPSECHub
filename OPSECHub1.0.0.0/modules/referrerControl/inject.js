// Runs in the page's MAIN world context
(function() {
    console.log('[OPSECHub] referrerControl.js INJECTED AND RUNNING!');

    function enforceMetaReferrer(win) {
        try {
            if (!win.document) return;
            const doc = win.document;
            
            function applyMeta() {
                try {
                    let meta = doc.querySelector('meta[name="referrer"]');
                    if (meta) {
                        if (meta.content !== 'no-referrer') meta.content = 'no-referrer';
                    } else if (doc.head || doc.documentElement) {
                        meta = doc.createElement('meta');
                        meta.name = 'referrer';
                        meta.content = 'no-referrer';
                        (doc.head || doc.documentElement).appendChild(meta);
                    }
                } catch(e) {}
            }

            applyMeta();

            // Observe for changes to keep it enforced
            const observer = new win.MutationObserver((mutations) => {
                let needsApply = false;
                for (const m of mutations) {
                    if (m.addedNodes) {
                        for (const n of m.addedNodes) {
                            if (n.tagName === 'META' && n.name === 'referrer') needsApply = true;
                        }
                    }
                    if (m.type === 'attributes' && m.target.tagName === 'META' && m.target.name === 'referrer') {
                        if (m.target.content !== 'no-referrer') needsApply = true;
                    }
                }
                if (needsApply) applyMeta();
            });

            if (doc.documentElement) {
                observer.observe(doc.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['content'] });
            } else {
                // If documentElement doesn't exist yet, wait for it
                const rootObserver = new win.MutationObserver(() => {
                    if (doc.documentElement) {
                        rootObserver.disconnect();
                        observer.observe(doc.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['content'] });
                        applyMeta();
                    }
                });
                rootObserver.observe(doc, { childList: true });
            }
        } catch(e) {}
    }

    // Applies document.referrer overrides — safe to call multiple times (idempotent)
    function applyReferrerOverride(win) {
        try {
            // Override on the document INSTANCE directly (more resilient to bfcache)
            try {
                win.Object.defineProperty(win.document, 'referrer', {
                    get: function() { return ''; },
                    configurable: true
                });
            } catch(e) {}

            // Override on Document prototype (catches all documents including iframes)
            win.Object.defineProperty(win.Document.prototype, 'referrer', {
                get: function() {
                    return '';
                },
                configurable: true,
                enumerable: true
            });
        } catch(e) {}
    }

    function installReferrerPatches(win) {
        if (!win || win.__opsechub_referrer_patched) return;
        try {
            win.__opsechub_referrer_patched = true;
            applyReferrerOverride(win);
            enforceMetaReferrer(win);
        } catch(e) {}
    }

    // Apply to current main window
    installReferrerPatches(window);

    // Re-apply patches when page is restored from bfcache (back/forward navigation)
    window.addEventListener('pageshow', function(event) {
        if (event.persisted) {
            applyReferrerOverride(window);
            enforceMetaReferrer(window);
        }
    }, true);

    // Re-apply patches when a prerendered page is activated (Chrome Speculation Rules / Prerender)
    if (document.prerendering) {
        document.addEventListener('prerenderingchange', function() {
            applyReferrerOverride(window);
            enforceMetaReferrer(window);
        });
    }

    try {
        const originalContentWindow = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow').get;
        Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
            get: function() {
                const win = originalContentWindow.call(this);
                try {
                    if (win && !win.__opsechub_referrer_patched) {
                        installReferrerPatches(win);
                    }
                } catch(e) {}
                return win;
            },
            configurable: true,
            enumerable: true
        });
    } catch(e) {}

    try {
        const originalContentDoc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentDocument').get;
        Object.defineProperty(HTMLIFrameElement.prototype, 'contentDocument', {
            get: function() {
                const doc = originalContentDoc.call(this);
                try {
                    if (doc && doc.defaultView && !doc.defaultView.__opsechub_referrer_patched) {
                        installReferrerPatches(doc.defaultView);
                    }
                } catch(e) {}
                return doc;
            },
            configurable: true,
            enumerable: true
        });
    } catch(e) {}
})();
