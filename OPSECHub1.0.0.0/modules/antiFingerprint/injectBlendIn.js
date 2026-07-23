// Runs in the page's MAIN world context for Blend-In (Standardized Spoofing) mode
console.log('[OPSECHub] antiFingerprintBlendIn.js INJECTED AND RUNNING!');
(function() {
    // Wrap the entire patching logic so it can be re-applied to child frames
    function installAntiFingerprintPatches(win) {
        // Prevent double-patching the same realm
        if (!win || win.__patched_afp) return;
        
        win.__patched_afp = true;
        
        // Use a shared WeakMap via Symbol on top window
        let proxyMap;
        try {
            let topWin;
            try { topWin = win.top || win; } catch(e) { topWin = win; }
            const sym = topWin.Symbol.for('__opsechub_proxymap_blendin');
            if (!topWin[sym]) {
                topWin[sym] = new topWin.WeakMap();
            }
            proxyMap = topWin[sym];
        } catch(e) {
            proxyMap = new win.WeakMap(); // fallback
        }
        
        let toStringProxy;
        try {
            const nativeToString = win.Function.prototype.toString;
            toStringProxy = new win.Proxy(nativeToString, {
                apply(target, thisArg, args) {
                    if (proxyMap.has(thisArg)) {
                        const name = thisArg.name || '';
                        if (name.startsWith('get ') || name.startsWith('set ')) {
                            return 'function () { [native code] }';
                        }
                        return 'function ' + name + '() { [native code] }';
                    }
                    if (thisArg === toStringProxy) {
                        return 'function toString() { [native code] }';
                    }
                    return win.Reflect.apply(target, thisArg, args);
                }
            });
            
            win.Object.defineProperty(win.Function.prototype, 'toString', {
                value: toStringProxy,
                configurable: true,
                enumerable: false,
                writable: true
            });
        } catch(e) {}

        function createProxyTrap(targetObj, methodName, handler) {
            try {
                const descriptor = win.Object.getOwnPropertyDescriptor(targetObj, methodName);
                const originalFn = descriptor ? descriptor.value : targetObj[methodName];
                if (!originalFn) return originalFn;

                const proxy = new win.Proxy(originalFn, handler);
                win.Object.defineProperty(proxy, 'name', { value: originalFn.name, configurable: true });
                win.Object.defineProperty(proxy, 'length', { value: originalFn.length, configurable: true });
                proxyMap.set(proxy, true);

                if (descriptor) {
                    win.Object.defineProperty(targetObj, methodName, {
                        value: proxy,
                        configurable: descriptor.configurable,
                        enumerable: descriptor.enumerable,
                        writable: descriptor.writable
                    });
                } else {
                    win.Object.defineProperty(targetObj, methodName, {
                        value: proxy,
                        configurable: true,
                        writable: true
                    });
                }
                return originalFn; 
            } catch(e) {
                return targetObj[methodName];
            }
        }

        function spoofGetter(targetObj, propName, spoofedValue) {
            try {
                const descriptor = win.Object.getOwnPropertyDescriptor(targetObj, propName);
                if (!descriptor || !descriptor.get) return;

                const getterProxy = new win.Proxy(descriptor.get, {
                    apply() { return typeof spoofedValue === 'function' ? spoofedValue() : spoofedValue; }
                });

                proxyMap.set(getterProxy, true);

                win.Object.defineProperty(targetObj, propName, {
                    get: getterProxy,
                    configurable: true,
                    enumerable: descriptor.enumerable
                });
            } catch(e) {}
        }

        // --- WebGL ---
        // We only spoof the renderer info to standard Intel graphics.
        // No noise is applied to readPixels.
        try {
            const webglTrap = {
                apply(target, thisArg, args) {
                    const param = args[0];
                    if (param === 37445) return 'Google Inc. (Intel)';
                    if (param === 37446) {
                        return 'Intel(R) UHD Graphics 620';
                    }
                    return win.Reflect.apply(target, thisArg, args);
                }
            };

            if (win.WebGLRenderingContext) {
                createProxyTrap(win.WebGLRenderingContext.prototype, 'getParameter', webglTrap);
            }
            if (win.WebGL2RenderingContext) {
                createProxyTrap(win.WebGL2RenderingContext.prototype, 'getParameter', webglTrap);
            }
        } catch(e) {}

        // --- Screen & HW ---
        // We spoof to common/generic standard values.
        try {
            if (win.Navigator) {
                spoofGetter(win.Navigator.prototype, 'hardwareConcurrency', 8);
                spoofGetter(win.Navigator.prototype, 'deviceMemory', 8);
            }
            if (win.Screen) {
                spoofGetter(win.Screen.prototype, 'width', 1920);
                spoofGetter(win.Screen.prototype, 'height', 1080);
                spoofGetter(win.Screen.prototype, 'colorDepth', 24);
            }
        } catch(e) {}

        // --- IFrame Getters (Realm Poisoning for Statically Defined Iframes) ---
        try {
            if (win.HTMLIFrameElement) {
                function hookIframeGetter(prop) {
                    try {
                        const desc = win.Object.getOwnPropertyDescriptor(win.HTMLIFrameElement.prototype, prop);
                        if (desc && desc.get) {
                            const proxyGet = new win.Proxy(desc.get, {
                                apply(target, thisArg, args) {
                                    const result = win.Reflect.apply(target, thisArg, args);
                                    if (result) {
                                        try {
                                            const targetWin = prop === 'contentWindow' ? result : result.defaultView;
                                            if (targetWin) installAntiFingerprintPatches(targetWin);
                                        } catch(e) {}
                                    }
                                    return result;
                                }
                            });
                            win.Object.defineProperty(proxyGet, 'name', { value: desc.get.name, configurable: true });
                            win.Object.defineProperty(proxyGet, 'length', { value: desc.get.length, configurable: true });
                            proxyMap.set(proxyGet, true);
                            win.Object.defineProperty(win.HTMLIFrameElement.prototype, prop, {
                                get: proxyGet,
                                set: desc.set,
                                enumerable: desc.enumerable,
                                configurable: desc.configurable
                            });
                        }
                    } catch(e) {}
                }
                hookIframeGetter('contentWindow');
                hookIframeGetter('contentDocument');
            }
        } catch(e) {}

        // --- DOM Methods (Realm Poisoning for Dynamically Appended Iframes) ---
        try {
            if (win.Node) {
                ['appendChild', 'insertBefore', 'replaceChild'].forEach(method => {
                    createProxyTrap(win.Node.prototype, method, {
                        apply(target, thisArg, args) {
                            const result = win.Reflect.apply(target, thisArg, args);
                            const node = args[0];
                            if (node && node.tagName === 'IFRAME') {
                                try { if (node.contentWindow) installAntiFingerprintPatches(node.contentWindow); } catch(e) {}
                                node.addEventListener('load', () => {
                                    try { if (node.contentWindow) installAntiFingerprintPatches(node.contentWindow); } catch(e) {}
                                });
                            }
                            return result;
                        }
                    });
                });
            }
        } catch(e) {}

        try {
            if (win.Document && win.Document.prototype.write) {
                createProxyTrap(win.Document.prototype, 'write', {
                    apply(target, thisArg, args) {
                        const result = win.Reflect.apply(target, thisArg, args);
                        try { if (thisArg.defaultView) installAntiFingerprintPatches(thisArg.defaultView); } catch(e) {}
                        return result;
                    }
                });
            }
        } catch(e) {}
    }

    installAntiFingerprintPatches(window);
})();
