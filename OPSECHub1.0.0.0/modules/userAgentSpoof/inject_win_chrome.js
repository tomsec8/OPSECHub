// Runs in the page's MAIN world context
(function() {
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
    const platform = 'Win32';

    function installUAPatches(win) {
        if (!win || win.__patched_ua) return;
        try {
            win.__patched_ua = true;
            
            // Use a shared WeakMap via Symbol on top window
            let topWin;
            try { topWin = win.top || win; } catch(e) { topWin = win; }
            const sym = topWin.Symbol.for('__opsechub_proxymap');
            if (!topWin[sym]) {
                topWin[sym] = new topWin.WeakMap();
            }
            const proxyMap = topWin[sym];
            
            const nativeToString = win.Function.prototype.toString;

            const toStringProxy = new win.Proxy(nativeToString, {
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

            function createProxyTrap(targetObj, methodName, handler) {
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
            }

            function spoofGetter(targetObj, propName, spoofedValue) {
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
            }

            if (win.Navigator) {
                spoofGetter(win.Navigator.prototype, 'userAgent', ua);
                spoofGetter(win.Navigator.prototype, 'appVersion', ua.replace(/^Mozilla\//, ''));
                spoofGetter(win.Navigator.prototype, 'platform', platform);
                
                if (win.Navigator.prototype.hasOwnProperty('userAgentData')) {
                    spoofGetter(win.Navigator.prototype, 'userAgentData', () => ({
                        brands: [{brand: 'Not_A Brand', version: '8'}, {brand: 'Chromium', version: '120'}, {brand: 'Google Chrome', version: '120'}],
                        mobile: false,
                        platform: 'Windows',
                        getHighEntropyValues: async (hints) => {
                            let values = {};
                            if (hints.includes('platform')) values.platform = 'Windows';
                            if (hints.includes('model')) values.model = '';
                            if (hints.includes('uaFullVersion')) values.uaFullVersion = '120.0.0.0';
                            return values;
                        }
                    }));
                }
            }

            // --- IFrame Getters (Realm Poisoning for Statically Defined Iframes) ---
            if (win.HTMLIFrameElement) {
                function hookIframeGetter(prop) {
                    const desc = win.Object.getOwnPropertyDescriptor(win.HTMLIFrameElement.prototype, prop);
                    if (desc && desc.get) {
                        const proxyGet = new win.Proxy(desc.get, {
                            apply(target, thisArg, args) {
                                const result = win.Reflect.apply(target, thisArg, args);
                                if (result) {
                                    try {
                                        const targetWin = prop === 'contentWindow' ? result : result.defaultView;
                                        if (targetWin) installUAPatches(targetWin);
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
                }
                hookIframeGetter('contentWindow');
                hookIframeGetter('contentDocument');
            }

            // --- DOM Methods (Realm Poisoning for Dynamically Appended Iframes) ---
            if (win.Node) {
                ['appendChild', 'insertBefore', 'replaceChild'].forEach(method => {
                    createProxyTrap(win.Node.prototype, method, {
                        apply(target, thisArg, args) {
                            const result = win.Reflect.apply(target, thisArg, args);
                            const node = args[0];
                            if (node && node.tagName === 'IFRAME') {
                                try {
                                    if (node.contentWindow) installUAPatches(node.contentWindow);
                                } catch(e) {}
                                node.addEventListener('load', () => {
                                    try {
                                        if (node.contentWindow) installUAPatches(node.contentWindow);
                                    } catch(e) {}
                                });
                            }
                            return result;
                        }
                    });
                });
            }

            if (win.Document && win.Document.prototype.write) {
                createProxyTrap(win.Document.prototype, 'write', {
                    apply(target, thisArg, args) {
                        const result = win.Reflect.apply(target, thisArg, args);
                        try {
                            if (thisArg.defaultView) installUAPatches(thisArg.defaultView);
                        } catch(e) {}
                        return result;
                    }
                });
            }
        } catch (e) {}
    }

    installUAPatches(window);
})();
