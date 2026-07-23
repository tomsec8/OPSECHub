// Runs in the page's MAIN world context
console.log('[OPSECHub] hardwareMask.js INJECTED AND RUNNING!');
(function() {
    function installHardwareMaskPatches(win) {
        if (!win || win.__patched_hwm) return;
        try {
            win.__patched_hwm = true;

            // Use a shared WeakMap via Symbol on top window
            let proxyMap;
            try {
                let topWin;
                try { topWin = win.top || win; } catch(e) { topWin = win; }
                const sym = topWin.Symbol.for('__opsechub_proxymap_hwm');
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
                    if (!descriptor || !descriptor.get) {
                        // Fallback to defineProperty direct if getter doesn't exist
                        win.Object.defineProperty(targetObj, propName, {
                            get: () => typeof spoofedValue === 'function' ? spoofedValue() : spoofedValue,
                            configurable: true,
                            enumerable: true
                        });
                        return;
                    }

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

            // 1. Spoof CPU, RAM & Touch Points
            if (win.Navigator) {
                spoofGetter(win.Navigator.prototype, 'hardwareConcurrency', 8);
                spoofGetter(win.Navigator.prototype, 'deviceMemory', 8);
                spoofGetter(win.Navigator.prototype, 'maxTouchPoints', 0);
            }

            // 2. Spoof Battery API
            if (win.Navigator && (win.Navigator.prototype.getBattery || win.navigator.getBattery)) {
                const fakeBattery = {
                    charging: true,
                    chargingTime: 0,
                    dischargingTime: Infinity,
                    level: 1.0,
                    onchargingchange: null,
                    onchargingtimechange: null,
                    ondischargingtimechange: null,
                    onlevelchange: null,
                    addEventListener: function() {},
                    removeEventListener: function() {},
                    dispatchEvent: function() { return true; }
                };
                const fakeGetBattery = function() { return Promise.resolve(fakeBattery); };
                if (win.Navigator.prototype.getBattery) spoofGetter(win.Navigator.prototype, 'getBattery', () => fakeGetBattery);
                if (win.navigator.getBattery) {
                    try {
                        win.navigator.getBattery = fakeGetBattery;
                    } catch(e) {}
                }
            }

            // 3. Spoof Screen Dimensions & Color Depth
            if (win.Screen) {
                const screenProps = {
                    width: 1920,
                    height: 1080,
                    availWidth: 1920,
                    availHeight: 1040,
                    colorDepth: 24,
                    pixelDepth: 24
                };
                for (const [prop, val] of win.Object.entries(screenProps)) {
                    spoofGetter(win.Screen.prototype, prop, val);
                }
            }

            // --- IFrame Getters (Realm Poisoning for Statically Defined Iframes) ---
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
                                            if (targetWin) installHardwareMaskPatches(targetWin);
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

            // --- DOM Methods (Realm Poisoning for Dynamically Appended Iframes) ---
            if (win.Node) {
                ['appendChild', 'insertBefore', 'replaceChild'].forEach(method => {
                    createProxyTrap(win.Node.prototype, method, {
                        apply(target, thisArg, args) {
                            const result = win.Reflect.apply(target, thisArg, args);
                            const node = args[0];
                            if (node && node.tagName === 'IFRAME') {
                                try { if (node.contentWindow) installHardwareMaskPatches(node.contentWindow); } catch(e) {}
                                node.addEventListener('load', () => {
                                    try { if (node.contentWindow) installHardwareMaskPatches(node.contentWindow); } catch(e) {}
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
                        try { if (thisArg.defaultView) installHardwareMaskPatches(thisArg.defaultView); } catch(e) {}
                        return result;
                    }
                });
            }

        } catch(e) {
            console.error('[OPSECHub:HardwareMask] Error applying hardware mask:', e);
        }
    }

    installHardwareMaskPatches(window);
})();
