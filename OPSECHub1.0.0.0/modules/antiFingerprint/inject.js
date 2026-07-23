// Runs in the page's MAIN world context for Noise Mode
console.log('[OPSECHub] antiFingerprint.js INJECTED AND RUNNING!');
(function() {
    // 1. Session Deterministic Seed
    const SESSION_SEED = crypto.getRandomValues(new Uint32Array(1))[0];
    
    function seededRandom(str) {
        let h = SESSION_SEED;
        for (let i = 0; i < str.length; i++) {
            h = Math.imul(31, h) + str.charCodeAt(i) | 0;
        }
        return ((h & 0x7fffffff) / 0x7fffffff) * 2 - 1;
    }

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
            const sym = topWin.Symbol.for('__opsechub_proxymap');
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

        function applyCanvasNoise(dataArray) {
            const shift = Math.floor(SESSION_SEED % 10) + 15; // 15 to 24
            for (let i = 0; i < dataArray.length; i += 4) {
                if (dataArray[i+3] > 0) {
                    dataArray[i] = (dataArray[i] + shift) % 256;
                    dataArray[i+1] = (dataArray[i+1] + shift) % 256;
                    dataArray[i+2] = (dataArray[i+2] + shift) % 256;
                }
            }
        }

        // --- Canvas ---
        try {
            const originalToDataURL = win.HTMLCanvasElement ? win.HTMLCanvasElement.prototype.toDataURL : null;
            const originalGetImageData = win.CanvasRenderingContext2D ? win.CanvasRenderingContext2D.prototype.getImageData : null;

            const toDataURLTrap = {
                apply(target, thisArg, args) {
                    if (thisArg.width > 0 && thisArg.height > 0) {
                        try {
                            if (thisArg.getContext('2d')) {
                                const cloneCanvas = win.document.createElement('canvas');
                                cloneCanvas.width = thisArg.width;
                                cloneCanvas.height = thisArg.height;
                                const cloneCtx = cloneCanvas.getContext('2d', { willReadFrequently: true });
                                
                                cloneCtx.drawImage(thisArg, 0, 0);
                                const imgData = originalGetImageData.call(cloneCtx, 0, 0, cloneCanvas.width, cloneCanvas.height);
                                applyCanvasNoise(imgData.data);
                                cloneCtx.putImageData(imgData, 0, 0);
                                return win.Reflect.apply(target, cloneCanvas, args); 
                            }
                        } catch(e) {}
                    }
                    return win.Reflect.apply(target, thisArg, args);
                }
            };
            
            const toBlobTrap = {
                apply(target, thisArg, args) {
                    if (thisArg.width > 0 && thisArg.height > 0) {
                        try {
                            if (thisArg.getContext('2d')) {
                                const cloneCanvas = win.document.createElement('canvas');
                                cloneCanvas.width = thisArg.width;
                                cloneCanvas.height = thisArg.height;
                                const cloneCtx = cloneCanvas.getContext('2d', { willReadFrequently: true });
                                cloneCtx.drawImage(thisArg, 0, 0);
                                const imgData = originalGetImageData.call(cloneCtx, 0, 0, cloneCanvas.width, cloneCanvas.height);
                                applyCanvasNoise(imgData.data);
                                cloneCtx.putImageData(imgData, 0, 0);
                                return win.Reflect.apply(target, cloneCanvas, args); 
                            }
                        } catch(e) {}
                    }
                    return win.Reflect.apply(target, thisArg, args);
                }
            };

            const getImageDataTrap = {
                apply(target, thisArg, args) {
                    const result = win.Reflect.apply(target, thisArg, args);
                    if (result && result.data) {
                        applyCanvasNoise(result.data);
                    }
                    return result;
                }
            };

            if (win.HTMLCanvasElement) {
                createProxyTrap(win.HTMLCanvasElement.prototype, 'toDataURL', toDataURLTrap);
                createProxyTrap(win.HTMLCanvasElement.prototype, 'toBlob', toBlobTrap);
            }
            if (win.CanvasRenderingContext2D) createProxyTrap(win.CanvasRenderingContext2D.prototype, 'getImageData', getImageDataTrap);
            if (win.OffscreenCanvasRenderingContext2D) createProxyTrap(win.OffscreenCanvasRenderingContext2D.prototype, 'getImageData', getImageDataTrap);
            if (win.OffscreenCanvas) createProxyTrap(win.OffscreenCanvas.prototype, 'convertToBlob', toDataURLTrap);
        } catch(e) {}

        // --- WebGL ---
        try {
            const webglTrap = {
                apply(target, thisArg, args) {
                    const param = args[0];
                    if (param === 37445) return 'Google Inc. (Intel)';
                    if (param === 37446) {
                        const models = ['Intel(R) Iris(TM) Plus Graphics 640', 'Intel(R) UHD Graphics 620', 'ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)', 'Apple M1', 'AMD Radeon Pro 5300M'];
                        return models[SESSION_SEED % models.length];
                    }
                    return win.Reflect.apply(target, thisArg, args);
                }
            };
            
            const readPixelsTrap = {
                apply(target, thisArg, args) {
                    const result = win.Reflect.apply(target, thisArg, args);
                    const pixels = args[6];
                    if (pixels && pixels.length) {
                        applyCanvasNoise(pixels);
                    }
                    return result;
                }
            };

            if (win.WebGLRenderingContext) {
                createProxyTrap(win.WebGLRenderingContext.prototype, 'getParameter', webglTrap);
                createProxyTrap(win.WebGLRenderingContext.prototype, 'readPixels', readPixelsTrap);
            }
            if (win.WebGL2RenderingContext) {
                createProxyTrap(win.WebGL2RenderingContext.prototype, 'getParameter', webglTrap);
                createProxyTrap(win.WebGL2RenderingContext.prototype, 'readPixels', readPixelsTrap);
            }
        } catch(e) {}

        // --- Audio ---
        try {
            if (win.AudioBuffer) {
                createProxyTrap(win.AudioBuffer.prototype, 'getChannelData', {
                    apply(target, thisArg, args) {
                        const data = win.Reflect.apply(target, thisArg, args);
                        const noise = seededRandom("audio") * 0.0000001;
                        if (data) {
                            for (let i = 0; i < data.length; i += 100) data[i] += noise;
                        }
                        return data;
                    }
                });
            }
        } catch(e) {}

        // --- Rects ---
        try {
            const rectTrap = {
                apply(target, thisArg, args) {
                    const rects = win.Reflect.apply(target, thisArg, args);
                    const noise = seededRandom("rect_" + (thisArg.id || thisArg.tagName)) * 0.00001;
                    
                    if (win.DOMRectList && rects instanceof win.DOMRectList) {
                        return new win.Proxy(rects, {
                            get(targetList, prop) {
                                if (prop === 'item') {
                                    return function(idx) {
                                        const rect = targetList.item(idx);
                                        if (!rect) return rect;
                                        return new win.DOMRect(rect.x, rect.y, rect.width + noise, rect.height + noise);
                                    };
                                }
                                const val = win.Reflect.get(targetList, prop);
                                if (typeof val === 'object' && val !== null && win.DOMRect && val instanceof win.DOMRect) {
                                    return new win.DOMRect(val.x, val.y, val.width + noise, val.height + noise);
                                }
                                return val;
                            }
                        });
                    }
                    
                    if (win.DOMRect && rects instanceof win.DOMRect) {
                        return new win.DOMRect(rects.x, rects.y, rects.width + noise, rects.height + noise);
                    }
                    return rects;
                }
            };
            
            if (win.Element) {
                createProxyTrap(win.Element.prototype, 'getClientRects', rectTrap);
                createProxyTrap(win.Element.prototype, 'getBoundingClientRect', rectTrap);
            }
        } catch(e) {}

        // --- Screen & HW ---
        try {
            if (win.Navigator) {
                spoofGetter(win.Navigator.prototype, 'hardwareConcurrency', 8);
                spoofGetter(win.Navigator.prototype, 'deviceMemory', 8);
            }
            if (win.Screen) {
                const widthOffset = Math.floor(seededRandom("screen_w") * 5);
                spoofGetter(win.Screen.prototype, 'width', () => 1920 + widthOffset);
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
